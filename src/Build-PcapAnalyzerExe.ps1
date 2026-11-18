<#
.SYNOPSIS
    Builds PCAP-Analyzer.exe from PCAP-Analyzer-GUI.ps1 + the analyzer engine, with the
    Section 12 Copilot PII guardrail added to the embedded engine's prompt.

.DESCRIPTION
    Your .ps1 files are never modified. The build:
      1. Syntax-checks the GUI and the engine.
      2. Adds the DATA HANDLING RULES text to a COPY of the engine's Section 12 Copilot
         prompt (prompt text only - no logic changes).
      3. Embeds that copy into the GUI (the GUI's __EMBEDDED_ENGINE_BASE64__ placeholder).
      4. Compiles a windowed STA EXE with PS2EXE.
      5. Extracts the script back out of the EXE and confirms the guardrail is inside.

    Test the exact code that goes into the EXE without compiling:
      powershell -STA -ExecutionPolicy Bypass -File .\dist\PCAP-Analyzer-GUI.embedded.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Build-PcapAnalyzerExe.ps1

.EXAMPLE
    .\Build-PcapAnalyzerExe.ps1 -EngineScript .\PCAP-Analyzer.ps1 -IconFile .\mde.ico -Version 16.5.6.0

.EXAMPLE
    .\Build-PcapAnalyzerExe.ps1 -DebugConsole     # EXE also opens a console that shows any startup errors
#>
[CmdletBinding()]
param(
    [string]$GuiScript    = '.\PCAP-Analyzer-GUI.ps1',
    [string]$EngineScript = '',                 # default: the $EngineName set in the GUI script
    [string]$OutputDir    = '.\dist',
    [string]$ExeName      = 'PCAP-Analyzer.exe',
    [string]$IconFile     = '.\mde.ico',
    [string]$Version      = '16.5.6.0',
    [switch]$DebugConsole
)

$ErrorActionPreference = 'Stop'
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    $m" -ForegroundColor Green }
function Warn($m) { Write-Host "    $m" -ForegroundColor Yellow }

function Test-Syntax([string]$Path) {
    $tokens = $null; $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
    if ($errs.Count) {
        $errs | ForEach-Object { Write-Host "    $(Split-Path $Path -Leaf) line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red }
        throw "$(Split-Path $Path -Leaf) has syntax errors."
    }
}

# ---------------------------------------------------------------------------
# Section 12 guardrail. Inserted right after the anchor line inside the engine's
# double-quoted prompt here-string, so it must never contain a double quote,
# a dollar sign or a backtick.
# ---------------------------------------------------------------------------
$Anchor = 'Write plain text only: no markdown, no bold, no tables.'
$Rules  = @(
    'DATA HANDLING RULES - follow these before answering:'
    '- These findings come from a customer''s packet capture. Do not repeat, store, or ask for personally identifiable information (PII) or customer-identifying details: customer hostnames or device names, customer or internal domain names, usernames, email addresses, company or organization names (including names in certificate issuers), tenant or organization IDs, or case numbers. Refer to them generically instead, for example the proxy server, the inspecting certificate authority, or the affected device.'
    '- IP addresses (local/private and Microsoft service IPs) and Microsoft service URLs are not PII - use them normally.'
    '- These rules only limit what you repeat. Still give the complete, specific fix for every finding listed below.'
    '- Do not ask the engineer for more customer details.'
)
foreach ($r in $Rules) { if ($r -match '["$`]') { throw "Guardrail text can't contain double quotes, dollar signs or backticks: $r" } }

# --- Inputs -----------------------------------------------------------------
Step 'Resolving inputs'
$GuiScript = (Resolve-Path $GuiScript).Path
$guiText   = [IO.File]::ReadAllText($GuiScript)
if (-not $EngineScript) {
    $m = [regex]::Match($guiText, '(?m)^\s*\$EngineName\s*=\s*''([^'']+)''')
    if (-not $m.Success) { throw 'No -EngineScript given and $EngineName not found in the GUI script.' }
    $EngineScript = Join-Path (Split-Path $GuiScript -Parent) $m.Groups[1].Value
}
$EngineScript = (Resolve-Path $EngineScript).Path
if ($IconFile -and (Test-Path $IconFile)) { $IconFile = (Resolve-Path $IconFile).Path }
else { if ($IconFile) { Warn "Icon not found ($IconFile) - building without one." }; $IconFile = '' }
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
$OutputDir     = (Resolve-Path $OutputDir).Path
$exePath       = Join-Path $OutputDir $ExeName
$guardedEngine = Join-Path $OutputDir 'PCAP-Analyzer-engine.guarded.ps1'
$mergedPath    = Join-Path $OutputDir 'PCAP-Analyzer-GUI.embedded.ps1'
foreach ($f in @($GuiScript, $EngineScript, $IconFile) | Where-Object { $_ }) {
    try { Unblock-File -Path $f -ErrorAction SilentlyContinue } catch { }
}
Ok "GUI   : $GuiScript"
Ok "Engine: $EngineScript"
Ok "Icon  : $(if ($IconFile) { $IconFile } else { '(none)' })"
Ok "Output: $exePath"
if ($OutputDir -match 'OneDrive') { Warn 'Output is inside OneDrive - if the EXE misbehaves, build to a local folder (-OutputDir C:\Build\PCAP).' }

# --- Checks -----------------------------------------------------------------
Step 'Checking scripts'
Test-Syntax $GuiScript
Test-Syntax $EngineScript
Ok 'No syntax errors in GUI or engine'
$placeholder = "'__EMBEDDED_ENGINE_BASE64__'"
$hits = ([regex]::Matches($guiText, [regex]::Escape($placeholder))).Count
if ($hits -ne 1) { throw "Expected the engine placeholder $placeholder once in the GUI, found $hits." }
Ok 'GUI embed placeholder found'

# --- Guardrail into a copy of the engine -----------------------------------
Step 'Adding PII guardrail to the Section 12 prompt (engine copy)'
$engineBytes = [IO.File]::ReadAllBytes($EngineScript)
$hasBom      = $engineBytes.Length -ge 3 -and $engineBytes[0] -eq 0xEF -and $engineBytes[1] -eq 0xBB -and $engineBytes[2] -eq 0xBF
$engineText  = (New-Object System.Text.UTF8Encoding($false)).GetString($engineBytes, $(if ($hasBom) { 3 } else { 0 }), $engineBytes.Length - $(if ($hasBom) { 3 } else { 0 }))

if ($engineText.Contains('DATA HANDLING RULES')) {
    Warn 'Engine already contains DATA HANDLING RULES - embedding it as-is.'
} else {
    $anchorHits = ([regex]::Matches($engineText, [regex]::Escape($Anchor))).Count
    if ($anchorHits -ne 1) { throw "Expected this line once in the engine's Section 12 prompt, found ${anchorHits}:`n    $Anchor" }
    $nl = if ($engineText.Contains("`r`n")) { "`r`n" } else { "`n" }
    $engineText = $engineText.Replace($Anchor, $Anchor + $nl + $nl + ($Rules -join $nl))
    Ok 'Guardrail inserted after the plain-text instruction'
}
$guardedBytes = [Text.Encoding]::UTF8.GetBytes($engineText)
if ($hasBom) { $guardedBytes = [byte[]](0xEF, 0xBB, 0xBF) + $guardedBytes }
[IO.File]::WriteAllBytes($guardedEngine, $guardedBytes)
Test-Syntax $guardedEngine
Ok "Engine copy parses cleanly -> $guardedEngine"

# --- Embed ------------------------------------------------------------------
Step 'Embedding engine into GUI'
$merged = $guiText.Replace($placeholder, "'" + [Convert]::ToBase64String($guardedBytes) + "'")
[IO.File]::WriteAllText($mergedPath, $merged, (New-Object System.Text.UTF8Encoding($true)))
Test-Syntax $mergedPath
Ok "Embedded ($([math]::Round($guardedBytes.Length / 1KB)) KB) -> $mergedPath"

# --- PS2EXE -----------------------------------------------------------------
Step 'Preparing PS2EXE'
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Install-Module ps2exe -Scope CurrentUser -Force -AllowClobber
}
Import-Module ps2exe
Ok "ps2exe $((Get-Module ps2exe).Version)"

Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($ExeName)) -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -eq $exePath } | ForEach-Object { throw "$ExeName is running (PID $($_.Id)) - close it and rebuild." }
if (Test-Path $exePath) { Remove-Item $exePath -Force }

Step 'Compiling'
$ps2exeArgs = @{
    inputFile   = $mergedPath
    outputFile  = $exePath
    STA         = $true          # WinForms, drag-and-drop and the clipboard need STA
    x64         = $true
    title       = 'PCAP Analyzer for MDE'
    description = 'Packet Capture (PCAP) Analyzer for Microsoft Defender for Endpoint (MDE)'
    product     = 'PCAP Analyzer for MDE'
    company     = 'Bryan Rigano - Defender for Endpoint Team'
    copyright   = "(c) $(Get-Date -Format yyyy) Bryan Rigano"
    version     = $Version
}
if ($DebugConsole) { Warn 'Debug build: a console window will show any startup errors.' }
else               { $ps2exeArgs.noConsole = $true }
if ($IconFile)     { $ps2exeArgs.iconFile = $IconFile }
Invoke-ps2exe @ps2exeArgs

Start-Sleep -Seconds 2   # a quarantined EXE disappears right after it's written
if (-not (Test-Path $exePath)) {
    throw 'The EXE was written but is gone - most likely quarantined. Check: Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 3'
}

# --- Verify the EXE contains the guarded engine ----------------------------
Step 'Verifying EXE contents'
$extracted = Join-Path $OutputDir 'extracted-check.ps1'
Remove-Item $extracted -ErrorAction SilentlyContinue
try {
    Start-Process -FilePath $exePath -ArgumentList "-extract:`"$extracted`"" -Wait -WindowStyle Hidden
    $x = [IO.File]::ReadAllText($extracted)
    $b = [regex]::Match($x, '\$EmbeddedEngine\s*=\s*''([A-Za-z0-9+/=]+)''').Groups[1].Value
    $inside = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b))
    if ($inside.Contains('DATA HANDLING RULES')) { Ok 'EXE contains the engine with the PII guardrail' }
    else { throw 'Engine inside the EXE is missing the PII guardrail.' }
} catch {
    Warn "Couldn't verify the EXE contents: $($_.Exception.Message)"
} finally { Remove-Item $extracted -ErrorAction SilentlyContinue }

Step 'Build complete'
Ok "EXE    : $exePath"
Ok "Version: $Version"
Ok "SHA256 : $((Get-FileHash $exePath -Algorithm SHA256).Hash)"
