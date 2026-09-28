<#
.SYNOPSIS
    Builds PCAP-Analyzer.exe: the GUI plus the V16.5 analyzer packed into one Windows program.

.DESCRIPTION
    1. Installs the PS2EXE module for your user if it's missing (from the PowerShell Gallery).
    2. Embeds PCAP-AnalyzerV16_5-copilot.ps1 into PCAP-Analyzer-GUI.ps1 (base64).
    3. Compiles that into PCAP-Analyzer.exe - a windowed app, no console.
    4. Optionally signs the .exe with your code-signing certificate (-CertThumbprint).

    Re-run it whenever you change the analyzer or the GUI.

.NOTES
    Designed and developed by Bryan Rigano - Defender for Endpoint Team.

.EXAMPLE
    .\Build-PcapAnalyzerExe.ps1
.EXAMPLE
    .\Build-PcapAnalyzerExe.ps1 -Version 16.5.1.0 -CertThumbprint 0123456789ABCDEF0123456789ABCDEF01234567
#>
param(
    [string]$Analyzer = (Join-Path $PSScriptRoot 'PCAP-AnalyzerV16_5-copilot.ps1'),
    [string]$Gui      = (Join-Path $PSScriptRoot 'PCAP-Analyzer-GUI.ps1'),
    [string]$Icon     = (Join-Path $PSScriptRoot 'mde.ico'),
    [string]$OutFile  = (Join-Path $PSScriptRoot 'PCAP-Analyzer.exe'),
    [string]$Version  = '16.5.0.0',
    [string]$CertThumbprint
)
$ErrorActionPreference = 'Stop'

# PS2EXE compiles against .NET Framework, so build from Windows PowerShell 5.1
if ($PSVersionTable.PSEdition -eq 'Core') {
    Write-Host 'Switching to Windows PowerShell 5.1 for the build...' -ForegroundColor Cyan
    $wps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    foreach ($k in $PSBoundParameters.Keys) { $argList += "-$k"; $argList += [string]$PSBoundParameters[$k] }
    & $wps @argList
    exit $LASTEXITCODE
}

foreach ($f in @($Analyzer, $Gui)) {
    if (-not (Test-Path -LiteralPath $f)) { throw "Missing file: $f" }
}

# 1) PS2EXE
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host 'Installing the PS2EXE module (current user)...' -ForegroundColor Cyan
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -Scope CurrentUser -Force | Out-Null
    }
    Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber
}
Import-Module ps2exe

# 2) Embed the analyzer into a temporary copy of the GUI
$placeholder = '__EMBEDDED_' + 'ENGINE_BASE64__'
$guiText = [IO.File]::ReadAllText($Gui)
if (-not $guiText.Contains("'$placeholder'")) { throw "The GUI script doesn't contain the analyzer placeholder - was it edited?" }
$engineB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Analyzer))
$buildDir = Join-Path $env:TEMP ('pcap-analyzer-build-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
$buildScript = Join-Path $buildDir 'PCAP-Analyzer.ps1'
[IO.File]::WriteAllText($buildScript, $guiText.Replace("'$placeholder'", "'$engineB64'"), (New-Object System.Text.UTF8Encoding($true)))

# 3) Compile
$ps2exeArgs = @{
    inputFile   = $buildScript
    outputFile  = $OutFile
    noConsole   = $true
    STA         = $true
    x64         = $true
    noOutput    = $true
    noError     = $true
    DPIAware    = $true
    title       = 'PCAP Analyzer for MDE'
    description = 'MDE connectivity analysis of packet captures, with Copilot action plans'
    product     = 'PCAP Analyzer for MDE'
    company     = 'Defender for Endpoint Team'
    copyright   = 'Designed and developed by Bryan Rigano - Defender for Endpoint Team'
    version     = $Version
}
if (Test-Path -LiteralPath $Icon) { $ps2exeArgs.iconFile = $Icon }
Write-Host 'Compiling...' -ForegroundColor Cyan
try {
    Invoke-ps2exe @ps2exeArgs
} finally {
    Remove-Item -LiteralPath $buildDir -Recurse -Force -ErrorAction SilentlyContinue
}
if (-not (Test-Path -LiteralPath $OutFile)) { throw 'PS2EXE did not produce the .exe - see the messages above.' }

# 4) Optional code signing (strongly recommended before sharing)
if ($CertThumbprint) {
    $cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert | Where-Object Thumbprint -eq $CertThumbprint | Select-Object -First 1
    if (-not $cert) { throw "No code-signing certificate with thumbprint $CertThumbprint in CurrentUser\My or LocalMachine\My." }
    $sig = Set-AuthenticodeSignature -FilePath $OutFile -Certificate $cert -TimestampServer 'http://timestamp.digicert.com' -HashAlgorithm SHA256
    Write-Host "Signature: $($sig.Status)" -ForegroundColor $(if ($sig.Status -eq 'Valid') { 'Green' } else { 'Yellow' })
}

$size = [math]::Round((Get-Item -LiteralPath $OutFile).Length / 1KB)
Write-Host ''
Write-Host "Built: $OutFile  ($size KB)" -ForegroundColor Green
Write-Host 'Double-click it to launch. Keep Wireshark (tshark) installed on any PC that runs it.' -ForegroundColor Green
