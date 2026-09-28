<#
.SYNOPSIS
    PCAP Analyzer for MDE - Windows GUI for PCAP-Analyzer.ps1

.DESCRIPTION
    Pick a capture, tick -All and/or -Domain, press Run. The analyzer runs in a hidden
    PowerShell process and its colored output - including Copilot's recommended fix
    (green) from Section 12 - streams into the window.

    Run from source : powershell.exe -STA -ExecutionPolicy Bypass -File .\PCAP-Analyzer-GUI.ps1
    Build the .exe  : .\Build-PcapAnalyzerExe.ps1   (embeds the analyzer into PCAP-Analyzer.exe)

.NOTES
    Designed and developed by Bryan Rigano - Defender for Endpoint Team.

    Disclaimer: results are generated automatically from packet-capture analysis and
    AI-assisted (Copilot) recommendations. Validate findings in Wireshark before acting on
    them or sharing them with customers, particularly where a result appears inconsistent
    or unexpected.
#>

$ErrorActionPreference = 'Stop'

# WinForms needs a single-threaded apartment; relaunch under Windows PowerShell -STA if needed (source runs only)
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA' -and $PSCommandPath) {
    Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
        -ArgumentList "-STA -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`""
    return
}

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# =============================================================================
# Settings and paths
# =============================================================================
$AppTitle   = 'PCAP Analyzer for MDE  -  V16.5 + Copilot'
$AppCredit  = 'Designed and developed by Bryan Rigano  |  Defender for Endpoint Team'
$Disclaimer = 'Results are generated automatically from packet-capture analysis and AI-assisted recommendations. ' +
              'Validate findings in Wireshark before acting on them or sharing them with customers, particularly where a result appears inconsistent or unexpected.'
$EngineName = 'PCAP-Analyzer.ps1'

# Build-PcapAnalyzerExe.ps1 swaps this value for the analyzer's code (base64). From source it stays a placeholder.
$EmbeddedEngine = '__EMBEDDED_ENGINE_BASE64__'
$IsEmbedded     = $EmbeddedEngine -ne ('__EMBEDDED_' + 'ENGINE_BASE64__')
$SourceDir      = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

$AppData       = Join-Path $env:LOCALAPPDATA 'PCAP-Analyzer'
$EngineDir     = Join-Path $AppData 'engine'
$EngineFile    = Join-Path $EngineDir 'PCAP-Analyzer-engine.ps1'
$RunnerFile    = Join-Path $EngineDir 'run-engine.ps1'
$SettingsFile  = Join-Path $AppData 'gui-settings.json'
$CopilotMarker = Join-Path $AppData 'copilot-cli-ok.txt'   # same marker the analyzer's COPILOT PRE-CHECK uses

# Pick up anything installed since this session started (winget adds per-user PATH entries)
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')

# Run the analyzer under Windows PowerShell 5.1 - the same runtime it's developed and validated in from the console
$PsHost      = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$PsHostLabel = 'Windows PowerShell 5.1'

$IsAdmin = $false
try { $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
if ($IsAdmin) { $AppTitle += '   (Administrator)' }

# Runs the analyzer and streams each output line back as  <color>|<nonewline>|<base64 UTF-8 text>
# so Write-Host colors survive the trip into the GUI. Arguments arrive as JSON in PCAPGUI_ARGS.
$RunnerCode = @'
param([Parameter(Mandatory)][string]$Engine)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$defaultFg = $null
try { $defaultFg = $Host.UI.RawUI.ForegroundColor } catch { }

$script:SawDone = $false
function Send([int]$Color, [bool]$NoNewLine, [string]$Text) {
    if ($Text -match '^\s*Done\.\s*$') { $script:SawDone = $true }
    [Console]::Out.WriteLine(('{0}|{1}|{2}' -f $Color, [int]$NoNewLine, [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$Text))))
    [Console]::Out.Flush()
}

$splat = @{}
($env:PCAPGUI_ARGS | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $splat[$_.Name] = $_.Value }

& $Engine @splat *>&1 | ForEach-Object {
    $r = $_
    if ($r -is [System.Management.Automation.InformationRecord]) {
        $m = $r.MessageData
        if ($m -is [System.Management.Automation.HostInformationMessage]) {
            $fg = -1
            if ($null -ne $m.ForegroundColor -and $m.ForegroundColor -ne $defaultFg) { $fg = [int]$m.ForegroundColor }
            Send $fg ([bool]$m.NoNewLine) $m.Message
        } else { Send -1 $false ([string]$m) }
    }
    elseif ($r -is [System.Management.Automation.ErrorRecord])   { Send 12 $false (($r | Out-String).TrimEnd()) }
    elseif ($r -is [System.Management.Automation.WarningRecord]) { Send 14 $false ('WARNING: ' + $r.Message) }
    elseif ($r -is [System.Management.Automation.VerboseRecord] -or $r -is [System.Management.Automation.DebugRecord]) { }
    elseif ($r -is [string]) { Send -1 $false $r }
    else { Send -1 $false (($r | Out-String -Width 250).TrimEnd()) }
}
if ($script:SawDone) { exit 0 } else { exit 1 }   # the analyzer prints 'Done.' only when it runs to the end
'@

# Console colors -> screen colors on the dark output box (index = ConsoleColor + 1; slot 0 = default text)
$Palette = @(
    [Drawing.Color]::FromArgb(204, 204, 204),  # default
    [Drawing.Color]::FromArgb(138, 138, 138),  # Black (lifted so it's readable)
    [Drawing.Color]::FromArgb(59, 120, 255),   # DarkBlue
    [Drawing.Color]::FromArgb(19, 161, 14),    # DarkGreen
    [Drawing.Color]::FromArgb(58, 150, 221),   # DarkCyan
    [Drawing.Color]::FromArgb(209, 52, 56),    # DarkRed
    [Drawing.Color]::FromArgb(198, 120, 221),  # DarkMagenta
    [Drawing.Color]::FromArgb(193, 156, 0),    # DarkYellow
    [Drawing.Color]::FromArgb(204, 204, 204),  # Gray
    [Drawing.Color]::FromArgb(138, 138, 138),  # DarkGray
    [Drawing.Color]::FromArgb(59, 120, 255),   # Blue
    [Drawing.Color]::FromArgb(22, 198, 12),    # Green  - Copilot's fix
    [Drawing.Color]::FromArgb(97, 214, 214),   # Cyan
    [Drawing.Color]::FromArgb(231, 72, 86),    # Red
    [Drawing.Color]::FromArgb(255, 121, 198),  # Magenta
    [Drawing.Color]::FromArgb(249, 241, 165),  # Yellow
    [Drawing.Color]::FromArgb(242, 242, 242)   # White
)

# =============================================================================
# Helpers
# =============================================================================
function Import-GuiSettings {
    try { if (Test-Path -LiteralPath $SettingsFile) { return (Get-Content -LiteralPath $SettingsFile -Raw | ConvertFrom-Json) } } catch { }
    return $null
}

function Save-GuiSettings {
    try {
        New-Item -ItemType Directory -Path $AppData -Force | Out-Null
        [pscustomobject]@{
            TsharkPath  = $txtTshark.Text
            LastFolder  = $script:LastFolder
            CopilotMode = [string]$cmbCopilot.SelectedItem
            Detailed    = [bool]$chkDetailed.Checked
            LastPcap    = $txtPcap.Text
        } | ConvertTo-Json | Set-Content -LiteralPath $SettingsFile -Encoding UTF8
    } catch { }
}

function Initialize-Engine {
    New-Item -ItemType Directory -Path $EngineDir -Force | Out-Null
    if ($IsEmbedded) {
        [IO.File]::WriteAllBytes($EngineFile, [Convert]::FromBase64String($EmbeddedEngine))
    } else {
        $src = Join-Path $SourceDir $EngineName
        if (-not (Test-Path -LiteralPath $src)) { throw "Analyzer script not found next to the GUI: $src" }
        Copy-Item -LiteralPath $src -Destination $EngineFile -Force
    }
    [IO.File]::WriteAllText($RunnerFile, $RunnerCode, (New-Object System.Text.UTF8Encoding($true)))
}

function New-HiddenProcess([string]$File, [string]$Arguments, [hashtable]$Environment) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true            # no console windows for PowerShell, tshark, or Copilot
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
    if (Test-Path -LiteralPath $EngineDir) { $psi.WorkingDirectory = $EngineDir }
    if ($Environment) { foreach ($k in $Environment.Keys) { $psi.EnvironmentVariables[$k] = [string]$Environment[$k] } }
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    return $p
}

function Stop-ProcessTree($Process) {
    if (-not $Process) { return }
    try { if ($Process.HasExited) { return } } catch { return }
    try {
        $k = New-HiddenProcess (Join-Path $env:SystemRoot 'System32\taskkill.exe') "/PID $($Process.Id) /T /F" $null
        [void]$k.WaitForExit(5000)
    } catch { try { $Process.Kill() } catch { } }
}

function Write-Out([string]$Text, [int]$Color = -1, [bool]$NoNewLine = $false) {
    if ($Color -lt -1 -or $Color -gt 15) { $Color = -1 }
    $box.SelectionStart = $box.TextLength
    $box.SelectionLength = 0
    $box.SelectionColor = $Palette[$Color + 1]
    $box.AppendText(($Text -replace "`r`n", "`n") + $(if ($NoNewLine) { '' } else { "`n" }))
}

function Receive-EngineLine([string]$Line) {
    $parts = $Line.Split([char[]]@('|'), 3)
    if ($parts.Count -eq 3) {
        try {
            $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[2]))
            Write-Out $text ([int]$parts[0]) ($parts[1] -eq '1')
            return
        } catch { }
    }
    Write-Out $Line
}

function Restart-Elevated {
    Save-GuiSettings
    try {
        if ($IsEmbedded) {
            Start-Process -FilePath ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) -Verb RunAs
        } else {
            Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Verb RunAs `
                -ArgumentList "-STA -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`""
        }
        $form.Close()
    } catch { }   # UAC prompt declined - stay open
}

function Invoke-Safe([scriptblock]$Action) {
    try { & $Action } catch { Write-Out ("GUI error: " + $_.Exception.Message) 12 }
}

# =============================================================================
# Copilot CLI status (the GUI owns sign-in so the hidden analyzer never has to)
# =============================================================================
$script:CopilotState = 'Unknown'
$script:CopilotCli   = $null
$script:CopilotTest  = $null
$script:LoginProc    = $null

function Set-CopilotState([string]$State, [string]$Text) {
    $script:CopilotState = $State
    $lblCopilot.Text = $Text
    switch ($State) {
        'Ready'        { $lblCopilot.ForeColor = [Drawing.Color]::FromArgb(16, 124, 16); $btnCopilot.Text = 'Re-check';            $btnCopilot.Enabled = $true }
        'NotReady'     { $lblCopilot.ForeColor = [Drawing.Color]::FromArgb(202, 80, 16); $btnCopilot.Text = 'Sign in';             $btnCopilot.Enabled = $true }
        'NotInstalled' { $lblCopilot.ForeColor = [Drawing.Color]::FromArgb(202, 80, 16); $btnCopilot.Text = 'Install Copilot CLI'; $btnCopilot.Enabled = $true }
        default        { $lblCopilot.ForeColor = [Drawing.Color]::DimGray;               $btnCopilot.Text = 'Checking...';         $btnCopilot.Enabled = $false }
    }
}

function Update-CopilotStatus {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
    $cli = Get-Command copilot -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $script:CopilotCli = if ($cli) { $cli.Source } else { $null }
    if (-not $script:CopilotCli) {
        Set-CopilotState 'NotInstalled' 'Copilot CLI not installed - Section 12 will open Copilot Chat for you to paste into.'
    } elseif (Test-Path -LiteralPath $CopilotMarker) {
        Set-CopilotState 'Ready' 'Copilot CLI ready - the recommended fix prints in this window.'
    } else {
        Start-CopilotTest
    }
}

function Start-CopilotTest {
    Set-CopilotState 'Checking' 'Checking Copilot CLI sign-in (one-line test prompt)...'
    $p = New-HiddenProcess $script:CopilotCli '-s -p "Reply with exactly: COPILOT_OK"' $null
    $script:CopilotTest = @{ Proc = $p; Out = $p.StandardOutput.ReadToEndAsync(); Err = $p.StandardError.ReadToEndAsync(); Start = Get-Date }
}

function Update-CopilotTest {
    $t = $script:CopilotTest
    if (-not $t) { return }
    $timedOut = ((Get-Date) - $t.Start).TotalSeconds -gt 120
    if (-not $t.Proc.HasExited -and -not $timedOut) { return }
    if ($timedOut) { Stop-ProcessTree $t.Proc }
    if (-not $timedOut -and -not ($t.Out.IsCompleted -and $t.Err.IsCompleted)) { return }
    $script:CopilotTest = $null
    $reply = ''
    try { if ($t.Out.IsCompleted) { $reply += [string]$t.Out.Result }; if ($t.Err.IsCompleted) { $reply += [string]$t.Err.Result } } catch { }
    if ($reply -match 'COPILOT_OK') {
        try { New-Item -ItemType Directory -Path $AppData -Force | Out-Null; Set-Content -LiteralPath $CopilotMarker -Value (Get-Date -Format s) } catch { }
        Set-CopilotState 'Ready' 'Copilot CLI ready - the recommended fix prints in this window.'
    } else {
        $first = ($reply.Trim() -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
        if (-not $first) { $first = if ($timedOut) { 'no reply within 2 minutes' } else { 'no reply' } }
        Set-CopilotState 'NotReady' "Copilot CLI not signed in (or blocked): $first"
        $tips.SetToolTip($lblCopilot, $reply.Trim())
    }
}

function Invoke-CopilotAction {
    switch ($script:CopilotState) {
        'NotInstalled' {
            $cmd = "winget install GitHub.Copilot; Write-Host ''; Write-Host 'Done - close this window and click Re-check in PCAP Analyzer.' -ForegroundColor Green"
            Start-Process -FilePath $PsHost -ArgumentList "-NoProfile -NoExit -Command `"$cmd`""
            Set-CopilotState 'NotInstalled' 'Installing in the window that opened - click Re-check when it finishes.'
            $btnCopilot.Text = 'Re-check'
            $script:CopilotState = 'Installing'
        }
        'Installing' { Update-CopilotStatus }
        'NotReady' {
            # Visible console so the sign-in code and prompts show
            $script:LoginProc = Start-Process -FilePath $script:CopilotCli -ArgumentList 'login' -PassThru
            Set-CopilotState 'Checking' 'Finish the GitHub sign-in in the window that opened...'
        }
        default {
            Remove-Item -LiteralPath $CopilotMarker -ErrorAction SilentlyContinue
            Update-CopilotStatus
        }
    }
}

# =============================================================================
# Running the analyzer
# =============================================================================
$script:Run = $null

function Set-Busy([bool]$Busy) {
    foreach ($c in @($txtPcap, $btnPcap, $txtTshark, $btnTshark, $chkAll, $chkDomain, $cmbCopilot, $btnRun)) { $c.Enabled = -not $Busy }
    $txtFqdn.Enabled = (-not $Busy) -and $chkDomain.Checked
    $chkDetailed.Enabled = (-not $Busy) -and $chkDomain.Checked
    $btnStop.Enabled = $Busy
}

function Start-Analysis {
    $pcap = $txtPcap.Text.Trim().Trim('"')
    $fqdn = $txtFqdn.Text.Trim()
    $problem = $null
    if (-not $pcap -or -not (Test-Path -LiteralPath $pcap -PathType Leaf)) { $problem = 'Select a PCAP file first (Browse, or drag it onto the window).' }
    elseif (-not $chkAll.Checked -and -not $chkDomain.Checked) { $problem = 'Tick -All, -Domain, or both.' }
    elseif ($chkDomain.Checked -and $fqdn -notmatch '^(\*\.)?[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$') { $problem = 'Enter one FQDN for -Domain, e.g. winatp-gw-eus3.microsoft.com' }
    if ($problem) { [void][Windows.Forms.MessageBox]::Show($form, $problem, $AppTitle, 'OK', 'Information'); return }

    # Captures written by admin tools (MDE Client Analyzer) are often admin-only. tshark would fail on them,
    # so check up front and offer to restart elevated instead of producing an empty analysis.
    $readError = $null
    try { $fs = [IO.File]::Open($pcap, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite); $fs.Dispose() }
    catch { $readError = $_.Exception.GetBaseException() }
    if ($readError -is [UnauthorizedAccessException] -and -not $IsAdmin) {
        $msg = "Windows won't let this app read the capture (access denied):`n`n$pcap`n`n" +
               "This usually means an admin tool such as MDE Client Analyzer created the file.`n`n" +
               "Restart PCAP Analyzer as administrator?`n(Or copy the capture to a folder you own and select the copy.)"
        if ([Windows.Forms.MessageBox]::Show($form, $msg, $AppTitle, 'YesNo', 'Warning') -eq 'Yes') { Restart-Elevated }
        return
    } elseif ($readError) {
        [void][Windows.Forms.MessageBox]::Show($form, "Can't open the capture:`n`n$($readError.Message)", $AppTitle, 'OK', 'Warning')
        return
    }

    # Copilot: Auto only uses the CLI when it's signed in; otherwise Chat (never a hidden sign-in prompt)
    $mode = [string]$cmbCopilot.SelectedItem
    $note = $null
    if ($mode -eq 'Auto' -and $script:CopilotState -ne 'Ready') { $mode = 'Chat'; $note = 'Copilot CLI isn''t ready, so Section 12 will open Copilot Chat (paste with Ctrl+V).' }

    $engineArgs = [ordered]@{ PcapPath = $pcap; Copilot = $mode }
    if ($txtTshark.Text.Trim()) { $engineArgs.TsharkPath = $txtTshark.Text.Trim().Trim('"') }
    if ($chkAll.Checked)    { $engineArgs.All = $true }
    if ($chkDomain.Checked) { $engineArgs.Domain = $fqdn }
    if ($chkDomain.Checked -and $chkDetailed.Checked) { $engineArgs.Detailed = $true }

    Initialize-Engine
    Save-GuiSettings
    $box.Clear()
    $switches = @(); if ($chkAll.Checked) { $switches += '-All' }; if ($chkDomain.Checked) { $switches += "-Domain $fqdn" }; if ($engineArgs.Contains('Detailed')) { $switches += '-Detailed' }
    Write-Out ("Capture : " + $pcap) 11
    Write-Out ("Switches: " + ($switches -join ' ') + "    Copilot: " + $mode) 11
    Write-Out ("Engine  : " + $PsHostLabel + $(if ($IsAdmin) { '  (administrator)' } else { '' })) 8
    if ($note) { Write-Out $note 14 }
    Write-Out ''

    $p = New-HiddenProcess $PsHost ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Engine "{1}"' -f $RunnerFile, $EngineFile) @{ PCAPGUI_ARGS = ($engineArgs | ConvertTo-Json -Compress) }
    $script:Run = @{ Proc = $p; Out = $p.StandardOutput.ReadLineAsync(); Err = $p.StandardError.ReadLineAsync(); Start = Get-Date; Stopped = $false }
    Set-Busy $true
    $statusMain.Text = 'Analyzing...'
}

function Update-Run {
    $r = $script:Run
    if (-not $r) { return }
    $n = 0
    while ($r.Out -and $r.Out.IsCompleted -and $n -lt 800) {
        $line = $null
        try { $line = $r.Out.Result } catch { }
        if ($null -eq $line) { $r.Out = $null; break }
        Receive-EngineLine $line
        $n++
        $r.Out = $r.Proc.StandardOutput.ReadLineAsync()
    }
    while ($r.Err -and $r.Err.IsCompleted -and $n -lt 1600) {
        $line = $null
        try { $line = $r.Err.Result } catch { }
        if ($null -eq $line) { $r.Err = $null; break }
        if ($line.Trim()) { Write-Out $line 12 }
        $n++
        $r.Err = $r.Proc.StandardError.ReadLineAsync()
    }
    if ($n -gt 0) { $box.ScrollToCaret() }
    $elapsed = (Get-Date) - $r.Start
    $statusTime.Text = '{0:mm\:ss}' -f $elapsed

    if (-not $r.Out -and -not $r.Err -and $r.Proc.HasExited) {
        $script:Run = $null
        $code = $r.Proc.ExitCode
        Write-Out ''
        if ($r.Stopped) { Write-Out '---- Stopped ----' 14 }
        elseif ($code -eq 0) { Write-Out ('---- Finished in {0:mm\:ss} ----' -f $elapsed) 8 }
        else { Write-Out '---- The analyzer stopped early - see the red message above ----' 12 }
        $box.ScrollToCaret()
        $statusMain.Text = if ($r.Stopped) { 'Stopped' } elseif ($code -eq 0) { 'Done' } else { 'Stopped early - see the output' }
        Set-Busy $false
    }
}

# =============================================================================
# Window
# =============================================================================
$form = New-Object Windows.Forms.Form
$form.Text = $AppTitle
$form.Font = New-Object Drawing.Font('Segoe UI', 9)
$form.AutoScaleMode = 'Font'
$form.StartPosition = 'CenterScreen'
$g = $form.CreateGraphics(); $scale = $g.DpiX / 96; $g.Dispose()
$form.Size = New-Object Drawing.Size([int](1120 * $scale), [int](780 * $scale))
$form.MinimumSize = New-Object Drawing.Size([int](820 * $scale), [int](560 * $scale))
$form.AllowDrop = $true
try {
    $iconFile = Join-Path $SourceDir 'mde.ico'
    if (-not $IsEmbedded -and (Test-Path -LiteralPath $iconFile)) { $form.Icon = New-Object Drawing.Icon($iconFile) }
    else { $form.Icon = [Drawing.Icon]::ExtractAssociatedIcon([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) }
} catch { }
$tips = New-Object Windows.Forms.ToolTip

$grid = New-Object Windows.Forms.TableLayoutPanel
$grid.Dock = 'Fill'
$grid.Padding = New-Object Windows.Forms.Padding(10)
$grid.ColumnCount = 3
[void]$grid.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('AutoSize')))
[void]$grid.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('Percent', 100)))
[void]$grid.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('AutoSize')))
$grid.RowCount = 7
for ($i = 0; $i -lt 5; $i++) { [void]$grid.RowStyles.Add((New-Object Windows.Forms.RowStyle('AutoSize'))) }
[void]$grid.RowStyles.Add((New-Object Windows.Forms.RowStyle('Percent', 100)))
[void]$grid.RowStyles.Add((New-Object Windows.Forms.RowStyle('AutoSize')))

function New-RowLabel([string]$Text) {
    $l = New-Object Windows.Forms.Label
    $l.Text = $Text; $l.AutoSize = $true; $l.Anchor = 'Left'
    $l.Margin = New-Object Windows.Forms.Padding(3, 8, 8, 3)
    return $l
}
function New-Button([string]$Text) {
    $b = New-Object Windows.Forms.Button
    $b.Text = $Text; $b.AutoSize = $true; $b.Padding = New-Object Windows.Forms.Padding(8, 2, 8, 2)
    return $b
}

# Row 0 - capture
$txtPcap = New-Object Windows.Forms.TextBox; $txtPcap.Anchor = 'Left, Right'; $txtPcap.AllowDrop = $true
$btnPcap = New-Button 'Browse...'
$grid.Controls.Add((New-RowLabel 'PCAP file:'), 0, 0); $grid.Controls.Add($txtPcap, 1, 0); $grid.Controls.Add($btnPcap, 2, 0)
$tips.SetToolTip($txtPcap, 'The capture to analyze (.pcap / .pcapng / .cap). You can also drag a file onto the window.')

# Row 1 - tshark
$txtTshark = New-Object Windows.Forms.TextBox; $txtTshark.Anchor = 'Left, Right'
$btnTshark = New-Button 'Browse...'
$grid.Controls.Add((New-RowLabel 'tshark.exe:'), 0, 1); $grid.Controls.Add($txtTshark, 1, 1); $grid.Controls.Add($btnTshark, 2, 1)
$tips.SetToolTip($txtTshark, 'Installed with Wireshark. Leave blank to use tshark from PATH.')

# Row 2 - switches
$flowSw = New-Object Windows.Forms.FlowLayoutPanel; $flowSw.AutoSize = $true; $flowSw.WrapContents = $false; $flowSw.Anchor = 'Left, Right'; $flowSw.Margin = New-Object Windows.Forms.Padding(0)
$chkAll = New-Object Windows.Forms.CheckBox; $chkAll.Text = '-All   (every MDE / Defender URL, commercial + US Gov)'; $chkAll.AutoSize = $true; $chkAll.Checked = $true
$chkAll.Margin = New-Object Windows.Forms.Padding(3, 6, 24, 3)
$chkDomain = New-Object Windows.Forms.CheckBox; $chkDomain.Text = '-Domain   FQDN:'; $chkDomain.AutoSize = $true; $chkDomain.Margin = New-Object Windows.Forms.Padding(3, 6, 3, 3)
$txtFqdn = New-Object Windows.Forms.TextBox; $txtFqdn.Width = [int](340 * $scale); $txtFqdn.Enabled = $false; $txtFqdn.Margin = New-Object Windows.Forms.Padding(3, 4, 3, 3)
$chkDetailed = New-Object Windows.Forms.CheckBox; $chkDetailed.Text = '-Detailed'; $chkDetailed.AutoSize = $true; $chkDetailed.Enabled = $false
$chkDetailed.Margin = New-Object Windows.Forms.Padding(14, 6, 3, 3)
$flowSw.Controls.AddRange(@($chkAll, $chkDomain, $txtFqdn, $chkDetailed))
$tips.SetToolTip($chkDetailed, 'Expands the -Domain results to every Client Hello, Server Hello, and per-IP conversation. Only applies to -Domain.')
$grid.Controls.Add((New-RowLabel 'Switches:'), 0, 2); $grid.Controls.Add($flowSw, 1, 2); $grid.SetColumnSpan($flowSw, 2)
$tips.SetToolTip($txtFqdn, 'One FQDN, e.g. winatp-gw-eus3.microsoft.com. Tick both boxes to run -All and -Domain together.')

# Row 3 - Copilot
$flowCo = New-Object Windows.Forms.FlowLayoutPanel; $flowCo.AutoSize = $true; $flowCo.WrapContents = $false; $flowCo.Anchor = 'Left, Right'; $flowCo.Margin = New-Object Windows.Forms.Padding(0)
$cmbCopilot = New-Object Windows.Forms.ComboBox; $cmbCopilot.DropDownStyle = 'DropDownList'; $cmbCopilot.Width = [int](90 * $scale)
foreach ($m in 'Auto', 'Chat', 'Off') { [void]$cmbCopilot.Items.Add($m) }
$cmbCopilot.SelectedIndex = 0
$lblCopilot = New-Object Windows.Forms.Label; $lblCopilot.AutoSize = $true; $lblCopilot.Margin = New-Object Windows.Forms.Padding(10, 7, 3, 3)
$flowCo.Controls.AddRange(@($cmbCopilot, $lblCopilot))
$btnCopilot = New-Button 'Checking...'
$grid.Controls.Add((New-RowLabel 'Copilot:'), 0, 3); $grid.Controls.Add($flowCo, 1, 3); $grid.Controls.Add($btnCopilot, 2, 3)
$tips.SetToolTip($cmbCopilot, 'Auto = Copilot CLI answers in this window when signed in, otherwise Copilot Chat. Chat = always open Copilot Chat. Off = skip Section 12.')

# Row 4 - actions
$flowBtn = New-Object Windows.Forms.FlowLayoutPanel; $flowBtn.AutoSize = $true; $flowBtn.WrapContents = $false; $flowBtn.Margin = New-Object Windows.Forms.Padding(0, 6, 0, 6)
$btnRun    = New-Button 'Run analysis'; $btnRun.Font = New-Object Drawing.Font('Segoe UI', 9, [Drawing.FontStyle]::Bold)
$btnStop   = New-Button 'Stop'; $btnStop.Enabled = $false
$btnCopy   = New-Button 'Copy output'
$btnSave   = New-Button 'Save output...'
$btnFolder = New-Button 'Open capture folder'
$flowBtn.Controls.AddRange(@($btnRun, $btnStop, $btnCopy, $btnSave, $btnFolder))
$grid.Controls.Add($flowBtn, 0, 4); $grid.SetColumnSpan($flowBtn, 3)

# Row 5 - output
$box = New-Object Windows.Forms.RichTextBox
$box.Dock = 'Fill'
$box.ReadOnly = $true
$box.BackColor = [Drawing.Color]::FromArgb(16, 20, 24)
$box.ForeColor = $Palette[0]
$box.Font = New-Object Drawing.Font('Consolas', 10)
$box.WordWrap = $false
$box.DetectUrls = $false
$box.HideSelection = $false
$box.AllowDrop = $true
$grid.Controls.Add($box, 0, 5); $grid.SetColumnSpan($box, 3)

$lblDisclaimer = New-Object Windows.Forms.Label
$lblDisclaimer.Text = 'Disclaimer: ' + $Disclaimer
$lblDisclaimer.AutoSize = $true
$lblDisclaimer.MaximumSize = New-Object Drawing.Size([int](1400 * $scale), 0)
$lblDisclaimer.ForeColor = [Drawing.Color]::DimGray
$lblDisclaimer.Font = New-Object Drawing.Font('Segoe UI', 8, [Drawing.FontStyle]::Italic)
$lblDisclaimer.Margin = New-Object Windows.Forms.Padding(3, 6, 3, 0)
$grid.Controls.Add($lblDisclaimer, 0, 6); $grid.SetColumnSpan($lblDisclaimer, 3)
$grid.add_Resize({ $lblDisclaimer.MaximumSize = New-Object Drawing.Size([Math]::Max(200, $grid.ClientSize.Width - 30), 0) })

$status = New-Object Windows.Forms.StatusStrip
$statusMain = New-Object Windows.Forms.ToolStripStatusLabel; $statusMain.Text = 'Ready'; $statusMain.Spring = $true; $statusMain.TextAlign = 'MiddleLeft'
$statusTime = New-Object Windows.Forms.ToolStripStatusLabel; $statusTime.Text = ''
$statusCredit = New-Object Windows.Forms.ToolStripStatusLabel; $statusCredit.Text = $AppCredit; $statusCredit.ForeColor = [Drawing.Color]::DimGray
[void]$status.Items.Add($statusMain); [void]$status.Items.Add($statusTime); [void]$status.Items.Add($statusCredit)

$form.Controls.Add($grid)
$form.Controls.Add($status)
$form.AcceptButton = $btnRun

# =============================================================================
# Events
# =============================================================================
$script:LastFolder = $null

$btnPcap.add_Click({ Invoke-Safe {
    $dlg = New-Object Windows.Forms.OpenFileDialog
    $dlg.Title = 'Select a packet capture'
    $dlg.Filter = 'Packet captures (*.pcapng;*.pcap;*.cap)|*.pcapng;*.pcap;*.cap|All files (*.*)|*.*'
    if ($script:LastFolder -and (Test-Path -LiteralPath $script:LastFolder)) { $dlg.InitialDirectory = $script:LastFolder }
    if ($dlg.ShowDialog($form) -eq 'OK') { $txtPcap.Text = $dlg.FileName; $script:LastFolder = Split-Path -Parent $dlg.FileName }
} })

$btnTshark.add_Click({ Invoke-Safe {
    $dlg = New-Object Windows.Forms.OpenFileDialog
    $dlg.Title = 'Locate tshark.exe (installed with Wireshark)'
    $dlg.Filter = 'tshark.exe|tshark.exe|Programs (*.exe)|*.exe'
    if (Test-Path (Join-Path $env:ProgramFiles 'Wireshark')) { $dlg.InitialDirectory = Join-Path $env:ProgramFiles 'Wireshark' }
    if ($dlg.ShowDialog($form) -eq 'OK') { $txtTshark.Text = $dlg.FileName }
} })

$chkDomain.add_CheckedChanged({ $txtFqdn.Enabled = $chkDomain.Checked; $chkDetailed.Enabled = $chkDomain.Checked; if ($chkDomain.Checked) { [void]$txtFqdn.Focus() } })
$btnRun.add_Click({ Invoke-Safe { Start-Analysis } })
$btnStop.add_Click({ Invoke-Safe { if ($script:Run) { $script:Run.Stopped = $true; Stop-ProcessTree $script:Run.Proc } } })
$btnCopy.add_Click({ Invoke-Safe { if ($box.TextLength) { [Windows.Forms.Clipboard]::SetText($box.Text); $statusMain.Text = 'Output copied to the clipboard' } } })
$btnCopilot.add_Click({ Invoke-Safe { Invoke-CopilotAction } })

$btnSave.add_Click({ Invoke-Safe {
    if (-not $box.TextLength) { return }
    $dlg = New-Object Windows.Forms.SaveFileDialog
    $dlg.Filter = 'Rich Text - keeps colors (*.rtf)|*.rtf|Plain text (*.txt)|*.txt'
    $base = if ($txtPcap.Text) { [IO.Path]::GetFileNameWithoutExtension($txtPcap.Text) } else { 'capture' }
    $dlg.FileName = '{0}_analysis_{1:yyyyMMdd-HHmm}' -f $base, (Get-Date)
    if ($txtPcap.Text -and (Test-Path -LiteralPath $txtPcap.Text)) { $dlg.InitialDirectory = Split-Path -Parent $txtPcap.Text }
    if ($dlg.ShowDialog($form) -eq 'OK') {
        $type = if ($dlg.FilterIndex -eq 1) { [Windows.Forms.RichTextBoxStreamType]::RichText } else { [Windows.Forms.RichTextBoxStreamType]::PlainText }
        $box.SaveFile($dlg.FileName, $type)
        $statusMain.Text = "Saved: $($dlg.FileName)"
    }
} })

$btnFolder.add_Click({ Invoke-Safe {
    $p = $txtPcap.Text.Trim().Trim('"')
    if ($p -and (Test-Path -LiteralPath $p)) { Start-Process explorer.exe "/select,`"$p`"" }
} })

# Drag a capture onto the path box, the output box, or the window
$onDragEnter = { param($s, $e) if ($e.Data.GetDataPresent([Windows.Forms.DataFormats]::FileDrop)) { $e.Effect = 'Copy' } }
$onDragDrop  = { param($s, $e)
    $files = $e.Data.GetData([Windows.Forms.DataFormats]::FileDrop)
    if ($files -and $files.Count -gt 0 -and $btnRun.Enabled) { $txtPcap.Text = $files[0]; $script:LastFolder = Split-Path -Parent $files[0] }
}
foreach ($c in @($form, $txtPcap, $box)) { $c.add_DragEnter($onDragEnter); $c.add_DragDrop($onDragDrop) }

$timer = New-Object Windows.Forms.Timer
$timer.Interval = 100
$timer.add_Tick({
    try {
        Update-Run
        Update-CopilotTest
        if ($script:LoginProc -and $script:LoginProc.HasExited) {
            $script:LoginProc = $null
            Remove-Item -LiteralPath $CopilotMarker -ErrorAction SilentlyContinue
            Start-CopilotTest
        }
    } catch { }
})

$form.add_Shown({ Invoke-Safe {
    $settings = Import-GuiSettings
    $tshark = $null
    if ($settings -and $settings.TsharkPath -and (Test-Path -LiteralPath $settings.TsharkPath)) { $tshark = $settings.TsharkPath }
    if (-not $tshark) {
        $tshark = @((Join-Path $env:ProgramFiles 'Wireshark\tshark.exe'), (Join-Path ${env:ProgramFiles(x86)} 'Wireshark\tshark.exe')) |
            Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    }
    if (-not $tshark) { $c = Get-Command tshark -ErrorAction SilentlyContinue; if ($c) { $tshark = $c.Source } }
    if ($tshark) { $txtTshark.Text = $tshark }
    if ($settings) {
        $script:LastFolder = $settings.LastFolder
        if ($settings.CopilotMode -and $cmbCopilot.Items.Contains($settings.CopilotMode)) { $cmbCopilot.SelectedItem = $settings.CopilotMode }
        if ($settings.Detailed) { $chkDetailed.Checked = $true }
        if ($settings.LastPcap -and (Test-Path -LiteralPath $settings.LastPcap)) { $txtPcap.Text = $settings.LastPcap }
    }
    Write-Out 'PCAP Analyzer for MDE' 11
    Write-Out $AppCredit 8
    Write-Out ''
    Write-Out '1. Browse to a capture (or drag it here)   2. Tick -All and/or -Domain (-Detailed expands -Domain)   3. Run analysis' 8
    Write-Out 'Section 12 at the end shows Copilot''s recommended fix in green.' 8
    Update-CopilotStatus
    $timer.Start()
} })

$form.add_FormClosing({
    $timer.Stop()
    if ($script:Run) { Stop-ProcessTree $script:Run.Proc }
    if ($script:CopilotTest) { Stop-ProcessTree $script:CopilotTest.Proc }
    Save-GuiSettings
    Remove-Item -LiteralPath $EngineDir -Recurse -Force -ErrorAction SilentlyContinue
})

[void]$form.ShowDialog()
$form.Dispose()
