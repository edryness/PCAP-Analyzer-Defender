<#
================================================================================
 Created by Bryan Rigano | Defender for Endpoint Team
================================================================================

================================================================================
 V16.5.2 - NO CUSTOMER EMAIL FROM COPILOT
 - Section 12 now asks Copilot only for the engineer-facing fix (green). The
   customer email (pink) and its clipboard copy are removed; if Copilot adds a
   customer message anyway, it's cut off before display and before saving.
================================================================================

================================================================================
 V16.5.1 - CREDIT + DISCLAIMER
 - Header at the start of every run: Created by Bryan Rigano | Defender for
   Endpoint Team.
 - Disclaimer printed at the end of every run, after Section 12.
================================================================================

================================================================================
 V16.5.1 FIX - CAPTURE READ CHECK
 - Every tshark query discards tshark's error output, so a capture tshark
   couldn't open (access denied, not a capture file, empty) used to look like a
   clean capture: zero Client Hellos, sections skipped, no findings. The script
   now reads the first packet before any analysis and stops with tshark's own
   error message if that fails. Typical cause: a capture created by an admin
   tool (MDE Client Analyzer) opened from a non-admin window.
================================================================================

================================================================================
 COPILOT HAND-OFF (added on top of V17)
 - New Section 12 - COPILOT ACTION PLAN: after Section 11, on every mode
   (-All, -Domain, etc.), the Section 11 findings are sent to Copilot with a
   prompt asking for the recommended fix, who owns it, and how to verify it
   (engineer-facing only - see V16.5.2).
 - New -Copilot parameter: Auto (default) | CLI | Chat | Off.
     Auto = GitHub Copilot CLI if installed, otherwise Copilot Chat.
     CLI  = answer prints in this console and is saved next to the PCAP.
     Chat = prompt copied to clipboard + Microsoft 365 Copilot Chat opens.
 - COPILOT PRE-CHECK runs before the analysis: finds the Copilot CLI (flags an
   admin window, where a per-user install isn't visible), checks for GitHub
   credentials and runs 'copilot login' if there are none (approve once in the
   browser), and on the first run on a PC sends a one-line test prompt. Each
   step prints [x]/[ ] so it's clear why Section 12 used the CLI or Chat.
 - Section 12 output is split in two: GREEN = Copilot's recommended fix for the
   engineer (problem, 1-3 fix steps, owner, how to confirm, what to collect next),
   saved to <capture>_CopilotPlan_<time>.md next to the PCAP.
 - Only the Section 11 findings (Microsoft URLs + issue/cause/fix text) and the
   switches used are sent - no IPs, no capture file name.
 - No detection logic changed.
================================================================================

================================================================================
 V17 CHANGELOG (from V16)
 - Added US Gov streamlined connectivity hostnames to $GovRequiredUrlPatterns,
   checked by -govURLHandshakes / -AllGov / -All in sections 8 and 9:
     endpoint.security.microsoft.us, *.endpoint.security.microsoft.us
   (e.g. mdav.usm.endpoint.security.microsoft.us). Gov-only domain, so no
   double-reporting with the commercial *.endpoint.security.microsoft.com.
 - No detection logic changed.
================================================================================

================================================================================
 V16 CHANGELOG (from V15)
 - Added US Gov (GCC High / DoD) Defender portal + Entra sign-in hostnames to
   $GovRequiredUrlPatterns, so they're checked by -govURLHandshakes / -AllGov /
   -All in sections 8 (SSL inspection) and 9 (handshake status):
     security.microsoft.us, login.microsoftonline.us,
     securitycenter.microsoft.us, *.securitycenter.microsoft.us
   (bare + wildcard both listed - "*." alone doesn't match the bare name).
   *.blob.core.usgovcloudapi.net was already present.
 - No detection logic changed.
================================================================================

================================================================================
 V15 CHANGELOG (from V14)
 - FIX: -All / -AllCommercial / -AllGov handshake sweeps (sections 7 and 9)
   could not see failures that happen BEFORE TLS (SYN with no SYN-ACK, ICMP
   unreachable). The sweep built its IP list only from TLS Client Hellos, and
   an IP whose SYN was dropped never gets a Client Hello - so a hostname with
   one working IP and one blocked IP looked clean. The sweep now also pulls
   DNS-resolved IPs for each MDE hostname and checks any of them the device
   actually tried (sent a SYN to) but never got a SYN-ACK from, or that drew
   an ICMP unreachable. Untried IPs from multi-A DNS answers are ignored (normal).
 - FIX: hostnames seen ONLY in DNS (no TLS at all) are now also checked at the
   IP level in the sweep, instead of only being listed by name.
 - FIX: added bare "endpoint.security.microsoft.com" to the commercial pattern
   list - "*.endpoint.security.microsoft.com" alone did not match the bare name.
 - FIX: ICMP unreachable lookup now keys on the ORIGINAL destination (inner IP
   header, last occurrence of ip.dst) instead of the outer header, which is the
   client's own IP - previously ICMP errors could never match a destination.
================================================================================

================================================================================
 V14 CHANGELOG (from V13)
 - Adds Section 11 - SUMMARY & RECOMMENDED ACTIONS: a closing summary listing
   only genuine, actionable issues found elsewhere in the run (full
   connectivity failures, TLS/SSL inspection signals, missing required
   cipher suites, proxy-auth blocks), each with a likely cause, a suggested
   fix, and a pointer back to the section with the supporting evidence.
   Runs unconditionally, on every switch/mode, right after Section 10.
 - Cipher Compliance findings for a missing TLS 1.3 suite carry an extra
   NOTE: not every MDE URL requires TLS 1.3 (the Microsoft baseline this
   check uses is documented for Power Platform/Dataverse, not MDE
   specifically) - confirm via SSL Labs (ssllabs.com/ssltest) whether the
   specific URL actually requires/supports TLS 1.3, or whether TLS 1.2 is
   sufficient, before reporting a TLS 1.3 gap to the customer as an issue.
 - No detection logic elsewhere in the script was changed - only finding
   capture was added at points where a real issue was already being
   determined and reported.
================================================================================
#>

<#
.SYNOPSIS
    Analyze a PCAP file for a specific domain: TLS version, full cipher list, handshake
    status, outbound connectivity, Microsoft cipher compliance, an SSL-inspection sweep
    across all documented Microsoft Defender for Endpoint connectivity URLs, and an
    explicit forward-proxy detection sweep (HTTP CONNECT tunnels / 407 responses).

.PARAMETER PcapPath
    Path to the .pcap / .pcapng file to analyze.

.PARAMETER Domain
    Optional. The domain to search for, e.g. eu-v20.events.endpoint.security.microsoft.com
    Required unless -CheckMdeUrlsOnly is used.

.PARAMETER CheckMdeUrlsOnly
    Optional switch. Skip the single-domain analysis (sections 1-5) and only run the
    SSL-inspection sweep (section 6) across all documented MDE connectivity URLs found
    anywhere in the capture. Does not require -Domain.

.PARAMETER CommercialURLHandshakes
    Optional switch. Runs section 7: the same staged handshake status check used in
    sections 3-4 (SYN, SYN-ACK, ACK, TLS Client Hello, TLS Server Hello, data), applied
    to every documented MDE connectivity URL found in the capture instead of one domain.
    Independent of -Domain - does not run as part of a normal -Domain analysis, and does
    not require -Domain to be set.

.PARAMETER govURLHandshakes
    Optional switch. Same as -CommercialURLHandshakes, but against the MDE connectivity
    URLs documented for US Government cloud environments (GCC, GCC High, DoD) instead of
    commercial. Runs as section 9 (plus its own SSL inspection check as section 8).
    Independent of -Domain and -CommercialURLHandshakes.

.PARAMETER AllCommercial
    Optional switch. Shorthand for -CommercialURLHandshakes. Runs every commercial MDE
    check (SSL inspection sweep + handshake status sweep) without needing -Domain.

.PARAMETER AllGov
    Optional switch. Shorthand for -govURLHandshakes. Runs every US Gov MDE check
    (SSL inspection sweep + handshake status sweep) without needing -Domain.

.PARAMETER All
    Optional switch. Runs everything: both the commercial and US Gov SSL inspection
    sweeps and both handshake status sweeps, without needing -Domain. Equivalent to
    passing -AllCommercial and -AllGov together.

.PARAMETER TsharkPath
    Optional. Full path to tshark.exe if it isn't in your PATH.

.PARAMETER Detailed
    Optional switch. Show every individual Client Hello / Server Hello / IP conversation
    instead of just the summary. Only applies to the -Domain analysis.

.PARAMETER ExportCsv
    Optional. Folder path to also dump raw extracts as CSV.

.PARAMETER Copilot
    Optional. Auto (default) | CLI | Chat | Off. After the summary, sends the Section 11
    findings to Copilot for a customer action plan. Auto uses GitHub Copilot CLI if it's
    installed, otherwise copies the prompt and opens Microsoft 365 Copilot Chat.

.EXAMPLE
    .\Analyze-PcapDomain.ps1 -PcapPath "C:\Captures\capture.pcapng" -Domain "eu-v20.events.endpoint.security.microsoft.com"

.EXAMPLE
    .\Analyze-PcapDomain.ps1 -PcapPath "C:\Captures\capture.pcapng" -CheckMdeUrlsOnly
#>

<#
================================================================================
 SWITCH REFERENCE - what each switch does, and when to reach for it
================================================================================

 -Domain "<hostname>"
     Deep-dive on ONE specific domain/URL. Runs sections 1-5 (TLS version
     offered vs negotiated, full cipher list offered vs selected, staged
     handshake status with SYN/SYN-ACK/ACK/TLS breakdown, outbound
     connectivity with byte counts, Microsoft cipher compliance) plus
     section 6 (commercial SSL inspection check) automatically.
     BEST FOR: Root-causing ONE known or suspect URL - usually after a broad
     sweep (below) has already told you where to look. This is also the
     only mode that gives cipher-level and byte-count detail; the sweep
     switches only report pass/fail/stage, not why.

 -CheckMdeUrlsOnly
     Lightweight sweep: ONLY the commercial SSL inspection check (section 6)
     across every documented commercial MDE URL found in the capture.
     No handshake status sweep, no -Domain needed.
     BEST FOR: A quick "is anything being SSL-inspected" pass when you don't
     need pass/fail status on every URL - the fastest of the sweep switches
     since it skips the per-URL handshake staging entirely.

 -CommercialURLHandshakes  (alias: -AllCommercial)
     Full commercial sweep: SSL inspection check (section 6) + handshake
     status sweep (section 7) across every documented commercial MDE URL.
     BEST FOR: Routine health check of all required commercial MDE
     connectivity in one pass, when Gov URLs aren't relevant.

 -govURLHandshakes  (alias: -AllGov)
     Same as -CommercialURLHandshakes, but against the US Gov (GCC/GCC
     High/DoD) URL list instead: SSL inspection check (section 8) +
     handshake status sweep (section 9).
     BEST FOR: Routine health check on Gov-cloud tenants specifically.
     Excludes ordinary commercial domains even if they share a hostname
     pattern with a Gov-documented URL (see the *.endpoint.security note
     in the $GovRequiredUrlPatterns definition below).

 -All
     Runs EVERYTHING: commercial + Gov, both SSL inspection checks and both
     handshake sweeps (sections 6, 7, 8, 9). Does not require -Domain.
     BEST FOR: First-pass triage on a new capture when you don't yet know
     whether the environment is commercial, Gov, or both, or as a routine
     "check everything MDE needs" health check.

 (no switch needed) - Section 10: PROXY DETECTION
     Always runs, on every invocation, regardless of which switch(es) above
     were used. Scans the whole capture for HTTP CONNECT tunnels (explicit
     forward-proxy signal) and 407 Proxy-Authentication-Required responses,
     and annotates each finding: whether the tunneled target is a documented
     MDE URL, whether the proxy accepted/rejected/challenged it, and whether
     TLS actually proceeded afterward. Independent of -Domain and of the
     commercial/Gov URL split, since a proxy in the path affects all traffic.
     BEST FOR: Confirming (not just inferring) that an explicit proxy sits
     between the client and Microsoft, and pinpointing proxy-auth (407) as
     the specific failure stage - a very common root cause for the Sense
     service specifically, since it runs as SYSTEM.

 (no switch needed) - Section 11: SUMMARY & RECOMMENDED ACTIONS
     Always runs last, on every invocation. Pulls together only the real,
     actionable issues found by the sections above - full connectivity
     failures, TLS/SSL inspection signals, missing required cipher suites,
     and proxy-authentication blocks - into a short list, each with a
     likely cause, a suggested fix, and which section above has the
     supporting evidence. Prints a clean "no actionable issues" line
     instead when nothing above found a real problem.
     BEST FOR: A quick, ticket-ready recap to hand to the customer once
     you've already reviewed the detailed sections above - not a
     replacement for reading them, since it deliberately leaves out
     anything ambiguous or purely informational.

 -Detailed
     Expands -Domain mode's summary into full per-frame, per-stream, and
     per-IP output (every Client Hello, every Server Hello, full
     conversation stats). Only affects -Domain mode; ignored by every
     sweep switch above.
     BEST FOR: Deep forensic review of one connection, or when the summary
     alone doesn't have enough detail to explain an anomaly.

 -TsharkPath "<path>"
     Full path to tshark.exe if it isn't on your PATH (commonly
     "C:\Program Files\Wireshark\tshark.exe"). Not required if tshark is
     already callable by name from the shell.

 -ExportCsv "<folder>"
     Also writes raw CSV extracts (DNS, Client Hellos, IP conversations) to
     the given folder for further analysis outside this script.
     BEST FOR: Building an evidence package for a ticket, or feeding raw
     results into Excel, a SIEM, or another tool.

 -Copilot Auto|CLI|Chat|Off
     Section 12. After the summary, sends the Section 11 findings to Copilot
     and asks for the recommended fix, who owns it, and how to verify it
     (engineer-facing only - no customer email). Default is Auto:
       CLI  - GitHub Copilot CLI answers right in this console; the answer
              is also saved next to the PCAP as <name>_CopilotPlan_<time>.md.
       Chat - the prompt is copied to your clipboard and Microsoft 365
              Copilot Chat opens in the browser: paste (Ctrl+V) and Enter.
       Auto - CLI if 'copilot' is installed, otherwise Chat.
       Off  - skip Section 12.
     BEST FOR: Turning the findings into a ticket-ready plan in one step.

--------------------------------------------------------------------------------
 RECOMMENDED WORKFLOW
--------------------------------------------------------------------------------
 1. Run -All (or -AllCommercial / -AllGov if you already know the
    environment) as a routine first pass on any new capture. This checks
    the FULL required URL surface, not just the one domain you already
    suspect - it often surfaces problems you didn't know to look for.
 2. For any URL that comes back [FAILED] or [WARNING] (SSL inspection
    downgrade, missing certificate, handshake failure at a specific stage),
    re-run with -Domain "<that exact URL>" [-Detailed] to get the full
    cipher list, Microsoft compliance check, and byte-level detail needed
    to root-cause or document the issue.
================================================================================
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PcapPath,

    [string]$Domain = "",

    [switch]$CheckMdeUrlsOnly,

    [switch]$CommercialURLHandshakes,

    [switch]$govURLHandshakes,

    [switch]$AllCommercial,

    [switch]$AllGov,

    [switch]$All,

    [string]$TsharkPath = "tshark",

    [switch]$Detailed,

    [string]$ExportCsv,

    [ValidateSet('Auto', 'CLI', 'Chat', 'Off')]
    [string]$Copilot = 'Auto'
)

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host " PCAP Analyzer V16.5.2 - MDE connectivity analysis" -ForegroundColor Cyan
Write-Host " Created by Bryan Rigano | Defender for Endpoint Team" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

function Test-Tshark {
    param([string]$Path)
    try { $null = & $Path -v 2>$null; return $true } catch { return $false }
}

if (-not (Test-Path $PcapPath)) {
    Write-Host "ERROR: PCAP file not found at '$PcapPath'" -ForegroundColor Red
    exit 1
}
if (-not (Test-Tshark -Path $TsharkPath)) {
    Write-Host "ERROR: Could not run tshark at '$TsharkPath'." -ForegroundColor Red
    Write-Host "Install Wireshark or pass -TsharkPath 'C:\Program Files\Wireshark\tshark.exe'" -ForegroundColor Yellow
    exit 1
}
# Prove tshark can actually read this capture. Every query below throws away tshark's
# errors (2>$null), so an unreadable file would otherwise look like a clean capture.
$probe = @(& $TsharkPath -r $PcapPath -c 1 -T fields -e frame.number 2>&1 | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
$probeExit = $LASTEXITCODE
if ($probeExit -ne 0 -or -not ($probe | Where-Object { $_ -match '^\d+$' })) {
    if ($probeExit -eq 0 -and $probe.Count -eq 0) {
        Write-Host "ERROR: '$PcapPath' contains no packets." -ForegroundColor Red
    } else {
        Write-Host "ERROR: tshark could not read '$PcapPath' - no analysis was done." -ForegroundColor Red
        $probe | Select-Object -First 3 | ForEach-Object { Write-Host "       tshark says: $_" -ForegroundColor Yellow }
        Write-Host "       'Permission denied' usually means an admin tool (e.g. MDE Client Analyzer) created the file:" -ForegroundColor Yellow
        Write-Host "       run this as administrator, or copy the capture to a folder you own." -ForegroundColor Yellow
    }
    exit 1
}
if (-not $CheckMdeUrlsOnly -and -not $CommercialURLHandshakes -and -not $govURLHandshakes -and -not $AllCommercial -and -not $AllGov -and -not $All -and [string]::IsNullOrWhiteSpace($Domain)) {
    Write-Host "ERROR: Provide -Domain '<domain>' for a single-domain analysis, -CheckMdeUrlsOnly for the SSL-inspection sweep, -CommercialURLHandshakes (or -AllCommercial) for commercial, -govURLHandshakes (or -AllGov) for US Gov, or -All for everything." -ForegroundColor Red
    exit 1
}
if ($ExportCsv -and -not (Test-Path $ExportCsv)) {
    New-Item -ItemType Directory -Path $ExportCsv -Force | Out-Null
}

# ---------------------------------------------------------------------------
# COPILOT PRE-CHECK - runs BEFORE the analysis (unless -Copilot Chat/Off) so a
# missing CLI or sign-in shows up now, not after the capture is processed.
# 1) finds the GitHub Copilot CLI  2) checks for GitHub credentials and runs
# 'copilot login' if there are none  3) on the first run on this PC, sends a
# one-line test prompt to prove it answers. Section 12 uses the result.
# ---------------------------------------------------------------------------
$script:CopilotCliPath = $null
$script:CopilotOkMarker = Join-Path (Join-Path $(if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $HOME }) 'PCAP-Analyzer') 'copilot-cli-ok.txt'

function Test-CopilotCliReady {
    Write-Host "`nCOPILOT PRE-CHECK:" -ForegroundColor Cyan
    $cli = Get-Command copilot -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cli -and $env:OS -eq 'Windows_NT') {
        # Installed with winget in this same window? Reload PATH so it's visible without reopening
        $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
        $cli = Get-Command copilot -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    $isAdmin = $false
    if ($env:OS -eq 'Windows_NT') {
        try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
    }
    if (-not $cli) {
        Write-Host "     [ ] Copilot CLI not found for user '$env:USERNAME' - Section 12 will use Copilot Chat instead." -ForegroundColor Yellow
        if ($isAdmin) {
            Write-Host "         This is an ADMIN window. winget installs Copilot CLI per user, so run the script from a" -ForegroundColor Yellow
            Write-Host "         normal (non-admin) PowerShell 7 window - the analysis doesn't need admin rights." -ForegroundColor Yellow
        } else {
            Write-Host "         Install it:  winget install GitHub.Copilot   (then open a new PowerShell 7 window)" -ForegroundColor Yellow
        }
        return
    }
    Write-Host "     [x] Copilot CLI found: $($cli.Source)" -ForegroundColor Green

    # GitHub credentials, in the order the CLI itself uses them: env token, then the
    # token 'copilot login' saved in Windows Credential Manager, then a signed-in gh CLI
    $workedBefore = Test-Path -LiteralPath $script:CopilotOkMarker
    $credSource = $null
    if ($env:COPILOT_GITHUB_TOKEN) { $credSource = 'COPILOT_GITHUB_TOKEN environment variable' }
    elseif ($env:GH_TOKEN)         { $credSource = 'GH_TOKEN environment variable' }
    elseif ($env:GITHUB_TOKEN)     { $credSource = 'GITHUB_TOKEN environment variable' }
    if (-not $credSource) {
        try { if (cmdkey /list 2>$null | Select-String -SimpleMatch 'copilot') { $credSource = 'Windows Credential Manager (saved by copilot login)' } } catch { }
    }
    if (-not $credSource -and (Get-Command gh -ErrorAction SilentlyContinue)) {
        try { & gh auth status *> $null; if ($LASTEXITCODE -eq 0) { $credSource = 'GitHub CLI (gh) sign-in' } } catch { }
    }
    if (-not $credSource -and $workedBefore) { $credSource = 'saved by copilot login (the CLI has answered on this PC before)' }

    if ($credSource) {
        Write-Host "     [x] GitHub credentials: $credSource" -ForegroundColor Green
    } else {
        Write-Host "     [ ] No GitHub credentials found - signing in now (one time)." -ForegroundColor Yellow
        Write-Host "         Approve the sign-in in the browser window that opens, then come back here.`n" -ForegroundColor Yellow
        & $cli.Source login
        if ($LASTEXITCODE -ne 0) {
            Write-Host "     [ ] Sign-in didn't complete - Section 12 will use Copilot Chat. Retry any time with:  copilot login" -ForegroundColor Yellow
            return
        }
        Write-Host "     [x] Signed in to GitHub." -ForegroundColor Green
    }

    if ($workedBefore) {
        Write-Host "     [x] Copilot CLI ready - Section 12 will print the customer action plan." -ForegroundColor Green
        $script:CopilotCliPath = $cli.Source
        return
    }

    # First run on this PC: prove it answers end to end (catches sign-in, org policy, and proxy problems now)
    Write-Host "     ... First run on this PC - testing Copilot CLI with a one-line prompt (10-60s)..." -ForegroundColor Cyan
    $job = Start-Job -ScriptBlock { param($exe) & $exe -s -p 'Reply with exactly: COPILOT_OK' 2>&1 | Out-String } -ArgumentList $cli.Source
    $finished = Wait-Job $job -Timeout 120
    $reply = if ($finished) { (Receive-Job $job) -join "`n" } else { 'No reply within 120 seconds.' }
    Remove-Job $job -Force
    if ($reply -match 'COPILOT_OK') {
        try {
            New-Item -ItemType Directory -Path (Split-Path -Parent $script:CopilotOkMarker) -Force | Out-Null
            Set-Content -LiteralPath $script:CopilotOkMarker -Value (Get-Date -Format s)
        } catch { }
        Write-Host "     [x] Copilot CLI answered - Section 12 will print the customer action plan." -ForegroundColor Green
        $script:CopilotCliPath = $cli.Source
    } else {
        Write-Host "     [ ] Copilot CLI test failed - Section 12 will use Copilot Chat instead. It said:" -ForegroundColor Yellow
        ($reply.Trim() -split "`r?`n" | Select-Object -First 8) | ForEach-Object { Write-Host "         $_" -ForegroundColor DarkGray }
        Write-Host "         Signed out / auth error -> run:  copilot login" -ForegroundColor Yellow
        Write-Host "         'policy' / 'not enabled'  -> Copilot CLI is disabled for your account by your org admin" -ForegroundColor Yellow
        Write-Host "         Proxy / certificate error -> something is intercepting HTTPS to GitHub" -ForegroundColor Yellow
    }
}

if ($Copilot -in @('Auto', 'CLI')) { Test-CopilotCliReady }

# Effective flags: -All / -AllCommercial / -AllGov are shorthand for the
# underlying switches, so the rest of the script only needs to check these.
$RunCommercialHandshakes = $CommercialURLHandshakes -or $AllCommercial -or $All
$RunGovHandshakes = $govURLHandshakes -or $AllGov -or $All

$TlsVersionMap = @{
    "0x0300" = "SSL 3.0"; "0x0301" = "TLS 1.0"; "0x0302" = "TLS 1.1"
    "0x0303" = "TLS 1.2"; "0x0304" = "TLS 1.3"
}

$CipherNameMap = @{
    "0x1301" = "TLS_AES_128_GCM_SHA256"
    "0x1302" = "TLS_AES_256_GCM_SHA384"
    "0x1303" = "TLS_CHACHA20_POLY1305_SHA256"
    "0xc02c" = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    "0xc030" = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    "0x009f" = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
    "0xcca9" = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
    "0xcca8" = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    "0xccaa" = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    "0xc02b" = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    "0xc02f" = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    "0x009e" = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
    "0xc024" = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
    "0xc028" = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
    "0x006b" = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
    "0xc023" = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
    "0xc027" = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
    "0x0067" = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
    "0xc00a" = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
    "0xc014" = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
    "0x0039" = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
    "0xc009" = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
    "0xc013" = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
    "0x0033" = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
    "0x009d" = "TLS_RSA_WITH_AES_256_GCM_SHA384"
    "0x009c" = "TLS_RSA_WITH_AES_128_GCM_SHA256"
    "0x003d" = "TLS_RSA_WITH_AES_256_CBC_SHA256"
    "0x003c" = "TLS_RSA_WITH_AES_128_CBC_SHA256"
    "0x0035" = "TLS_RSA_WITH_AES_256_CBC_SHA"
    "0x002f" = "TLS_RSA_WITH_AES_128_CBC_SHA"
}

# Reference: learn.microsoft.com/power-platform/admin/server-cipher-tls-requirements
$MsRequiredTls13Ciphers = @("0x1302", "0x1301")
$MsRequiredTls12Ciphers = @("0xc02b", "0xc02c", "0xc02f", "0xc030", "0xc023", "0xc024", "0xc027", "0xc028")
$MsDeprecatedCiphers = @("0x009d", "0x009c", "0x003d", "0x003c", "0x0035", "0x002f", "0x0039", "0x0033", "0xc009", "0xc00a", "0xc013", "0xc014")

# Reference: learn.microsoft.com/defender-endpoint/standard-device-connectivity-urls-commercial
$MdeRequiredUrlPatterns = @(
    "crl.microsoft.com", "ctldl.windowsupdate.com", "www.microsoft.com",
    "events.data.microsoft.com", "x.cp.wd.microsoft.com", "cdn.x.cp.wd.microsoft.com",
    "packages.microsoft.com", "unitedstates.x.cp.wd.microsoft.com", "us-v20.events.data.microsoft.com",
    "winatp-gw-cus.microsoft.com", "winatp-gw-eus.microsoft.com", "winatp-gw-cus3.microsoft.com",
    "winatp-gw-eus3.microsoft.com", "*.blob.core.windows.net", "winatp-gw-aec0a.microsoft.com",
    "winatp-gw-aen0a.microsoft.com", "europe.x.cp.wd.microsoft.com", "eu-v20.events.data.microsoft.com",
    "winatp-gw-neu.microsoft.com", "winatp-gw-weu.microsoft.com", "winatp-gw-neu3.microsoft.com",
    "winatp-gw-weu3.microsoft.com", "unitedkingdom.x.cp.wd.microsoft.com", "uk-v20.events.data.microsoft.com",
    "winatp-gw-uks.microsoft.com", "winatp-gw-ukw.microsoft.com", "australia.x.cp.wd.microsoft.com",
    "au-v20.events.data.microsoft.com", "winatp-gw-aue.microsoft.com", "winatp-gw-aus.microsoft.com",
    "go.microsoft.com", "definitionupdates.microsoft.com", "*.wdcp.microsoft.com", "*.wd.microsoft.com",
    "*ecs.office.com", "*.smartscreen-prod.microsoft.com",
    "*.smartscreen.microsoft.com", "*.endpoint.security.microsoft.com",
    "endpoint.security.microsoft.com",  # V15: bare name - the wildcard above requires a subdomain
    # Microsoft Defender Antivirus (MAPS / MU-WU / ADL) rows from the SAME doc,
    # "Microsoft Defender Antivirus" service, WW geography - Optional unless noted:
    "*.update.microsoft.com",           # MU/WU security intelligence + product updates (Optional)
    "*.delivery.mp.microsoft.com",      # MU/WU security intelligence + product updates (Optional).
                                         # Covers fe3cr.delivery.mp.microsoft.com/ClientWebService/client.asmx
                                         # too - SNI matching can't see the URL path, only the host.
    "*.windowsupdate.com",              # MU/WU security intelligence + product updates (Optional)
    "*.download.windowsupdate.com",     # Alternate Download Location (ADL), used if signatures are
                                         # 7+ days stale (Optional)
    "*.download.microsoft.com",         # ADL, same as above (Optional)
    "*.wdcpalt.microsoft.com"           # NOTE: NOT in the current live standard-device-connectivity-urls-
                                         # commercial doc's MAPS rows (only *.wdcp/*.wd are listed there
                                         # today) - this appears in older Microsoft/third-party guidance as
                                         # a geo-affinity failover for wdcp. Kept here defensively since
                                         # matching on it costs nothing, but treat it as unconfirmed rather
                                         # than "documented required" if it's the only thing driving a finding.
    # All "Optional" above means: optional if updates are managed internally via
    # WSUS/ConfigMgr/file share. A miss on these alone isn't necessarily a
    # misconfiguration the way a miss on a "Required" entry above is.
    #
    # NOTE: a broad "*.events.data.microsoft.com" wildcard used to be here too, but
    # it caught the gov-specific "us4-v20.events.data.microsoft.com" prefix as well,
    # causing the same domain to appear under both the commercial and gov sections.
    # The specific commercial subdomains (us-v20/eu-v20/uk-v20/au-v20 above) already
    # give full commercial coverage without that ambiguity.
)

# Reference: learn.microsoft.com/defender-endpoint/standard-device-connectivity-urls-gov
# "Required" entries only, covering GCC, GCC High, and DoD. Storage account entries
# (automatedirstr*/ussusg*/wsusg*.blob.core.usgovcloudapi.net etc.) are collapsed into
# the single "*.blob.core.usgovcloudapi.net" wildcard.
$GovRequiredUrlPatterns = @(
    "crl.microsoft.com", "ctldl.windowsupdate.com", "www.microsoft.com",
    "events.data.microsoft.com", "*.wns.windows.com", "login.microsoftonline.com",
    "login.live.com", "cdn.x.cp.wd.microsoft.com",
    "unitedstates4.x.cp.wd.microsoft.us", "us4-v20.events.data.microsoft.com",
    "winatp-gw-usmt.microsoft.com", "winatp-gw-usmv.microsoft.com", "*.blob.core.usgovcloudapi.net",
    "unitedstates1.x.cp.wd.microsoft.us", "winatp-gw-usgt.microsoft.com",
    "unitedstates2.x.cp.wd.microsoft.us", "winatp-gw-usgv.microsoft.com",
    "unitedstates4.cp.wd.microsoft.us", "unitedstates1.cp.wd.microsoft.us", "unitedstates2.cp.wd.microsoft.us",
    "unitedstates4.ss.wd.microsoft.us", "unitedstates1.ss.wd.microsoft.us", "unitedstates2.ss.wd.microsoft.us",
    # V16: GCC High / DoD Defender portal + Entra sign-in. Portal/auth URLs, not
    # device-sensor URLs - usually only seen in a capture if someone used the
    # portal or signed in from that machine.
    "security.microsoft.us", "login.microsoftonline.us",
    "securitycenter.microsoft.us", "*.securitycenter.microsoft.us",
    # V17: GCC High / DoD streamlined connectivity (device-sensor traffic, e.g.
    # mdav.usm.endpoint.security.microsoft.us). Gov-only domain - unlike the
    # commercial *.endpoint.security.microsoft.com noted below, it can't
    # double-report under the commercial section.
    "endpoint.security.microsoft.us", "*.endpoint.security.microsoft.us"
    # NOTE: two categories of pattern are deliberately NOT included here, even
    # though Microsoft's gov doc lists them, because the hostname itself is
    # identical (Geography: WW) to what's already in the commercial list -
    # SNI alone can't tell a gov tenant's use of it from a commercial tenant's,
    # so including it in both sections just double-reports the exact same
    # traffic under two different headings without adding any gov-specific
    # signal:
    #  - "*.endpoint.security.microsoft.com" (streamlined connectivity) -
    #    matches ordinary commercial EU/US/UK/AU MDE traffic too.
    #  - The Defender Antivirus MU/WU/ADL update wildcards -
    #    "*.update.microsoft.com", "*.delivery.mp.microsoft.com",
    #    "*.windowsupdate.com", "*.download.windowsupdate.com",
    #    "*.download.microsoft.com" - these are generic Windows Update/MU
    #    infrastructure shared identically by every Windows device regardless
    #    of tenant type (e.g. tas02.cwsmu.update.microsoft.com,
    #    tas02.sls.update.microsoft.com), not gov-specific. They stay in the
    #    commercial list (section 6/7) only; run that sweep too (or -All) to
    #    see them checked.
)

$ProxyVendorKeywords = @("zscaler", "palo alto", "paloalto", "forcepoint", "bluecoat", "blue coat",
    "fortinet", "fortigate", "netskope", "cisco", "umbrella", "ironport", "websense", "barracuda",
    "checkpoint", "check point", "sonicwall", "watchguard", "sophos", "mcafee", "iboss", "menlo")
$KnownGoodCaKeywords = @("microsoft", "digicert", "globalsign", "sectigo", "comodo", "entrust",
    "baltimore", "godaddy", "let's encrypt", "letsencrypt", "amazon", "google trust")

function Resolve-TlsVersionName {
    param([string]$Code)
    if ([string]::IsNullOrWhiteSpace($Code)) { return "Unknown" }
    $Code = $Code.Trim().ToLower()
    if ($Code -match ",") { $Code = ($Code -split ",")[0] }
    if ($TlsVersionMap.ContainsKey($Code)) { return $TlsVersionMap[$Code] }
    return $Code
}

function Resolve-CipherName {
    param([string]$Code)
    $Code = $Code.Trim().ToLower()
    if ($CipherNameMap.ContainsKey($Code)) { return "$Code ($($CipherNameMap[$Code]))" }
    return $Code
}

function Invoke-TsharkFields {
    param([string]$Filter, [string[]]$FieldNames, [string]$Occurrence = "a")
    $fieldArgs = @()
    foreach ($f in $FieldNames) { $fieldArgs += "-e"; $fieldArgs += $f }
    $tsArgs = @("-r", $PcapPath, "-Y", $Filter, "-T", "fields") + $fieldArgs + @("-E", "separator=|", "-E", "header=n", "-E", "occurrence=$Occurrence")
    $out = & $TsharkPath @tsArgs 2>$null
    if (-not $out) { return @() }
    return $out
}

function Get-FirstValue {
    param([string]$Value)
    if (-not $Value) { return $Value }
    return ($Value -split ",")[0]
}

function ConvertTo-ByteCount {
    param([string]$Number, [string]$Unit)
    $num = 0.0
    [void][double]::TryParse($Number, [ref]$num)
    switch ($Unit) {
        "bytes" { return [int64]$num }
        "kB"    { return [int64]($num * 1024) }
        "MB"    { return [int64]($num * 1024 * 1024) }
        "GB"    { return [int64]($num * 1024 * 1024 * 1024) }
        default { return [int64]$num }
    }
}

function Get-CertificateCommonNames {
    param([string]$Stream)
    $tsArgs = @("-r", $PcapPath, "-Y", "tcp.stream==$Stream && tls.handshake.type==11", "-O", "tls")
    $raw = & $TsharkPath @tsArgs 2>$null
    if (-not $raw) { return @() }
    $text = $raw -join "`n"
    $cns = [regex]::Matches($text, 'id-at-commonName=([^\s\),]+)') | ForEach-Object { $_.Groups[1].Value }
    # A multi-segment Certificate message can get its full reassembled protocol
    # tree echoed once per contributing frame when tshark evaluates the filter,
    # so the same CN set can come back duplicated 2-3x. De-dup to the distinct
    # set actually present in the chain (order preserved).
    return @($cns | Select-Object -Unique)
}

# Cheap existence check: is there a TLS Certificate handshake message (type 11)
# on this stream at all? A downgraded (TLS 1.2 or below) session should always
# have one - a genuine absence is itself an anomaly worth flagging, separate
# from "a certificate was present but its CN couldn't be parsed."
function Test-HasCertificateMessage {
    param([string]$Stream)
    $lines = Invoke-TsharkFields -Filter "tcp.stream==$Stream && tls.handshake.type==11" -FieldNames @("frame.number") -Occurrence "f"
    return ($lines.Count -gt 0)
}

# Shared SSL inspection check: TLS downgrade detection + missing/parsed certificate
# reporting, generalized so it can run against either the commercial or the US Gov
# URL pattern list.
# Shared source of truth: section 6/8 (SSL inspection check) populate this as
# they run, one entry per SNI that had ANY real ServerHello/cert evidence of a
# completed TLS session (regardless of whether it was flagged as inspection).
# Section 7/9 (handshake sweep) defer to this directly to decide whether a
# hostname's connectivity is already confirmed, rather than re-deriving that
# answer from the more fragile per-IP SYN/ClientHello correlation - the two
# sections can then never disagree about the same hostname.
$script:SniConfirmedGoodMap = @{}

function Show-SslInspectionCheck {
    param(
        [string]$SectionNumber,
        [string[]]$Patterns,
        [string]$SourceUrl,
        [string]$UrlSetLabel
    )
    Show-SummaryHeaderOnce
    Write-Host "`n$SectionNumber) SSL INSPECTION CHECK ($UrlSetLabel):"
    Write-Host "     Source: $SourceUrl" -ForegroundColor DarkGray
    Write-Host "     LIMITATION: certificates are only visible for TLS 1.2 sessions (TLS 1.3 encrypts them)." -ForegroundColor DarkGray
    Write-Host "     A TLS 1.3-to-1.2 downgrade is itself a strong inspection signal, since most inspecting proxies cannot terminate TLS 1.3." -ForegroundColor DarkGray

    $matchesForSet = $clientHellos | Where-Object {
        $sni = $_.SNI
        if (-not $sni) { return $false }
        foreach ($pattern in $Patterns) {
            if ($sni -like $pattern) { return $true }
        }
        return $false
    }

    if ($matchesForSet.Count -eq 0) {
        Write-Host "     No traffic to any documented $UrlSetLabel was found in this capture." -ForegroundColor Yellow
        Write-Host "==============================================================================" -ForegroundColor Cyan
        return
    }

    $bySni = $matchesForSet | Group-Object SNI
    $downgradeFound = $false
    $script:SslStrongSignalFound = $false
    foreach ($group in $bySni) {
        $sniName = $group.Name
        $streamsForSni = $group.Group | ForEach-Object { $_.Stream } | Select-Object -Unique
        $anyOk13 = $false
        $downgradeDetails = @()

        foreach ($stream in $streamsForSni) {
            if (-not $serverHellosByStream.ContainsKey($stream)) { continue }
            $sh = $serverHellosByStream[$stream]
            $negCode = if ($sh.SuppVer) { $sh.SuppVer } else { $sh.RecVer }
            $negName = Resolve-TlsVersionName -Code $negCode

            if ($negName -eq "TLS 1.3") {
                $anyOk13 = $true
            } elseif ($negName -eq "TLS 1.2" -or $negName -eq "TLS 1.1" -or $negName -eq "TLS 1.0") {
                $hasCert = Test-HasCertificateMessage -Stream $stream
                $cns = if ($hasCert) { Get-CertificateCommonNames -Stream $stream } else { @() }
                $downgradeDetails += @{ Stream = $stream; Version = $negName; HasCert = $hasCert; Cns = $cns }
            }
        }

        if ($anyOk13 -or $downgradeDetails.Count -gt 0) {
            # Real evidence of a completed TLS session for this SNI, whether it
            # ends up flagged as possible inspection or not - a hostname that's
            # actively being intercepted still isn't a "connectivity" problem
            # in the sense section 7/9's handshake sweep cares about.
            $script:SniConfirmedGoodMap[$sniName] = $true
        }

        if ($downgradeDetails.Count -gt 0) {
            $downgradeFound = $true
            $versionsSeen = $downgradeDetails | ForEach-Object { $_.Version } | Select-Object -Unique
            $worstVersion = if ($versionsSeen -contains "TLS 1.0") { "TLS 1.0" }
                elseif ($versionsSeen -contains "TLS 1.1") { "TLS 1.1" }
                else { "TLS 1.2" }

            # A TLS-version downgrade alone is not proof of inspection - plenty of
            # legitimate causes exist (FIPS-mode Schannel restricting to TLS 1.2 -
            # a Windows security policy setting, common in Gov/DoD-compliant
            # configurations but not exclusive to them, since any Windows device
            # can have it enabled - server-side version support, etc). Only
            # treat it as a real
            # inspection signal when the certificate itself looks wrong: a known
            # proxy-vendor CN, a missing certificate message entirely, or a CN that
            # doesn't match any known public/Microsoft CA. Deprecated TLS 1.0/1.1 is
            # kept as a strong signal on its own regardless of the cert, since
            # genuine Microsoft endpoints essentially never negotiate it today.
            $anyProxyKeyword = $false
            $anyMissingCert = $false
            $anyUnknownCn = $false
            $allKnownGoodCn = $true
            foreach ($detail in $downgradeDetails) {
                if (-not $detail.HasCert) {
                    $anyMissingCert = $true
                    $allKnownGoodCn = $false
                    continue
                }
                if ($detail.Cns.Count -eq 0) {
                    $allKnownGoodCn = $false
                    continue
                }
                $findingLower = ($detail.Cns -join ", ").ToLower()
                $hasProxyKeyword = ($ProxyVendorKeywords | Where-Object { $findingLower -like "*$_*" }).Count -gt 0
                $hasKnownGoodKeyword = ($KnownGoodCaKeywords | Where-Object { $findingLower -like "*$_*" }).Count -gt 0
                if ($hasProxyKeyword) { $anyProxyKeyword = $true }
                if (-not $hasKnownGoodKeyword) { $allKnownGoodCn = $false }
                if (-not $hasProxyKeyword -and -not $hasKnownGoodKeyword) { $anyUnknownCn = $true }
            }
            $isDeprecatedVersion = ($worstVersion -eq "TLS 1.0" -or $worstVersion -eq "TLS 1.1")
            $isStrongSignal = $isDeprecatedVersion -or $anyProxyKeyword -or $anyMissingCert -or $anyUnknownCn

            if ($isStrongSignal) {
                $script:SslStrongSignalFound = $true
                Write-Host "     [WARNING] $sniName - negotiated $worstVersion on at least one session (possible SSL inspection)" -ForegroundColor Red
                if ($isDeprecatedVersion) {
                    Write-Host "         $worstVersion is deprecated and essentially never negotiated by genuine Microsoft endpoints today - a stronger interception indicator than a plain TLS 1.2 downgrade." -ForegroundColor Red
                }

                $signalReasons = @()
                if ($anyProxyKeyword) { $signalReasons += "certificate CN matches a known SSL-inspection proxy vendor" }
                if ($anyMissingCert) { $signalReasons += "no TLS certificate message was observed at all" }
                if ($anyUnknownCn) { $signalReasons += "certificate CN does not match a known public/Microsoft CA" }
                if ($isDeprecatedVersion) { $signalReasons += "negotiated $worstVersion, which genuine Microsoft endpoints essentially never use" }

                Add-Finding -Category "TLS / SSL Inspection" `
                    -GroupKey "SSLInspection|$sniName" `
                    -Target $sniName `
                    -Section "Section $SectionNumber (SSL Inspection Check - $UrlSetLabel)" `
                    -Issue "Possible SSL inspection on $sniName - $($signalReasons -join '; ')." `
                    -LikelyCause "An SSL/TLS-inspecting device (proxy, firewall, or endpoint security tool) in the path is intercepting and re-signing this traffic, or forcing a downgrade to an older TLS version." `
                    -SuggestedFix "Add an SSL-inspection bypass/exclusion for the listed MDE URL(s) on the inspecting device, per Microsoft's documented TLS inspection exclusion guidance. If a bypass is already configured, verify it is actually being applied to this traffic."
            } else {
                Write-Host "     [INFO]    $sniName - negotiated $worstVersion on at least one session; certificate verified as a standard public/Microsoft CA, so NOT flagged as SSL inspection" -ForegroundColor Green
                Write-Host "         (TLS 1.2 alone is not an inspection signal - e.g. FIPS-mode Schannel (a Windows security policy, common in Gov/DoD-compliant setups but not exclusive to them), or server-side version support, can produce this legitimately.)" -ForegroundColor DarkGray
            }

            $detailGroups = @($downgradeDetails | Group-Object {
                if (-not $_.HasCert) { "NOCERT|$($_.Version)" }
                elseif ($_.Cns.Count -eq 0) { "UNPARSED|$($_.Version)" }
                else { "$($_.Version)|" + ($_.Cns -join ",") }
            })
            foreach ($dg in $detailGroups) {
                $sample = $dg.Group[0]
                $streamNums = @($dg.Group | ForEach-Object { $_.Stream })
                $label = if ($streamNums.Count -eq 1) {
                    "Stream $($streamNums[0])"
                } else {
                    $shown = ($streamNums | Select-Object -First 5) -join ", "
                    $more = if ($streamNums.Count -gt 5) { ", +$($streamNums.Count - 5) more" } else { "" }
                    "$($streamNums.Count) streams ($shown$more)"
                }
                if (-not $sample.HasCert) {
                    Write-Host "         $label ($($sample.Version)): NO certificate message observed at all - the certificate is missing entirely, another possible sign of interception or an abnormal handshake." -ForegroundColor Red
                } elseif ($sample.Cns.Count -gt 0) {
                    $finding = ($sample.Cns -join ", ")
                    $findingLower = $finding.ToLower()
                    $hasProxyKeyword = ($ProxyVendorKeywords | Where-Object { $findingLower -like "*$_*" }).Count -gt 0
                    $hasKnownGoodKeyword = ($KnownGoodCaKeywords | Where-Object { $findingLower -like "*$_*" }).Count -gt 0
                    Write-Host "         $label ($($sample.Version)) certificate CN(s): $finding"
                    if ($hasProxyKeyword) {
                        Write-Host "         -> Matches a known SSL-inspection proxy vendor name. Likely being intercepted." -ForegroundColor Red
                    } elseif (-not $hasKnownGoodKeyword) {
                        Write-Host "         -> Does not match a known public/Microsoft CA. Verify manually." -ForegroundColor Yellow
                    } else {
                        Write-Host "         -> Appears to be a standard public/Microsoft CA." -ForegroundColor Green
                    }
                } else {
                    Write-Host "         $label ($($sample.Version)): certificate message present but its CN could not be parsed automatically. Inspect manually with, e.g.:" -ForegroundColor Yellow
                    Write-Host "         tshark -r `"$PcapPath`" -Y `"tcp.stream==$($streamNums[0]) && tls.handshake.type==11`" -O tls" -ForegroundColor Yellow
                }
            }
            if ($Detailed -and $detailGroups.Count -lt $downgradeDetails.Count) {
                Write-Host "         (Grouped by identical finding above - $($downgradeDetails.Count) total streams matched $sniName. Full per-stream list:)" -ForegroundColor DarkGray
                foreach ($detail in $downgradeDetails) {
                    $certNote = if (-not $detail.HasCert) { "no certificate" } elseif ($detail.Cns.Count -gt 0) { ($detail.Cns -join ", ") } else { "cert present, CN unparsed" }
                    Write-Host "           Stream $($detail.Stream) ($($detail.Version)): $certNote" -ForegroundColor DarkGray
                }
            }
        } elseif ($anyOk13) {
            Write-Host "     [OK]      $sniName - TLS 1.3 negotiated, no downgrade detected" -ForegroundColor Green
        }
    }
    if (-not $script:SslStrongSignalFound) {
        if ($downgradeFound) {
            Write-Host "`n     Overall: no SSL-inspection indicators found across $($bySni.Count) $UrlSetLabel contacted - only benign TLS 1.2 downgrade(s) seen, each verified against a standard Microsoft/public CA." -ForegroundColor Green
        } else {
            Write-Host "`n     Overall: no TLS version downgrades detected across $($bySni.Count) $UrlSetLabel contacted in this capture." -ForegroundColor Green
        }
        Write-Host "     This is a good sign against SSL inspection, though it cannot fully confirm it since certificates under TLS 1.3 are not visible in a passive capture." -ForegroundColor DarkGray
    }
    Write-Host "==============================================================================" -ForegroundColor Cyan
}


$script:SummaryHeaderShown = $false
function Show-SummaryHeaderOnce {
    if (-not $script:SummaryHeaderShown) {
        Write-Host "`n================================= SUMMARY =================================" -ForegroundColor Cyan
        $script:SummaryHeaderShown = $true
    }
}

# ---------------------------------------------------------------------------
# Real-issue tracking for the closing SUMMARY & RECOMMENDED ACTIONS section
# (11). Every check below that finds a genuine, actionable
# problem - a full connectivity failure, an SSL-inspection signal, a missing
# required cipher suite, or a proxy-auth block - calls Add-Finding at the
# exact point where that determination is already made, so section 11 never
# has to re-derive anything and can never disagree with the detail above it.
# [OK]/[INFO]/inconclusive results are deliberately never added here.
# ---------------------------------------------------------------------------
$script:Findings = @()

function Add-Finding {
    param(
        [string]$Category,
        [string]$GroupKey,
        [string]$Target,
        [string]$Section,
        [string]$Issue,
        [string]$LikelyCause,
        [string]$SuggestedFix,
        [string]$Note = ""
    )
    $existing = $script:Findings | Where-Object { $_.GroupKey -eq $GroupKey }
    if ($existing) {
        if ($existing.Targets -notcontains $Target) { $existing.Targets += $Target }
        if ($Note -and -not $existing.Note) { $existing.Note = $Note }
        return
    }
    $script:Findings += [PSCustomObject]@{
        Category     = $Category
        GroupKey     = $GroupKey
        Targets      = @($Target)
        Section      = $Section
        Issue        = $Issue
        LikelyCause  = $LikelyCause
        SuggestedFix = $SuggestedFix
        Note         = $Note
    }
}

# Shared cause/fix text for a connectivity failure, keyed off the same
# $status.Stage values Get-IpHandshakeStatus already returns, so the wording
# stays consistent whether the failure came from the -Domain analysis or
# either URL handshake sweep.
function Get-ConnectivityIssueGuidance {
    param([string]$Stage, [string]$Reason)
    switch ($Stage) {
        "Network" {
            return @{
                Cause = "The network path returned an explicit error (e.g. a firewall/router actively rejecting the connection) rather than simply timing out."
                Fix   = "Check firewall/routing ACLs between the client and this destination for an explicit deny rule, and confirm outbound TCP 443 is permitted to this IP."
            }
        }
        "SYN-ACK" {
            return @{
                Cause = "The connection attempt got no response at all - most consistent with outbound TCP 443 being blocked/filtered somewhere in the path, or the destination being unreachable."
                Fix   = "Confirm outbound TCP 443 is allowed end-to-end (firewall, proxy, NSG/security group) to this destination, and that DNS is resolving to a current Microsoft IP."
            }
        }
        "ACK" {
            return @{
                Cause = "The TCP handshake did not complete - the server's SYN-ACK was seen but the client's final ACK never went out, which usually points to asymmetric routing or a device silently dropping mid-handshake."
                Fix   = "Check for asymmetric routing (return traffic taking a different path) and confirm no security device is dropping the final ACK."
            }
        }
        "TLS Alert" {
            return @{
                Cause = "TLS was actively rejected during the handshake ($Reason)."
                Fix   = "Check for SSL/TLS inspection interfering with the handshake, a blocked or untrusted CA on this device, or a URL/SNI filtering rule blocking this hostname."
            }
        }
        "TLS Server Hello" {
            return @{
                Cause = "A TLS Client Hello was sent but the server never responded - the session is being dropped mid-handshake, consistent with SNI-based filtering or a proxy/firewall interfering after the TCP handshake completes."
                Fix   = "Check for SNI-based blocking or a proxy/firewall dropping TLS traffic to this hostname specifically, and confirm the endpoint itself is reachable and healthy."
            }
        }
        default {
            return @{
                Cause = "The connection did not complete ($Reason)."
                Fix   = "Review the evidence in the cited section for the specific failure point and check firewall/proxy configuration accordingly."
            }
        }
    }
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " PCAP Domain Analysis" -ForegroundColor Cyan
Write-Host " File:   $PcapPath" -ForegroundColor Cyan
if ($Domain) {
    Write-Host " Domain: $Domain" -ForegroundColor Cyan
} else {
    Write-Host " Domain: (none - MDE URL SSL-inspection sweep only)" -ForegroundColor Cyan
}
Write-Host "=================================================================" -ForegroundColor Cyan

$domainLabels = if ($Domain) { ($Domain -split '\.') | Where-Object { $_.Length -ge 3 } } else { @() }

# ---------------------------------------------------------------------------
# DNS (full capture pull; domain-filtering happens later, only if -Domain given)
# ---------------------------------------------------------------------------
$dnsLines = Invoke-TsharkFields -Filter "dns" -FieldNames @(
    "frame.number", "frame.time", "ip.src", "ip.dst",
    "dns.qry.name", "dns.flags.response", "dns.a", "dns.resp.ttl", "dns.flags.rcode"
)
$dnsRecords = @()
foreach ($line in $dnsLines) {
    $c = $line -split "\|"
    if ($c.Count -ge 9 -and $c[4]) {
        $dnsRecords += [PSCustomObject]@{ Frame=$c[0]; Src=$c[2]; Dst=$c[3]; QryName=$c[4]; A=$c[6]; Ttl=$c[7]; Rcode=$c[8] }
    }
}
if ($ExportCsv) { $dnsLines | Out-File (Join-Path $ExportCsv "all_dns.csv") -Encoding UTF8 }

# ---------------------------------------------------------------------------
# Client Hellos (full capture - used both for -Domain match and the MDE sweep)
# ---------------------------------------------------------------------------
$chLines = Invoke-TsharkFields -Filter "tls.handshake.type == 1" -FieldNames @(
    "frame.number", "ip.src", "ip.dst", "tcp.stream",
    "tls.handshake.extensions_server_name", "tls.record.version",
    "tls.handshake.extensions.supported_version", "tls.handshake.ciphersuite"
)
$clientHellos = @()
foreach ($line in $chLines) {
    $c = $line -split "\|"
    if ($c.Count -ge 8) {
        $clientHellos += [PSCustomObject]@{
            Frame=$c[0]; Src=$c[1]; Dst=$c[2]; Stream=$c[3]; SNI=$c[4]
            RecVer=$c[5]; SuppVer=$c[6]; Ciphers=$c[7]
        }
    }
}
if ($ExportCsv) { $chLines | Out-File (Join-Path $ExportCsv "all_client_hellos.csv") -Encoding UTF8 }

# ---------------------------------------------------------------------------
# Server Hellos (full capture)
# ---------------------------------------------------------------------------
$shLines = Invoke-TsharkFields -Filter "tls.handshake.type == 2" -FieldNames @(
    "frame.number", "ip.src", "ip.dst", "tcp.stream",
    "tls.record.version", "tls.handshake.extensions.supported_version", "tls.handshake.ciphersuite"
)
$serverHellosByStream = @{}
foreach ($line in $shLines) {
    $c = $line -split "\|"
    if ($c.Count -ge 7) {
        $serverHellosByStream[$c[3]] = [PSCustomObject]@{
            Src=$c[1]; Dst=$c[2]; RecVer=$c[4]; SuppVer=$c[5]; Cipher=$c[6]
        }
    }
}

# ---------------------------------------------------------------------------
# TLS Alerts / TCP Resets (full capture)
# ---------------------------------------------------------------------------
$alertLines = Invoke-TsharkFields -Filter "tls.record.content_type == 21" -FieldNames @("tcp.stream", "tls.alert_message.level", "tls.alert_message.desc") -Occurrence "f"
$alertsByStream = @{}
foreach ($line in $alertLines) {
    $c = $line -split "\|"
    if ($c.Count -ge 3) { $alertsByStream[(Get-FirstValue $c[0])] = "$($c[1]) - $($c[2])" }
}
$rstLines = Invoke-TsharkFields -Filter "tcp.flags.reset == 1" -FieldNames @("tcp.stream", "ip.src", "ip.dst") -Occurrence "f"
$rstByStream = @{}
foreach ($line in $rstLines) {
    $c = $line -split "\|"
    if ($c.Count -ge 3) { $rstByStream[(Get-FirstValue $c[0])] = "$($c[1]) -> $($c[2])" }
}

$IcmpCodeMap = @{
    "0" = "Network Unreachable"; "1" = "Host Unreachable"; "2" = "Protocol Unreachable"; "3" = "Port Unreachable"
    "9" = "Network Administratively Prohibited (blocked by firewall/policy)"
    "10" = "Host Administratively Prohibited (blocked by firewall/policy)"
    "13" = "Communication Administratively Prohibited (blocked by firewall/policy)"
}

# ---------------------------------------------------------------------------
# TCP handshake stages (full capture) - SYN, SYN-ACK, final ACK, ICMP errors.
# Computed once, unconditionally, so both the -Domain analysis and the
# -CommercialURLHandshakes sweep can reuse the same data without re-running
# tshark separately for each.
# ---------------------------------------------------------------------------
$synLines = Invoke-TsharkFields -Filter "tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == 443" -FieldNames @("ip.dst", "tcp.stream") -Occurrence "f"
$synAckLines = Invoke-TsharkFields -Filter "tcp.flags.syn == 1 && tcp.flags.ack == 1 && tcp.srcport == 443" -FieldNames @("ip.src", "tcp.stream") -Occurrence "f"
$ackLines = Invoke-TsharkFields -Filter "tcp.flags.syn == 0 && tcp.flags.ack == 1 && tcp.len == 0 && tcp.dstport == 443" -FieldNames @("tcp.stream") -Occurrence "f"
# V15: occurrence "l" = inner (quoted) IP header, i.e. the original destination
# the client was trying to reach. The outer ip.dst is the client itself.
$icmpLines = Invoke-TsharkFields -Filter "icmp.type == 3" -FieldNames @("ip.dst", "icmp.code") -Occurrence "l"

$synByIp = @{}
foreach ($line in $synLines) {
    $c = $line -split "\|"
    if ($c.Count -ge 2) {
        $ip = $c[0]; $stream = Get-FirstValue $c[1]
        if (-not $synByIp.ContainsKey($ip)) { $synByIp[$ip] = @() }
        $synByIp[$ip] += $stream
    }
}
$synAckByIp = @{}
foreach ($line in $synAckLines) {
    $c = $line -split "\|"
    if ($c.Count -ge 2) {
        $ip = $c[0]
        if (-not $synAckByIp.ContainsKey($ip)) { $synAckByIp[$ip] = $true }
    }
}
$icmpByIp = @{}
foreach ($line in $icmpLines) {
    $c = $line -split "\|"
    if ($c.Count -ge 2) {
        $ip = $c[0]; $code = Get-FirstValue $c[1]
        $desc = if ($IcmpCodeMap.ContainsKey($code)) { $IcmpCodeMap[$code] } else { "ICMP unreachable (code $code)" }
        $icmpByIp[$ip] = $desc
    }
}
$ackStreams = ($ackLines | ForEach-Object { Get-FirstValue $_ }) | Select-Object -Unique

# ---------------------------------------------------------------------------
# HTTP CONNECT tunnels / HTTP response codes (full capture) - used by the
# proxy detection sweep (Section 10). An HTTP CONNECT is the explicit-forward-
# proxy tell: the client is asking a proxy to open a tunnel to <host>:<port>
# on its behalf, which only happens when a proxy is configured/enforced in
# the path. A 407 anywhere (CONNECT or plain HTTP) means a proxy demanded
# authentication before it would proceed.
# ---------------------------------------------------------------------------
$connectLines = Invoke-TsharkFields -Filter 'http.request.method == "CONNECT"' -FieldNames @(
    "frame.number", "frame.time", "ip.src", "ip.dst", "tcp.stream", "tcp.dstport", "http.request.uri"
) -Occurrence "f"
$connectRequests = @()
foreach ($line in $connectLines) {
    $c = $line -split "\|"
    if ($c.Count -ge 7) {
        $connectRequests += [PSCustomObject]@{
            Frame=$c[0]; Time=$c[1]; Src=$c[2]; Dst=$c[3]; Stream=$c[4]; DstPort=$c[5]; Target=$c[6]
        }
    }
}

$httpRespLines = Invoke-TsharkFields -Filter "http.response.code" -FieldNames @(
    "frame.number", "tcp.stream", "http.response.code", "http.response.phrase"
) -Occurrence "f"
$httpResponseByStream = @{}
$all407Frames = @()
foreach ($line in $httpRespLines) {
    $c = $line -split "\|"
    if ($c.Count -ge 4 -and $c[1]) {
        # Keep the FIRST response seen per stream - for a CONNECT tunnel this
        # is the proxy's accept/deny (200 = tunnel established, 407 = auth
        # required, anything else = proxy-side rejection/error).
        if (-not $httpResponseByStream.ContainsKey($c[1])) {
            $httpResponseByStream[$c[1]] = [PSCustomObject]@{ Frame=$c[0]; Code=$c[2]; Phrase=$c[3] }
        }
        if ($c[2] -eq "407") {
            $all407Frames += [PSCustomObject]@{ Frame=$c[0]; Stream=$c[1]; Phrase=$c[3] }
        }
    }
}

# Per-stream payload byte totals, in a single pass over the whole capture -
# used by the proxy detection sweep to tell "tunnel accepted, no ClientHello,
# and literally zero bytes moved" (consistent with a genuine stall) apart
# from "tunnel accepted, no detected ClientHello, but data DID flow" (points
# to a TLS-record parsing/reassembly gap in this capture instead). Kept as
# one bulk pass rather than calling Get-StreamByteCounts per-stream, since a
# busy capture can have dozens of CONNECT tunnels and that function spawns a
# tshark process per stream it's given.
$tcpLenLines = Invoke-TsharkFields -Filter "tcp.len > 0" -FieldNames @("tcp.stream", "tcp.len") -Occurrence "f"
$streamPayloadBytes = @{}
foreach ($line in $tcpLenLines) {
    $c = $line -split "\|"
    if ($c.Count -ge 2 -and $c[0]) {
        $len = 0
        [void][int]::TryParse($c[1], [ref]$len)
        if ($streamPayloadBytes.ContainsKey($c[0])) { $streamPayloadBytes[$c[0]] += $len } else { $streamPayloadBytes[$c[0]] = $len }
    }
}

# CONNECT targets are authority-form "host:port" (RFC 7231 s5.3) - strip the
# port so the host can be matched against the documented MDE URL patterns.
function Get-HostFromConnectTarget {
    param([string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $Target }
    if ($Target -match '^(.+):(\d+)$') { return $matches[1] }
    return $Target
}

# Pulls total byte counts for a set of TCP streams via tshark's conv stat.
function Get-StreamByteCounts {
    param([string[]]$Streams)
    $result = @{}
    foreach ($stream in $Streams) {
        $convArgs = @("-r", $PcapPath, "-q", "-z", "conv,tcp,tcp.stream==$stream")
        $convOut = & $TsharkPath @convArgs 2>$null
        $dataLine = $convOut | Where-Object { $_ -match '<->' } | Select-Object -First 1
        if ($dataLine -and $dataLine -match '<->\s+\S+\s+(\d+)\s+([\d.]+)\s+(\S+)\s+(\d+)\s+([\d.]+)\s+(\S+)\s+(\d+)\s+([\d.]+)\s+(\S+)') {
            $totalFrames = [int]$matches[7]
            $totalBytes = ConvertTo-ByteCount -Number $matches[8] -Unit $matches[9]
            $result[$stream] = @{ Frames = $totalFrames; Bytes = $totalBytes }
        }
    }
    return $result
}

# Determines the connection status for one destination IP by walking the
# stages in order (SYN, SYN-ACK, ACK, TLS Client Hello, TLS Server Hello,
# data) and stopping at the first one that didn't complete. Shared by both
# the -Domain analysis and the -CommercialURLHandshakes sweep so the failure
# logic only lives in one place.
function Get-IpHandshakeStatus {
    param(
        [string]$Ip,
        [array]$RelevantClientHellos,
        [hashtable]$ByteCounts
    )
    $sentSyn = $synByIp.ContainsKey($Ip)
    $gotSynAck = $synAckByIp.ContainsKey($Ip)
    $gotIcmp = $icmpByIp.ContainsKey($Ip)
    $matchingStreams = if ($synByIp.ContainsKey($Ip)) { $synByIp[$Ip] } else { @() }
    $gotFinalAck = ($matchingStreams | Where-Object { $ackStreams -contains $_ }).Count -gt 0
    $hadClientHello = ($RelevantClientHellos | Where-Object { $_.Dst -eq $Ip }).Count -gt 0
    $hadServerHello = ($matchingStreams | Where-Object { $serverHellosByStream.ContainsKey($_) }).Count -gt 0
    $hadAlert = $false
    $alertDetail = $null
    $hadReset = $false
    $resetDetail = $null
    foreach ($s in $matchingStreams) {
        if ($alertsByStream.ContainsKey($s)) { $hadAlert = $true; $alertDetail = $alertsByStream[$s] }
        if ($rstByStream.ContainsKey($s)) { $hadReset = $true; $resetDetail = $rstByStream[$s] }
    }
    $hadData = ($matchingStreams | Where-Object {
        $ByteCounts.ContainsKey($_) -and $ByteCounts[$_].Bytes -gt 2048
    }).Count -gt 0

    if ($gotIcmp) {
        return @{ Ok = $false; Stage = "Network"; Reason = "ICMP error: $($icmpByIp[$Ip])" }
    } elseif (-not $sentSyn) {
        return @{ Ok = $null; Stage = "No attempt"; Reason = "No outbound TCP SYN observed to this IP in the capture" }
    } elseif (-not $gotSynAck) {
        return @{ Ok = $false; Stage = "SYN-ACK"; Reason = "TCP SYN sent, no SYN-ACK received - server unreachable, connection filtered, or request timed out" }
    } elseif (-not $gotFinalAck -and -not $hadClientHello) {
        return @{ Ok = $false; Stage = "ACK"; Reason = "SYN-ACK received, but the client's final ACK was never sent/captured - TCP handshake did not complete" }
    } elseif ($hadAlert) {
        # tls.record.content_type==21 catches the record layer even when the
        # alert's own level/desc payload is encrypted (common for TLS 1.2
        # alerts sent after ChangeCipherSpec - the record header is visible,
        # the alert body isn't, without the session keys). A completed
        # session with real data that then closes this way is very likely a
        # normal close_notify, not a rejection - only treat it as a failure
        # when we either know the alert was bad, or too little data moved
        # for a normal close to make sense.
        $alertLevelKnown = $alertDetail -and ($alertDetail.Trim() -ne "-" ) -and ($alertDetail -match '\S')
        $alertStreams = $matchingStreams | Where-Object { $alertsByStream.ContainsKey($_) }
        $alertBytes = ($alertStreams | ForEach-Object { if ($streamPayloadBytes.ContainsKey($_)) { $streamPayloadBytes[$_] } else { 0 } } | Measure-Object -Sum).Sum
        $hadSubstantialData = $alertBytes -gt 2048

        if ($alertLevelKnown) {
            return @{ Ok = $false; Stage = "TLS Alert"; Reason = "TLS was rejected: $alertDetail ($alertBytes bytes exchanged first)." }
        } elseif ($hadSubstantialData) {
            $resetNote = if ($hadReset) { " (Connection also ended with a TCP reset from $resetDetail after the data - normal cleanup, not a red flag here.)" } else { "" }
            return @{ Ok = $null; Stage = "TLS Close (uncertain)"; Reason = "Session completed normally - $alertBytes bytes exchanged - then closed with a TLS alert whose exact reason can't be read (encrypted). Looks like a routine close, not a rejection.$resetNote" }
        } else {
            $resetNote = if ($hadReset) { " A TCP reset from $resetDetail followed too, which fits an active block." } else { "" }
            return @{ Ok = $false; Stage = "TLS Alert"; Reason = "Only $alertBytes bytes exchanged before the session closed with a TLS alert whose exact reason can't be read (encrypted) - consistent with an early rejection (e.g. blocked, or the certificate wasn't trusted).$resetNote" }
        }
    } elseif (-not $hadClientHello) {
        return @{ Ok = $null; Stage = "TLS Client Hello"; Reason = "TCP handshake completed, but no TLS Client Hello was sent to this IP (application-level, not a network failure)" }
    } elseif ($hadReset -and -not $hadData) {
        return @{ Ok = $false; Stage = "TLS handshake"; Reason = "Connection reset before data was exchanged ($resetDetail)" }
    } elseif (-not $hadServerHello) {
        return @{ Ok = $false; Stage = "TLS Server Hello"; Reason = "Client Hello sent, but the server never responded with a Server Hello - TLS handshake failed or timed out" }
    } elseif ($hadData) {
        return @{ Ok = $true; Stage = "Complete"; Reason = "Full handshake (SYN, SYN-ACK, ACK, TLS) completed and data exchanged" }
    } else {
        return @{ Ok = $null; Stage = "Data"; Reason = "TLS handshake completed but under 2 KB of follow-up data (may still be fine)" }
    }
}

# V15: builds the per-hostname target list for the handshake sweeps (7 and 9).
# V14 built each hostname's IP list from TLS Client Hellos only, so any IP that
# failed BEFORE TLS (SYN dropped, ICMP unreachable) was invisible to the sweep.
# This merges in DNS-resolved IPs for the same hostname - but only ones the
# device actually tried and that failed pre-TLS (SYN sent + no SYN-ACK, or an
# ICMP unreachable). Untried IPs from a multi-A DNS answer are normal and are
# skipped; IPs that did complete TCP would already have a Client Hello (under
# this or another hostname), so adding them here would only create noise.
# Also covers hostnames seen only in DNS with no TLS at all.
function Get-SweepHostTargets {
    param([array]$ClientHelloMatches, [array]$DnsMatches)
    $targets = @()
    $names = @(@($ClientHelloMatches | ForEach-Object { $_.SNI }) + @($DnsMatches | ForEach-Object { $_.QryName })) |
        Where-Object { $_ } | ForEach-Object { $_.ToLower() } | Select-Object -Unique
    foreach ($name in $names) {
        $chs = @($ClientHelloMatches | Where-Object { $_.SNI -and $_.SNI.ToLower() -eq $name })
        $chIps = @($chs | ForEach-Object { $_.Dst } | Where-Object { $_ } | Select-Object -Unique)
        $dnsIps = @($DnsMatches | Where-Object { $_.QryName -and $_.QryName.ToLower() -eq $name -and $_.A } |
            ForEach-Object { $_.A -split "[;,]" } | ForEach-Object { $_.Trim() } |
            Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -Unique)
        $preTlsFailedDnsIps = @($dnsIps | Where-Object {
            ($chIps -notcontains $_) -and (
                $icmpByIp.ContainsKey($_) -or
                ($synByIp.ContainsKey($_) -and -not $synAckByIp.ContainsKey($_))
            )
        })
        $targets += [PSCustomObject]@{
            Name         = $name
            ClientHellos = $chs
            Ips          = @(@($chIps) + @($preTlsFailedDnsIps) | Select-Object -Unique)
            HasTls       = ($chs.Count -gt 0)
            AddedFromDns = $preTlsFailedDnsIps.Count
        }
    }
    return $targets
}

# Shared per-SNI handshake status display, used by both the commercial (7) and
# US Gov (9) handshake sweeps. DNS commonly returns multiple IPs for one MDE
# hostname, and the client can open TCP to more than one candidate in parallel
# (connection racing / socket pre-warming) before picking a winner for the
# actual TLS session. The loser socket(s) complete TCP but never send a TLS
# Client Hello - that is expected behavior, not a failure. So: if ANY IP for
# this hostname completed a full handshake, downgrade that specific "no Client
# Hello sent" result from UNKNOWN to INFO instead of treating it as suspect.
function Show-HandshakeStatusForSni {
    param(
        [string]$SniName,
        [array]$IpsForSni,
        [array]$GroupClientHellos,
        [hashtable]$ByteCountsForSni,
        [string]$SectionNumber = ""
    )
    $results = foreach ($ip in $IpsForSni) {
        [PSCustomObject]@{ Ip = $ip; Status = (Get-IpHandshakeStatus -Ip $ip -RelevantClientHellos $GroupClientHellos -ByteCounts $ByteCountsForSni) }
    }
    $anyComplete = ($results | Where-Object { $_.Status.Ok -eq $true }).Count -gt 0
    # Stronger, independent corroboration: did ANY stream tied to this SNI get
    # a real ServerHello back, regardless of which IP the fragile per-IP SYN
    # correlation attributed it to? This catches cases the per-IP $anyComplete
    # check misses entirely - e.g. a converted-trace capture where every
    # individual IP shows "no Client Hello sent" even though the SNI-level
    # cert check (section 6/8) already proved a real negotiated session
    # exists somewhere in the capture for this exact hostname.
    $sniHadServerHello = ($GroupClientHellos | Where-Object { $serverHellosByStream.ContainsKey($_.Stream) }).Count -gt 0
    $sniConfirmedBySslCheck = $script:SniConfirmedGoodMap.ContainsKey($SniName) -and $script:SniConfirmedGoodMap[$SniName]
    $hostnameConfirmedGood = $anyComplete -or $sniHadServerHello -or $sniConfirmedBySslCheck

    $counts = @{ Ok = 0; Failed = 0; Unknown = 0; Info = 0 }
    $collapsedCount = 0
    foreach ($r in $results) {
        $ip = $r.Ip
        $status = $r.Status
        if ($status.Ok -eq $true) {
            $counts.Ok++
            Write-Host "     [OK]      $SniName ($ip) - [$($status.Stage)] $($status.Reason)" -ForegroundColor Green
        } elseif ($status.Ok -eq $false) {
            # Always shown individually, regardless of corroboration - a real
            # failure on one IP is worth knowing even if another IP/stream for
            # the same hostname is fine.
            $counts.Failed++
            Write-Host "     [FAILED]  $SniName ($ip) - FAILED AT: $($status.Stage) - $($status.Reason)" -ForegroundColor Red
            $guidance = Get-ConnectivityIssueGuidance -Stage $status.Stage -Reason $status.Reason
            Add-Finding -Category "Connectivity" `
                -GroupKey "Connectivity|$SniName|$($status.Stage)" `
                -Target "$SniName ($ip)" `
                -Section "Section $SectionNumber (MDE URL Handshake Status sweep)" `
                -Issue "$SniName failed at the $($status.Stage) stage - $($status.Reason)" `
                -LikelyCause $guidance.Cause `
                -SuggestedFix $guidance.Fix
        } elseif ($status.Stage -eq "TLS Close (uncertain)") {
            $counts.Info++
            Write-Host "     [INFO]    $SniName ($ip) - $($status.Reason)" -ForegroundColor DarkGray
        } elseif ($hostnameConfirmedGood) {
            # Ambiguous per-IP result (no Client Hello attributed, no attempt,
            # inconclusive data, etc.), but this hostname's connectivity is
            # already independently confirmed elsewhere - collapse to one
            # summary line by default instead of one noisy line per IP.
            $counts.Info++
            $collapsedCount++
            if ($Detailed) {
                Write-Host "     [INFO]    $SniName ($ip) - [$($status.Stage)] $($status.Reason) (real connectivity to this hostname already confirmed elsewhere in the capture - not flagged)" -ForegroundColor DarkGray
            }
        } else {
            $counts.Unknown++
            Write-Host "     [UNKNOWN] $SniName ($ip) - [$($status.Stage)] $($status.Reason)" -ForegroundColor Yellow
        }
    }
    if (-not $Detailed -and $collapsedCount -gt 0) {
        Write-Host "     [INFO]    $SniName - $collapsedCount other IP(s) showed inconclusive per-IP data (e.g. no Client Hello attributed to them), but real TLS connectivity to this hostname was independently confirmed elsewhere in this capture. Not flagged - use -Detailed to see them individually." -ForegroundColor DarkGray
    }
    return $counts
}

# Section 10: explicit forward-proxy detection - HTTP CONNECT tunnels and
# 407 Proxy-Authentication-Required responses. Unlike the SSL inspection
# check (sections 6/8), which infers possible inspection indirectly from a
# TLS version downgrade, a CONNECT method is direct, unambiguous proof a
# proxy is in the path: the client is explicitly asking it to tunnel a
# connection somewhere. Runs against the whole capture - not tied to
# -Domain or to the commercial/Gov URL split, since a proxy in the path
# affects all traffic through it.
function Show-ProxyDetectionCheck {
    Show-SummaryHeaderOnce
    Write-Host "`n10) PROXY DETECTION (HTTP CONNECT tunnels & Proxy-Authentication-Required):"
    Write-Host "     Basis: HTTP CONNECT (RFC 7231 s4.3.6) is the client explicitly asking a proxy to" -ForegroundColor DarkGray
    Write-Host "     tunnel a connection to <host>:<port> - this only happens with an explicit forward proxy" -ForegroundColor DarkGray
    Write-Host "     configured/enforced in the path. A 407 response means the proxy demanded authentication." -ForegroundColor DarkGray

    if ($connectRequests.Count -eq 0 -and $all407Frames.Count -eq 0) {
        Write-Host "     [OK] No HTTP CONNECT tunnels or 407 Proxy-Authentication-Required responses observed anywhere in this capture." -ForegroundColor Green
        Write-Host "     No explicit forward proxy detected in-path for this traffic. NOTE: this cannot detect a transparent/" -ForegroundColor DarkGray
        Write-Host "     TAP-mode inspecting proxy that intercepts without a CONNECT handshake - see the SSL inspection check above for that." -ForegroundColor DarkGray
        Write-Host "==============================================================================" -ForegroundColor Cyan
        return
    }

    if ($connectRequests.Count -gt 0) {
        # Anomaly check: does any one client talk to more than one proxy
        # endpoint during this capture? Not necessarily wrong (failover pool),
        # but worth a flag if unexpected.
        foreach ($srcGroup in ($connectRequests | Group-Object Src)) {
            $uniqueProxyEndpoints = $srcGroup.Group | ForEach-Object { "$($_.Dst):$($_.DstPort)" } | Select-Object -Unique
            if ($uniqueProxyEndpoints.Count -gt 1) {
                Write-Host "`n     [NOTE] $($srcGroup.Name) sent CONNECT requests to $($uniqueProxyEndpoints.Count) different proxy endpoints in this capture:" -ForegroundColor Yellow
                Write-Host "         $($uniqueProxyEndpoints -join ', ')" -ForegroundColor Yellow
                Write-Host "         If this isn't an expected failover/load-balanced pool, confirm why the client's proxy target changed mid-session." -ForegroundColor Yellow
            }
        }

        # Group by tunneled destination host so a busy capture doesn't dump
        # one block per frame - one row per destination with a status
        # breakdown; pass -Detailed for the full frame-by-frame listing.
        $annotated = $connectRequests | ForEach-Object {
            $_ | Add-Member -NotePropertyName TargetHost -NotePropertyValue (Get-HostFromConnectTarget -Target $_.Target) -PassThru -Force
        }
        $byTargetHost = $annotated | Group-Object TargetHost

        Write-Host "`n     -- HTTP CONNECT tunnels found: $($connectRequests.Count) across $($byTargetHost.Count) destination(s) --" -ForegroundColor Yellow

        $totalAcceptedNoTls = 0
        $totalAcceptedNoTlsWithData = 0

        foreach ($group in $byTargetHost) {
            $targetHost = $group.Name
            $reqs = $group.Group
            $matchesCommercial = ($MdeRequiredUrlPatterns | Where-Object { $targetHost -like $_ }).Count -gt 0
            $matchesGov = ($GovRequiredUrlPatterns | Where-Object { $targetHost -like $_ }).Count -gt 0

            $acceptedTlsFollowed = 0; $acceptedNoTls = 0; $acceptedNoTlsWithData = 0
            $rejected407 = 0; $otherCode = 0; $noResp = 0
            foreach ($req in $reqs) {
                $resp = if ($httpResponseByStream.ContainsKey($req.Stream)) { $httpResponseByStream[$req.Stream] } else { $null }
                if (-not $resp) { $noResp++; continue }
                if ($resp.Code -eq "200") {
                    $tlsOnStream = ($clientHellos | Where-Object { $_.Stream -eq $req.Stream }).Count -gt 0
                    if ($tlsOnStream) {
                        $acceptedTlsFollowed++
                    } else {
                        $acceptedNoTls++
                        $bytesForStream = if ($streamPayloadBytes.ContainsKey($req.Stream)) { $streamPayloadBytes[$req.Stream] } else { 0 }
                        if ($bytesForStream -gt 2048) { $acceptedNoTlsWithData++ }
                    }
                } elseif ($resp.Code -eq "407") {
                    $rejected407++
                } else {
                    $otherCode++
                }
            }
            $totalAcceptedNoTls += $acceptedNoTls
            $totalAcceptedNoTlsWithData += $acceptedNoTlsWithData

            $proxyEndpoints = ($reqs | ForEach-Object { "$($_.Dst):$($_.DstPort)" } | Select-Object -Unique) -join ", "
            Write-Host ""
            Write-Host "     [PROXY] $targetHost - $($reqs.Count) CONNECT tunnel(s) via $proxyEndpoints" -ForegroundColor Yellow

            if ($matchesCommercial -or $matchesGov) {
                $label = if ($matchesCommercial) { "COMMERCIAL" } else { "US GOV" }
                Write-Host "         -> Matches a documented $label MDE connectivity URL - Defender traffic for this hostname is" -ForegroundColor Red
                Write-Host "            being explicitly proxied - confirms a forward proxy sits in the path for MDE traffic specifically." -ForegroundColor Red
            } else {
                Write-Host "         -> Does not match a documented MDE connectivity URL - unrelated proxied traffic (general" -ForegroundColor DarkGray
                Write-Host "            browsing, Windows Update/telemetry, or another application sharing this capture)." -ForegroundColor DarkGray
            }

            $acceptedTotal = $acceptedTlsFollowed + $acceptedNoTls
            if ($acceptedTotal -gt 0) {
                Write-Host "         -> $acceptedTotal/$($reqs.Count) tunnel(s) ACCEPTED (200): $acceptedTlsFollowed had a TLS Client Hello" -ForegroundColor Green
                Write-Host "            follow, $acceptedNoTls did not." -ForegroundColor $(if ($acceptedNoTls -gt 0) { "Yellow" } else { "Green" })
                if ($acceptedNoTls -gt 0) {
                    if ($acceptedNoTlsWithData -gt 0) {
                        Write-Host "         -> $acceptedNoTlsWithData of those $acceptedNoTls stream(s) still exchanged over 2 KB of data after the" -ForegroundColor Yellow
                        Write-Host "            tunnel - data DID flow, so this looks like a TLS-record parsing/reassembly gap in this" -ForegroundColor Yellow
                        Write-Host "            capture (common in converted ETW/pktmon traces) rather than a genuine client-side abort." -ForegroundColor Yellow
                    } else {
                        Write-Host "         -> None of those stream(s) show meaningful data after the tunnel either - consistent with a" -ForegroundColor Yellow
                        Write-Host "            genuine stall (client accepted the tunnel then never proceeded with TLS)." -ForegroundColor Yellow
                    }
                }
            }
            if ($rejected407 -gt 0) {
                Write-Host "         -> $rejected407/$($reqs.Count) tunnel(s) REJECTED pending authentication (407). Common root cause for the" -ForegroundColor Red
                Write-Host "            Sense service specifically, which runs as SYSTEM and often lacks cached/WinHTTP proxy credentials." -ForegroundColor Red
                if ($matchesCommercial -or $matchesGov) {
                    Add-Finding -Category "Proxy" `
                        -GroupKey "ProxyAuth407|$targetHost" `
                        -Target $targetHost `
                        -Section "Section 10 (Proxy Detection)" `
                        -Issue "$rejected407/$($reqs.Count) CONNECT tunnel(s) to $targetHost were rejected pending proxy authentication (407)." `
                        -LikelyCause "The forward proxy requires authentication before allowing this connection through - a common root cause for the Sense service specifically, since it runs as SYSTEM and typically has no cached/WinHTTP proxy credentials." `
                        -SuggestedFix "Configure a proxy authentication exception/allow-list for MDE URLs, or provide the SYSTEM account (WinHTTP) with proxy credentials/authentication bypass, per Microsoft's Sense proxy configuration guidance."
                }
            }
            if ($otherCode -gt 0) {
                Write-Host "         -> $otherCode/$($reqs.Count) tunnel(s) got another response code - investigate proxy-side policy/ACL." -ForegroundColor Red
                if ($matchesCommercial -or $matchesGov) {
                    Add-Finding -Category "Proxy" `
                        -GroupKey "ProxyOtherCode|$targetHost" `
                        -Target $targetHost `
                        -Section "Section 10 (Proxy Detection)" `
                        -Issue "$otherCode/$($reqs.Count) CONNECT tunnel(s) to $targetHost got an unexpected response code from the proxy (not 200 or 407)." `
                        -LikelyCause "The proxy is actively blocking this destination via policy/ACL rather than simply requiring authentication." `
                        -SuggestedFix "Add an allow-list/exception on the proxy for the documented MDE connectivity URLs, then re-test."
                }
            }
            if ($noResp -gt 0) {
                Write-Host "         -> $noResp/$($reqs.Count) tunnel(s) got no response at all - proxy unreachable/dropping, or outside capture window." -ForegroundColor Yellow
            }
        }

        # Systemic-pattern callout - a near-uniform "accepted but no TLS
        # followed" rate across many distinct, unrelated destinations is
        # atypical for N independent real failures and more often points to
        # a capture-format limitation (see the byte-flow cross-check above).
        if ($connectRequests.Count -ge 5 -and $totalAcceptedNoTls -ge [math]::Ceiling(0.9 * $connectRequests.Count)) {
            $pct = [math]::Round(100 * $totalAcceptedNoTls / $connectRequests.Count)
            Write-Host "`n     [SYSTEMIC PATTERN] $totalAcceptedNoTls/$($connectRequests.Count) CONNECT tunnels ($pct%) show 'accepted, no TLS Client" -ForegroundColor Magenta
            Write-Host "     Hello followed' across $($byTargetHost.Count) different destinations. That uniformity across unrelated hosts is" -ForegroundColor Magenta
            Write-Host "     atypical for that many independent real failures - it more often points to a TLS-record reassembly" -ForegroundColor Magenta
            Write-Host "     gap specific to this capture ($totalAcceptedNoTlsWithData/$totalAcceptedNoTls of them still show over 2 KB of data" -ForegroundColor Magenta
            Write-Host "     flowing after the tunnel, above). Cross-check with a raw packet capture before treating this as a real outage." -ForegroundColor Magenta
        }

        if ($Detailed) {
            Write-Host "`n     -- Per-frame detail (-Detailed) --" -ForegroundColor DarkGray
            foreach ($req in $connectRequests) {
                Write-Host "`n     [PROXY] Frame $($req.Frame) (stream $($req.Stream)): $($req.Src) -> $($req.Dst):$($req.DstPort) requested CONNECT to $($req.Target)" -ForegroundColor Yellow
                $resp = if ($httpResponseByStream.ContainsKey($req.Stream)) { $httpResponseByStream[$req.Stream] } else { $null }
                if (-not $resp) {
                    Write-Host "         -> No response observed." -ForegroundColor Yellow
                } elseif ($resp.Code -eq "200") {
                    $tlsOnStream = ($clientHellos | Where-Object { $_.Stream -eq $req.Stream }).Count -gt 0
                    $bytesForStream = if ($streamPayloadBytes.ContainsKey($req.Stream)) { $streamPayloadBytes[$req.Stream] } else { 0 }
                    if ($tlsOnStream) {
                        Write-Host "         -> Accepted (200); TLS Client Hello followed." -ForegroundColor Green
                    } else {
                        Write-Host "         -> Accepted (200); no TLS Client Hello followed on this stream ($bytesForStream bytes of payload total)." -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "         -> $($resp.Code) $($resp.Phrase)" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "`n     (Run with -Detailed for the full per-frame CONNECT listing.)" -ForegroundColor DarkGray
        }
    }

    # Any 407s NOT already accounted for above (i.e. not the first response on
    # a CONNECT stream) - e.g. plain HTTP requests like CRL/OCSP checks that
    # also got challenged by the proxy for authentication. Capped the same
    # way as the CONNECT detail list, for the same reason.
    $connectStreams = $connectRequests | ForEach-Object { $_.Stream } | Select-Object -Unique
    $otherAuth407s = $all407Frames | Where-Object { $connectStreams -notcontains $_.Stream }
    if ($otherAuth407s.Count -gt 0) {
        Write-Host "`n     -- Additional 407 responses (not tied to a CONNECT tunnel): $($otherAuth407s.Count) --" -ForegroundColor Yellow
        $shown = if ($Detailed) { $otherAuth407s } else { $otherAuth407s | Select-Object -First 10 }
        foreach ($resp407 in $shown) {
            Write-Host "     [PROXY AUTH REQUIRED] Frame $($resp407.Frame) (stream $($resp407.Stream)): $($resp407.Phrase)" -ForegroundColor Red
            Write-Host "         -> A plain HTTP request on this stream (e.g. a CRL/OCSP or Windows Update style check, which" -ForegroundColor Red
            Write-Host "            travel over HTTP rather than HTTPS) was challenged for proxy authentication. If this repeats" -ForegroundColor Red
            Write-Host "            across CRL/OCSP endpoints it can cause certificate validation delays or failures even when" -ForegroundColor Red
            Write-Host "            the main MDE TLS channel itself connects fine." -ForegroundColor Red
        }
        if (-not $Detailed -and $otherAuth407s.Count -gt 10) {
            Write-Host "     ... and $($otherAuth407s.Count - 10) more (use -Detailed to see all)." -ForegroundColor DarkGray
        }
        Add-Finding -Category "Proxy" `
            -GroupKey "ProxyAuth407Other" `
            -Target "$($otherAuth407s.Count) plain-HTTP request(s)" `
            -Section "Section 10 (Proxy Detection)" `
            -Issue "$($otherAuth407s.Count) plain HTTP request(s) (e.g. CRL/OCSP checks) were challenged for proxy authentication (407), separate from any CONNECT tunnel." `
            -LikelyCause "The proxy is requiring authentication on plain-HTTP traffic (such as CRL/OCSP validation checks) the same way it does for CONNECT tunnels." `
            -SuggestedFix "Extend the proxy authentication exception to CRL/OCSP endpoints as well, not just the main MDE HTTPS URLs - a block here can cause certificate validation delays/failures even when the main TLS channel connects fine."
    }

    Write-Host "==============================================================================" -ForegroundColor Cyan
}

# MDE URL matches (full capture) - computed once here so both the SSL
# inspection sweep (-CheckMdeUrlsOnly) and the handshake sweep
# (-CommercialURLHandshakes) can reuse it.
$mdeMatches = $clientHellos | Where-Object {
    $sni = $_.SNI
    if (-not $sni) { return $false }
    foreach ($pattern in $MdeRequiredUrlPatterns) {
        if ($sni -like $pattern) { return $true }
    }
    return $false
}
$mdeDnsMatches = $dnsRecords | Where-Object {
    $qry = $_.QryName
    if (-not $qry) { return $false }
    foreach ($pattern in $MdeRequiredUrlPatterns) {
        if ($qry -like $pattern) { return $true }
    }
    return $false
}

# Same matching, against the US Gov (GCC/GCC High/DoD) URL list, for -govURLHandshakes.
$govMatches = $clientHellos | Where-Object {
    $sni = $_.SNI
    if (-not $sni) { return $false }
    foreach ($pattern in $GovRequiredUrlPatterns) {
        if ($sni -like $pattern) { return $true }
    }
    return $false
}
$govDnsMatches = $dnsRecords | Where-Object {
    $qry = $_.QryName
    if (-not $qry) { return $false }
    foreach ($pattern in $GovRequiredUrlPatterns) {
        if ($qry -like $pattern) { return $true }
    }
    return $false
}

# ===========================================================================
# SECTIONS 1-5: single-domain analysis - only runs if -Domain was given
# ===========================================================================
if ($Domain) {
    Show-SummaryHeaderOnce

    $dnsMatches = $dnsRecords | Where-Object { $_.QryName -like "*$Domain*" }
    $resolvedIps = @()
    $dnsErrors = $dnsMatches | Where-Object { $_.Rcode -and $_.Rcode -ne "0" -and $_.Rcode -ne "" }
    foreach ($rec in $dnsMatches) {
        if ($rec.A) {
            $rec.A -split "[;,]" | ForEach-Object {
                $ip = $_.Trim()
                if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') { $resolvedIps += $ip }
            }
        }
    }

    $chMatches = $clientHellos | Where-Object { $_.SNI -and $_.SNI -like "*$Domain*" }
    $matchedStreams = ($chMatches | ForEach-Object { $_.Stream }) | Select-Object -Unique
    foreach ($rec in $chMatches) {
        if ($rec.Dst -and ($resolvedIps -notcontains $rec.Dst)) { $resolvedIps += $rec.Dst }
    }
    $resolvedIps = $resolvedIps | Select-Object -Unique

    $streamByteCounts = Get-StreamByteCounts -Streams $matchedStreams

    $allDomainIps = ($resolvedIps + ($dnsMatches | ForEach-Object { $_.A -split "[;,]" } | Where-Object { $_ -match '^\d' })) | Select-Object -Unique

    $ipStatus = @{}
    foreach ($ip in $allDomainIps) {
        $ipStatus[$ip] = Get-IpHandshakeStatus -Ip $ip -RelevantClientHellos $chMatches -ByteCounts $streamByteCounts
    }


    if ($chMatches.Count -eq 0 -and $allDomainIps.Count -eq 0) {
        Write-Host "No DNS or TLS traffic found for '$Domain' in this capture." -ForegroundColor Red
        $allSni = $clientHellos | Select-Object -ExpandProperty SNI -Unique | Where-Object { $_ }
        if ($domainLabels.Count -gt 0) {
            $similar = $allSni | Where-Object { $sni = $_; ($domainLabels | Where-Object { $sni -like "*$_*" }).Count -gt 0 }
            if ($similar) {
                Write-Host "`nSimilar domains found in this capture:" -ForegroundColor Yellow
                $similar | Select-Object -First 15 | ForEach-Object { Write-Host "  $_" }
            }
        }
    } else {
        $offeredCipherList = @()
        if ($chMatches.Count -gt 0) {
            $offeredVersion = Resolve-TlsVersionName -Code ($(if ($chMatches[0].SuppVer) { ($chMatches[0].SuppVer -split ",")[0] } else { $chMatches[0].RecVer }))
            $negotiatedVersions = $matchedStreams | ForEach-Object {
                if ($serverHellosByStream.ContainsKey($_)) {
                    $sh = $serverHellosByStream[$_]
                    Resolve-TlsVersionName -Code $(if ($sh.SuppVer) { $sh.SuppVer } else { $sh.RecVer })
                }
            } | Select-Object -Unique
            Write-Host "1) TLS VERSION:"
            Write-Host "     Offered (client):    $offeredVersion"
            Write-Host "     Negotiated (server): $($negotiatedVersions -join ', ')"

            $offeredCipherList = $chMatches[0].Ciphers -split "," | Where-Object { $_ }
            $selectedCiphers = $matchedStreams | ForEach-Object {
                if ($serverHellosByStream.ContainsKey($_)) { $serverHellosByStream[$_].Cipher }
            } | Select-Object -Unique

            Write-Host "`n2) CIPHERS:"
            Write-Host "     Offered by this device ($($offeredCipherList.Count) total):"
            foreach ($cipher in $offeredCipherList) {
                Write-Host "       - $(Resolve-CipherName $cipher)"
            }
            Write-Host "     Selected by server:"
            foreach ($cipher in $selectedCiphers) {
                Write-Host "       -> $(Resolve-CipherName $cipher)" -ForegroundColor Green
            }

            $successCount = 0; $failCount = 0; $unknownCount = 0
            foreach ($stream in $matchedStreams) {
                $hasServerHello = $serverHellosByStream.ContainsKey($stream)
                $hasAlert = $alertsByStream.ContainsKey($stream)
                $bytes = if ($streamByteCounts.ContainsKey($stream)) { $streamByteCounts[$stream].Bytes } else { 0 }
                if ($hasAlert) { $failCount++ }
                elseif (-not $hasServerHello) { $failCount++ }
                elseif ($bytes -gt 2048) { $successCount++ }
                else { $unknownCount++ }
            }
            Write-Host "`n3) HANDSHAKE STATUS: $successCount succeeded, $failCount failed, $unknownCount inconclusive (of $($matchedStreams.Count) sessions)"
            if ($unknownCount -gt 0) {
                Write-Host "   ($unknownCount session(s) completed the TLS handshake but exchanged under 2 KB afterward.)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "1) TLS VERSION: No completed TLS session found (see outbound status below for why)." -ForegroundColor Yellow
            Write-Host "`n2) CIPHERS: N/A - no TLS handshake reached." -ForegroundColor Yellow
            Write-Host "`n3) HANDSHAKE STATUS: 0 succeeded (of $($allDomainIps.Count) IP(s) attempted)" -ForegroundColor Red
        }

        Write-Host "`n4) OUTBOUND CONNECTIVITY:"
        $okCount = ($ipStatus.Values | Where-Object { $_.Ok -eq $true }).Count
        $failIps = $ipStatus.GetEnumerator() | Where-Object { $_.Value.Ok -eq $false }
        $unkIps  = $ipStatus.GetEnumerator() | Where-Object { $_.Value.Ok -eq $null }

        if ($failIps.Count -gt 0) {
            Write-Host "     STATUS: ERRORS DETECTED - $($failIps.Count) of $($allDomainIps.Count) destination IP(s) failed." -ForegroundColor Red
        } elseif ($okCount -eq $allDomainIps.Count) {
            Write-Host "     STATUS: CONFIRMED OK - all $okCount of $($allDomainIps.Count) destination IP(s) succeeded with verified data exchange, no errors." -ForegroundColor Green
        } elseif ($okCount -gt 0) {
            Write-Host "     STATUS: MOSTLY OK - $okCount of $($allDomainIps.Count) confirmed successful, $($unkIps.Count) inconclusive, 0 failed." -ForegroundColor Yellow
        } else {
            Write-Host "     STATUS: NO ERRORS DETECTED, BUT UNCONFIRMED - 0 of $($allDomainIps.Count) destination IP(s) had enough data to positively confirm success." -ForegroundColor Yellow
        }
        foreach ($ip in $ipStatus.Keys | Sort-Object) {
            $s = $ipStatus[$ip]
            if ($s.Ok -eq $true) {
                Write-Host "       [OK]      $ip - [$($s.Stage)] $($s.Reason)" -ForegroundColor Green
            } elseif ($s.Ok -eq $false) {
                Write-Host "       [FAILED]  $ip - FAILED AT: $($s.Stage) - $($s.Reason)" -ForegroundColor Red
                $guidance = Get-ConnectivityIssueGuidance -Stage $s.Stage -Reason $s.Reason
                Add-Finding -Category "Connectivity" `
                    -GroupKey "Connectivity|$Domain|$($s.Stage)" `
                    -Target "$Domain ($ip)" `
                    -Section "Section 3-4 (-Domain handshake status)" `
                    -Issue "$Domain failed at the $($s.Stage) stage - $($s.Reason)" `
                    -LikelyCause $guidance.Cause `
                    -SuggestedFix $guidance.Fix
            } else {
                Write-Host "       [UNKNOWN] $ip - [$($s.Stage)] $($s.Reason)" -ForegroundColor Yellow
            }
        }
        if ($dnsErrors.Count -gt 0) {
            Write-Host "     DNS ERRORS: $($dnsErrors.Count) DNS response(s) returned a non-zero error code for this domain." -ForegroundColor Red
        }

        if ($offeredCipherList.Count -gt 0) {
            Write-Host "`n5) MICROSOFT TLS CIPHER COMPLIANCE (reference baseline - see note):"
            Write-Host "     Source: learn.microsoft.com/power-platform/admin/server-cipher-tls-requirements" -ForegroundColor DarkGray
            Write-Host "     NOTE: documented for Power Platform/Dataverse, not an official MDE-specific spec." -ForegroundColor DarkGray

            $offeredLower = $offeredCipherList | ForEach-Object { $_.Trim().ToLower() }
            $tls13Present = $MsRequiredTls13Ciphers | Where-Object { $offeredLower -contains $_ }
            $tls12Present = $MsRequiredTls12Ciphers | Where-Object { $offeredLower -contains $_ }
            $deprecatedPresent = $MsDeprecatedCiphers | Where-Object { $offeredLower -contains $_ }

            if ($tls13Present.Count -gt 0) {
                Write-Host "     TLS 1.3 requirement: MET ($($tls13Present.Count) of $($MsRequiredTls13Ciphers.Count) required suite(s) present)" -ForegroundColor Green
            } else {
                Write-Host "     TLS 1.3 requirement: NOT MET (0 of $($MsRequiredTls13Ciphers.Count) required suites present)" -ForegroundColor Red
                Add-Finding -Category "Cipher Compliance" `
                    -GroupKey "CipherCompliance|$Domain|TLS13" `
                    -Target $Domain `
                    -Section "Section 5 (Microsoft TLS Cipher Compliance)" `
                    -Issue "$Domain does not offer any of the required TLS 1.3 cipher suites." `
                    -LikelyCause "The device's SChannel cipher suite policy (Group Policy, registry, or an outdated OS build) does not include the required modern suites." `
                    -SuggestedFix "Update the device's TLS cipher suite order via Group Policy/registry to include the required TLS 1.3 suites (see the cited Microsoft reference), then re-test." `
                    -Note "Not every MDE URL requires TLS 1.3 - this baseline is documented for Power Platform/Dataverse, not MDE specifically. Before reporting this to the customer as an issue, confirm via SSL Labs (https://www.ssllabs.com/ssltest/index.html) whether $Domain actually requires/supports TLS 1.3, or whether TLS 1.2 is sufficient for this endpoint."
            }
            foreach ($cipher in $MsRequiredTls13Ciphers) {
                if ($offeredLower -contains $cipher) {
                    Write-Host "       [PRESENT] $(Resolve-CipherName $cipher)" -ForegroundColor Green
                } else {
                    Write-Host "       [MISSING] $(Resolve-CipherName $cipher) - consider adding via GPO/registry" -ForegroundColor Red
                }
            }

            if ($tls12Present.Count -gt 0) {
                Write-Host "     TLS 1.2 requirement: MET ($($tls12Present.Count) of $($MsRequiredTls12Ciphers.Count) required suite(s) present)" -ForegroundColor Green
            } else {
                Write-Host "     TLS 1.2 requirement: NOT MET (0 of $($MsRequiredTls12Ciphers.Count) required suites present)" -ForegroundColor Red
                Add-Finding -Category "Cipher Compliance" `
                    -GroupKey "CipherCompliance|$Domain|TLS12" `
                    -Target $Domain `
                    -Section "Section 5 (Microsoft TLS Cipher Compliance)" `
                    -Issue "$Domain does not offer any of the required TLS 1.2 cipher suites." `
                    -LikelyCause "The device's SChannel cipher suite policy (Group Policy, registry, or an outdated OS build) does not include the required suites." `
                    -SuggestedFix "Update the device's TLS cipher suite order via Group Policy/registry to include the required TLS 1.2 suites (see the cited Microsoft reference), then re-test."
            }
            foreach ($cipher in $MsRequiredTls12Ciphers) {
                if ($offeredLower -contains $cipher) {
                    Write-Host "       [PRESENT] $(Resolve-CipherName $cipher)" -ForegroundColor Green
                } else {
                    Write-Host "       [MISSING] $(Resolve-CipherName $cipher) - consider adding via GPO/registry" -ForegroundColor Yellow
                }
            }

            if ($deprecatedPresent.Count -gt 0) {
                Write-Host "     DEPRECATED suites still offered by this device:" -ForegroundColor Yellow
                $deprecatedPresent | ForEach-Object { Write-Host "       - $(Resolve-CipherName $_)" -ForegroundColor Yellow }
            }
        }
    }
    Write-Host "==============================================================================" -ForegroundColor Cyan

    if ($Detailed) {
        Write-Host "`n--- [1] DNS Resolution (detail) ---" -ForegroundColor Green
        if ($dnsMatches.Count -gt 0) {
            foreach ($rec in $dnsMatches) {
                Write-Host "Frame $($rec.Frame)  $($rec.Src) -> $($rec.Dst)  Query: $($rec.QryName)"
                if ($rec.A) { Write-Host "  -> A record: $($rec.A) (TTL $($rec.Ttl))" -ForegroundColor Green }
                if ($rec.Rcode -and $rec.Rcode -ne "0" -and $rec.Rcode -ne "") { Write-Host "  -> DNS error code: $($rec.Rcode)" -ForegroundColor Red }
            }
        } else {
            Write-Host "No DNS queries found for '$Domain'." -ForegroundColor Yellow
        }

        Write-Host "`n--- [2] TLS Client Hello (detail) ---" -ForegroundColor Green
        foreach ($rec in $chMatches) {
            $versionCode = if ($rec.SuppVer) { ($rec.SuppVer -split ",")[0] } else { $rec.RecVer }
            $cipherList = $rec.Ciphers -split "," | Where-Object { $_ }
            Write-Host ""
            Write-Host "Frame $($rec.Frame)  |  $($rec.Src) -> $($rec.Dst)  |  TCP stream $($rec.Stream)" -ForegroundColor White
            Write-Host "  SNI: $($rec.SNI)"
            Write-Host "  Offered version: $(Resolve-TlsVersionName $versionCode)"
            Write-Host "  Offered ciphers ($($cipherList.Count)): $($cipherList -join ', ')"
        }

        Write-Host "`n--- [3] TLS Server Hello (detail) ---" -ForegroundColor Green
        foreach ($stream in $matchedStreams) {
            if ($serverHellosByStream.ContainsKey($stream)) {
                $sh = $serverHellosByStream[$stream]
                $versionCode = if ($sh.SuppVer) { $sh.SuppVer } else { $sh.RecVer }
                Write-Host ""
                Write-Host "TCP stream $stream  |  $($sh.Src) -> $($sh.Dst)" -ForegroundColor White
                Write-Host "  Negotiated version: $(Resolve-TlsVersionName $versionCode)"
                Write-Host "  Selected cipher: $(Resolve-CipherName $sh.Cipher)"
            } else {
                Write-Host ""
                Write-Host "TCP stream $stream : No Server Hello - server did not respond." -ForegroundColor Yellow
            }
        }

        Write-Host "`n--- [4] Handshake Status (detail, with byte counts) ---" -ForegroundColor Green
        foreach ($stream in $matchedStreams) {
            $hasServerHello = $serverHellosByStream.ContainsKey($stream)
            $hasAlert = $alertsByStream.ContainsKey($stream)
            $hasReset = $rstByStream.ContainsKey($stream)
            $bytes = if ($streamByteCounts.ContainsKey($stream)) { $streamByteCounts[$stream].Bytes } else { 0 }
            $frames = if ($streamByteCounts.ContainsKey($stream)) { $streamByteCounts[$stream].Frames } else { 0 }
            Write-Host ""
            Write-Host "TCP stream $stream :" -ForegroundColor White
            if ($hasAlert) {
                Write-Host "  FAILED - TLS alert: $($alertsByStream[$stream])" -ForegroundColor Red
            } elseif (-not $hasServerHello) {
                Write-Host "  FAILED - No Server Hello observed." -ForegroundColor Red
            } elseif ($bytes -gt 2048) {
                Write-Host "  SUCCESS - $bytes bytes / $frames frames exchanged after handshake." -ForegroundColor Green
            } else {
                Write-Host "  INCONCLUSIVE - Server Hello seen, only $bytes bytes / $frames frames total." -ForegroundColor Yellow
            }
            if ($hasReset) { Write-Host "  NOTE: TCP RST seen ($($rstByStream[$stream]))." -ForegroundColor Yellow }
        }

        Write-Host "`n--- [5] IP Conversation Summary (detail) ---" -ForegroundColor Green
        foreach ($ip in $resolvedIps) {
            Write-Host "`nIP: $ip" -ForegroundColor White
            $convArgs = @("-r", $PcapPath, "-q", "-z", "conv,tcp,ip.addr==$ip")
            $convRaw = & $TsharkPath @convArgs 2>$null
            if ($convRaw) { $convRaw | Write-Output } else { Write-Host "  No TCP conversations found for $ip." -ForegroundColor Yellow }
            if ($ExportCsv) {
                $safeIp = $ip -replace '\.', '_'
                $convRaw | Out-File (Join-Path $ExportCsv "conv_$safeIp.txt") -Encoding UTF8
            }
        }
    } else {
        Write-Host "`n(Run with -Detailed for full per-frame and per-IP output, including exact byte counts.)" -ForegroundColor DarkGray
    }
}

# ===========================================================================
# SECTION 6: Commercial SSL inspection sweep - always runs (independent of
# -Domain), unless the capture has literally no Client Hello traffic at all
# ===========================================================================
if ($clientHellos.Count -gt 0 -and ($Domain -or $CheckMdeUrlsOnly -or $RunCommercialHandshakes)) {
    Show-SslInspectionCheck -SectionNumber "6" -Patterns $MdeRequiredUrlPatterns `
        -SourceUrl "learn.microsoft.com/defender-endpoint/standard-device-connectivity-urls-commercial" `
        -UrlSetLabel "MDE connectivity URLs (commercial)"
} elseif ($CheckMdeUrlsOnly) {
    Write-Host "`nNo TLS Client Hello traffic found anywhere in this capture - nothing to check." -ForegroundColor Red
}

# ===========================================================================
# SECTION 7: Commercial MDE URL handshake status sweep - runs with
# -CommercialURLHandshakes, -AllCommercial, or -All. Independent of -Domain.
# ===========================================================================
if ($RunCommercialHandshakes) {
    Show-SummaryHeaderOnce
    Write-Host "`n7) MDE CONNECTIVITY URL HANDSHAKE STATUS (all commercial URLs):"
    Write-Host "     Source: learn.microsoft.com/defender-endpoint/standard-device-connectivity-urls-commercial" -ForegroundColor DarkGray

    # V15: hostname list = TLS SNIs + DNS query names; IPs include pre-TLS failures from DNS.
    $mdeTargets = @(Get-SweepHostTargets -ClientHelloMatches $mdeMatches -DnsMatches $mdeDnsMatches)
    $mdeTargetsToCheck = @($mdeTargets | Where-Object { $_.Ips.Count -gt 0 })

    if ($mdeTargetsToCheck.Count -eq 0) {
        Write-Host "     No TLS traffic to any documented MDE connectivity URL was found in this capture." -ForegroundColor Yellow
        $dnsOnlyNames = @($mdeTargets | Where-Object { -not $_.HasTls } | ForEach-Object { $_.Name })
        if ($dnsOnlyNames.Count -gt 0) {
            Write-Host "`n     DNS resolved but no TLS traffic observed for:" -ForegroundColor Yellow
            $dnsOnlyNames | ForEach-Object { Write-Host "       - $_" -ForegroundColor Yellow }
        }
    } else {
        $totalOk = 0; $totalFailed = 0; $totalUnknown = 0; $totalInfo = 0

        foreach ($t in $mdeTargetsToCheck) {
            $streamsForSni = @($t.ClientHellos | ForEach-Object { $_.Stream } | Select-Object -Unique)
            $byteCountsForSni = Get-StreamByteCounts -Streams $streamsForSni

            $counts = Show-HandshakeStatusForSni -SniName $t.Name -IpsForSni $t.Ips -GroupClientHellos $t.ClientHellos -ByteCountsForSni $byteCountsForSni -SectionNumber "7"
            if ($t.AddedFromDns -gt 0) {
                Write-Host "               ($($t.AddedFromDns) IP(s) above came from DNS answers - the device tried them but never reached TLS)" -ForegroundColor DarkGray
            }
            $totalOk += $counts.Ok
            $totalFailed += $counts.Failed
            $totalUnknown += $counts.Unknown
            $totalInfo += $counts.Info
        }

        # Hostnames resolved via DNS with no TLS AND no failed attempt - nothing
        # to check at the IP level, but still worth listing.
        $dnsOnlyNoTls = @($mdeTargets | Where-Object { -not $_.HasTls -and $_.Ips.Count -eq 0 } | ForEach-Object { $_.Name })
        if ($dnsOnlyNoTls.Count -gt 0) {
            Write-Host "`n     DNS resolved but no TLS traffic observed for:" -ForegroundColor Yellow
            $dnsOnlyNoTls | ForEach-Object { Write-Host "       - $_" -ForegroundColor Yellow }
        }

        Write-Host "`n     TOTAL: $totalOk OK, $totalFailed FAILED, $totalUnknown UNKNOWN, $totalInfo INFO (across $($mdeTargetsToCheck.Count) MDE URL(s), $($totalOk + $totalFailed + $totalUnknown + $totalInfo) IP(s) checked)"
    }
    Write-Host "==============================================================================" -ForegroundColor Cyan
}

# ===========================================================================
# ===========================================================================
# SECTION 8: US Gov SSL inspection sweep - runs with -govURLHandshakes,
# -AllGov, or -All. Same downgrade/missing-certificate check as section 6,
# against the US Gov (GCC/GCC High/DoD) URL list instead of commercial.
# ===========================================================================
if ($RunGovHandshakes -and $clientHellos.Count -gt 0) {
    Show-SslInspectionCheck -SectionNumber "8" -Patterns $GovRequiredUrlPatterns `
        -SourceUrl "learn.microsoft.com/defender-endpoint/standard-device-connectivity-urls-gov" `
        -UrlSetLabel "MDE connectivity URLs (US Gov: GCC / GCC High / DoD)"
}

# ===========================================================================
# SECTION 9: US Gov MDE URL handshake status sweep - runs with
# -govURLHandshakes, -AllGov, or -All. Independent of -Domain and of the
# commercial sweep.
# ===========================================================================
if ($RunGovHandshakes) {
    Show-SummaryHeaderOnce
    Write-Host "`n9) MDE CONNECTIVITY URL HANDSHAKE STATUS (US Gov: GCC / GCC High / DoD):"
    Write-Host "     Source: learn.microsoft.com/defender-endpoint/standard-device-connectivity-urls-gov" -ForegroundColor DarkGray

    # V15: hostname list = TLS SNIs + DNS query names; IPs include pre-TLS failures from DNS.
    $govTargets = @(Get-SweepHostTargets -ClientHelloMatches $govMatches -DnsMatches $govDnsMatches)
    $govTargetsToCheck = @($govTargets | Where-Object { $_.Ips.Count -gt 0 })

    if ($govTargetsToCheck.Count -eq 0) {
        Write-Host "     No TLS traffic to any documented US Gov MDE connectivity URL was found in this capture." -ForegroundColor Yellow
        $dnsOnlyNames = @($govTargets | Where-Object { -not $_.HasTls } | ForEach-Object { $_.Name })
        if ($dnsOnlyNames.Count -gt 0) {
            Write-Host "`n     DNS resolved but no TLS traffic observed for:" -ForegroundColor Yellow
            $dnsOnlyNames | ForEach-Object { Write-Host "       - $_" -ForegroundColor Yellow }
        }
    } else {
        $totalOk = 0; $totalFailed = 0; $totalUnknown = 0; $totalInfo = 0

        foreach ($t in $govTargetsToCheck) {
            $streamsForSni = @($t.ClientHellos | ForEach-Object { $_.Stream } | Select-Object -Unique)
            $byteCountsForSni = Get-StreamByteCounts -Streams $streamsForSni

            $counts = Show-HandshakeStatusForSni -SniName $t.Name -IpsForSni $t.Ips -GroupClientHellos $t.ClientHellos -ByteCountsForSni $byteCountsForSni -SectionNumber "9"
            if ($t.AddedFromDns -gt 0) {
                Write-Host "               ($($t.AddedFromDns) IP(s) above came from DNS answers - the device tried them but never reached TLS)" -ForegroundColor DarkGray
            }
            $totalOk += $counts.Ok
            $totalFailed += $counts.Failed
            $totalUnknown += $counts.Unknown
            $totalInfo += $counts.Info
        }

        # Hostnames resolved via DNS with no TLS AND no failed attempt - nothing
        # to check at the IP level, but still worth listing.
        $dnsOnlyNoTls = @($govTargets | Where-Object { -not $_.HasTls -and $_.Ips.Count -eq 0 } | ForEach-Object { $_.Name })
        if ($dnsOnlyNoTls.Count -gt 0) {
            Write-Host "`n     DNS resolved but no TLS traffic observed for:" -ForegroundColor Yellow
            $dnsOnlyNoTls | ForEach-Object { Write-Host "       - $_" -ForegroundColor Yellow }
        }

        Write-Host "`n     TOTAL: $totalOk OK, $totalFailed FAILED, $totalUnknown UNKNOWN, $totalInfo INFO (across $($govTargetsToCheck.Count) Gov URL(s), $($totalOk + $totalFailed + $totalUnknown + $totalInfo) IP(s) checked)"
    }
    Write-Host "==============================================================================" -ForegroundColor Cyan
}


# ===========================================================================
# SECTION 10: Proxy detection (HTTP CONNECT tunnels + 407 responses) - runs
# unconditionally on every invocation, since a proxy in the path affects all
# traffic through it, not just one URL set. (Param validation above already
# guarantees at least one analysis mode was selected to get this far.)
# ===========================================================================
Show-ProxyDetectionCheck

# ===========================================================================
# SECTION 11: SUMMARY & RECOMMENDED ACTIONS - runs
# unconditionally, after every other section. Pulls together only the REAL,
# actionable issues found above (full connectivity failures, TLS/SSL
# inspection signals, missing required cipher suites, proxy-auth blocks)
# into a short, customer-facing summary an engineer can adapt directly into
# a ticket update. Nothing here is re-derived - each finding was captured
# via Add-Finding at the exact point in the sections above where that
# determination was already made, so this section can never disagree with
# the detailed sections above it. Clean/benign results are never listed.
# ===========================================================================
Show-SummaryHeaderOnce
Write-Host "`n11) SUMMARY & RECOMMENDED ACTIONS:"

if ($script:Findings.Count -eq 0) {
    Write-Host "     No actionable issues found. MDE/Defender AV connectivity, TLS negotiation, cipher" -ForegroundColor Green
    Write-Host "     compliance, and proxy authentication all looked healthy across everything checked" -ForegroundColor Green
    Write-Host "     in this capture." -ForegroundColor Green
} else {
    Write-Host "     $($script:Findings.Count) issue(s) found that likely need action, grouped below by area:" -ForegroundColor Yellow

    $categoryOrder = @("Connectivity", "TLS / SSL Inspection", "Cipher Compliance", "Proxy")
    $extraCategories = @($script:Findings | Select-Object -ExpandProperty Category -Unique | Where-Object { $categoryOrder -notcontains $_ })
    $orderedCategories = $categoryOrder + $extraCategories

    $findingNum = 0
    foreach ($cat in $orderedCategories) {
        $inCat = @($script:Findings | Where-Object { $_.Category -eq $cat })
        if ($inCat.Count -eq 0) { continue }
        Write-Host "`n     -- $cat --" -ForegroundColor Cyan
        foreach ($f in $inCat) {
            $findingNum++
            $targetList = $f.Targets -join ", "
            Write-Host ""
            Write-Host "     [$findingNum] $targetList" -ForegroundColor White
            Write-Host "         ISSUE:          $($f.Issue)" -ForegroundColor Red
            Write-Host "         LIKELY CAUSE:   $($f.LikelyCause)" -ForegroundColor Yellow
            Write-Host "         SUGGESTED FIX:  $($f.SuggestedFix)" -ForegroundColor Green
            if ($f.Note) {
                Write-Host "         NOTE:           $($f.Note)" -ForegroundColor Cyan
            }
            Write-Host "         EVIDENCE:       $($f.Section) above" -ForegroundColor DarkGray
        }
    }
}
Write-Host "`n==============================================================================" -ForegroundColor Cyan

# ===========================================================================
# SECTION 12: COPILOT ACTION PLAN - runs on every mode unless -Copilot Off.
# Sends ONLY the Section 11 findings (Microsoft URLs + issue/cause/fix text)
# and the switches used - no IPs, no capture file name - and asks Copilot
# for a customer action plan.
#   Auto (default): GitHub Copilot CLI if installed, otherwise Copilot Chat.
#   CLI : the answer prints here and is saved next to the PCAP.
#   Chat: the prompt is copied to the clipboard and M365 Copilot Chat opens.
# ===========================================================================
if ($Copilot -ne 'Off') {
    Write-Host "`n12) COPILOT ACTION PLAN:" -ForegroundColor Cyan

    $switchesUsed = @($PSBoundParameters.GetEnumerator() |
        Where-Object { $_.Key -notin @('PcapPath', 'TsharkPath', 'ExportCsv', 'Copilot') } |
        ForEach-Object {
            if ($_.Value -is [System.Management.Automation.SwitchParameter]) { "-$($_.Key)" } else { "-$($_.Key) $($_.Value)" }
        }) -join ' '

    $cloudHint = if ($All) { 'Not specified - both the commercial and US Gov URL sets were checked' }
                 elseif ($AllGov -or $govURLHandshakes) { 'US Gov (GCC / GCC High / DoD)' }
                 elseif ($AllCommercial -or $CommercialURLHandshakes -or $CheckMdeUrlsOnly) { 'Commercial' }
                 else { 'Not specified - infer it from the URLs' }

    # Same order and numbering as Section 11, so "[2]" means the same finding in both places
    $findingBlocks = @()
    if ($script:Findings.Count -gt 0) {
        $num = 0
        foreach ($cat in $orderedCategories) {
            foreach ($f in @($script:Findings | Where-Object { $_.Category -eq $cat })) {
                $num++
                $block = "[$num] $($f.Category): $($f.Targets -join ', ')`n    Issue: $($f.Issue)`n    Likely cause: $($f.LikelyCause)`n    Suggested fix: $($f.SuggestedFix)"
                if ($f.Note) { $block += "`n    Note: $($f.Note)" }
                $findingBlocks += "$block`n    Evidence: $($f.Section)"
            }
        }
        $findingText = $findingBlocks -join "`n`n"
    } else {
        $findingText = 'None. The analyzer found no actionable connectivity, TLS/SSL inspection, cipher, or proxy-authentication issues.'
    }

    $copilotPrompt = @"
You are a senior Microsoft Defender for Endpoint (MDE) support engineer. Below is the SUMMARY & RECOMMENDED ACTIONS section from a packet-capture analysis of a customer's device. Base your answer only on these findings - do not invent URLs, settings, or evidence - and do not run tools or commands. Write plain text only: no markdown, no bold, no tables.

Switches used: $switchesUsed
Customer cloud: $cloudHint
Actionable findings: $($script:Findings.Count)

FINDINGS (analyzer Section 11):
$findingText

Reply with only the section below, starting with its marker line written exactly as shown. This is for the support engineer only - do not write a customer email, greeting, or any customer-facing message.

===ENGINEER===
Short and simple, 10 lines or fewer:
Problem: one sentence.
Fix: 1-3 numbered steps in plain words (for example "Add an SSL inspection bypass for the listed MDE URLs on the proxy" or "Enable the missing TLS 1.2 cipher suites").
Who changes it: the customer team that owns it (network/proxy/firewall team or endpoint team).
Confirm: 1-2 checks that prove it's fixed.
If still broken: what to collect next.

If only -Domain was used, mention that only that URL was checked. If there are no findings, say the capture looks healthy for MDE connectivity and give the next things to check or collect.
"@

    $sentToCli = $false
    if ($Copilot -eq 'CLI' -and -not $script:CopilotCliPath) {
        Write-Host "     Copilot CLI isn't ready (see COPILOT PRE-CHECK at the top of this run). Using Copilot Chat instead." -ForegroundColor Yellow
    }
    if ($script:CopilotCliPath -and $Copilot -in @('Auto', 'CLI')) {
        # Windows PowerShell 5.1 mangles double quotes in native arguments, and npm's copilot.cmd shim can't take newlines
        $cliArg = $copilotPrompt -replace '"', "'"
        if ($script:CopilotCliPath -notlike '*.exe') { $cliArg = ($cliArg -replace '\r?\n', ' ') -replace '[%^&|<>]', ' ' }
        $pcapFull = (Resolve-Path -LiteralPath $PcapPath).Path
        $planFile = Join-Path (Split-Path -Parent $pcapFull) ('{0}_CopilotPlan_{1:yyyyMMdd-HHmm}.md' -f [IO.Path]::GetFileNameWithoutExtension($pcapFull), (Get-Date))

        Write-Host "     Asking Copilot for the recommended fix (15-60s) " -ForegroundColor Cyan -NoNewline
        $job = Start-Job -ScriptBlock {
            param($exe, $prompt, $dir)
            [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
            Set-Location -LiteralPath $dir
            $text = & $exe -s -p $prompt 2>&1 | Out-String
            [PSCustomObject]@{ Text = $text; Code = $LASTEXITCODE }
        } -ArgumentList $script:CopilotCliPath, $cliArg, $PSScriptRoot
        $waited = 0
        while ($job.State -eq 'Running' -and $waited -lt 240) { Write-Host '.' -NoNewline -ForegroundColor Cyan; Start-Sleep -Seconds 2; $waited += 2 }
        Write-Host ''
        $result = $null
        if ($job.State -eq 'Running') { Stop-Job $job } else { $result = Receive-Job $job }
        Remove-Job $job -Force

        if ($result -and $result.Code -eq 0 -and "$($result.Text)".Trim()) {
            $sentToCli = $true
            $lines = @("$($result.Text)" -split "`r?`n" | ForEach-Object { ($_ -replace '\*\*', '' -replace '^\s*#+\s*', '').TrimEnd() })
            $engAt = -1
            for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^[\s=*#_-]*ENGINEER[\s=*#_:-]*$') { $engAt = $i; break } }
            $start = $engAt + 1
            # Engineer-facing only: stop at anything that looks like a customer message
            $stopAt = $lines.Count
            for ($i = $start; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^[\s=*#_-]*(CUSTOMER|EMAIL)\b' -or $lines[$i] -match '^\s*Subject\s*:' -or $lines[$i] -match '^\s*(Hi|Hello|Dear)\b.*,\s*$') { $stopAt = $i; break }
            }
            # Drop blank lines at the start/end of the block
            $trimBlock = { param($arr) $arr = @($arr); $f = 0; while ($f -lt $arr.Count -and -not "$($arr[$f])".Trim()) { $f++ }
                           $l = $arr.Count - 1; while ($l -ge $f -and -not "$($arr[$l])".Trim()) { $l-- }; if ($f -le $l) { $arr[$f..$l] } else { @() } }
            $engLines = if ($stopAt -gt $start) { @(& $trimBlock $lines[$start..($stopAt - 1)]) } else { @() }

            Write-Host "`n     ---- WHAT TO DO: Copilot's recommended fix ----" -ForegroundColor Green
            foreach ($line in $engLines) { Write-Host "     $line" -ForegroundColor Green }

            $md = @("# Copilot recommended fix - $([IO.Path]::GetFileName($pcapFull)) - $(Get-Date -Format 'yyyy-MM-dd HH:mm')", '') + $engLines
            try { Set-Content -LiteralPath $planFile -Value $md -Encoding UTF8 -ErrorAction Stop; Write-Host "`n     Saved: $planFile" -ForegroundColor DarkGray } catch { }
        } else {
            $why = if (-not $result) { 'no reply within 4 minutes' } else { "exit code $($result.Code)" }
            Write-Host "     Copilot CLI didn't answer ($why) - using Copilot Chat instead." -ForegroundColor Yellow
            if ($result -and "$($result.Text)".Trim()) { ("$($result.Text)".Trim() -split "`r?`n" | Select-Object -First 5) | ForEach-Object { Write-Host "         $_" -ForegroundColor DarkGray } }
            Write-Host "     (If it says you're signed out, run:  copilot login)" -ForegroundColor DarkGray
            Remove-Item -LiteralPath $script:CopilotOkMarker -ErrorAction SilentlyContinue   # re-test on the next run
        }
    }
    if (-not $sentToCli) {
        $chatUrl = 'https://m365.cloud.microsoft/chat'
        $copied = $false
        try { $copilotPrompt | Set-Clipboard -ErrorAction Stop; $copied = $true } catch { }
        if (-not $copied) {
            $pcapFull = (Resolve-Path -LiteralPath $PcapPath).Path
            $promptFile = Join-Path (Split-Path -Parent $pcapFull) ('{0}_CopilotPrompt.txt' -f [IO.Path]::GetFileNameWithoutExtension($pcapFull))
            try { Set-Content -LiteralPath $promptFile -Value $copilotPrompt -Encoding UTF8 -ErrorAction Stop } catch { $promptFile = $null }
        }
        # An elevated (Run as administrator) window often can't launch the browser directly - explorer.exe hands it to the normal desktop
        $opened = $false
        try { Start-Process $chatUrl -ErrorAction Stop; $opened = $true } catch {
            try { Start-Process explorer.exe -ArgumentList $chatUrl -ErrorAction Stop; $opened = $true } catch { }
        }

        Write-Host "     Copilot has NOT answered yet - paste the prompt into Copilot Chat to get the customer action plan." -ForegroundColor Yellow
        if ($copied)         { Write-Host "     [x] Prompt copied to your clipboard." -ForegroundColor Green }
        elseif ($promptFile) { Write-Host "     [ ] Clipboard unavailable - prompt saved to: $promptFile (open it, Ctrl+A, Ctrl+C)." -ForegroundColor Yellow }
        else                 { Write-Host "     [ ] Clipboard unavailable - prompt below:`n`n$copilotPrompt`n" -ForegroundColor Yellow }
        if ($opened) { Write-Host "     [x] Microsoft 365 Copilot Chat is opening in your browser." -ForegroundColor Green }
        else         { Write-Host "     [ ] Couldn't open the browser - go to $chatUrl" -ForegroundColor Yellow }
        Write-Host "     Then: click the chat box, Ctrl+V, Enter." -ForegroundColor Green
        Write-Host "     Tip: fix the [ ] items under COPILOT PRE-CHECK at the top and the plan prints here automatically." -ForegroundColor DarkGray
    }
    Write-Host "`n==============================================================================" -ForegroundColor Cyan
}

Write-Host "`nDISCLAIMER:" -ForegroundColor Yellow
Write-Host " Results are generated automatically from packet-capture analysis and AI-assisted" -ForegroundColor Gray
Write-Host " recommendations. Validate findings in Wireshark before acting on them or sharing" -ForegroundColor Gray
Write-Host " them with customers, particularly where a result appears inconsistent or unexpected." -ForegroundColor Gray
Write-Host "==============================================================================" -ForegroundColor Cyan

Write-Host "`nDone." -ForegroundColor Cyan
