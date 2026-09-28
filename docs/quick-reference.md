# PCAP Analyzer for MDE - Quick Reference

*[Home](../README.md) | [Setup Guide](setup-guide.md) | [User Reference](user-reference.md) | [Quick Reference](quick-reference.md) | [Troubleshooting & FAQ](troubleshooting-faq.md)*

## Workflow

1. **-All** on every new capture.
2. **-Domain `<hostname>`** for each URL marked `[FAILED]` or `[WARNING]`.
3. Add **-Detailed** when you need frame-level evidence.
4. Read **Section 11** (actionable issues) and **Section 12** (Copilot's recommended fix).
5. **Validate in Wireshark** before sharing anything with the customer.

## Switches

| Switch | Needs | Runs | Use when |
|---|---|---|---|
| `-All` | Nothing | Sections 6-9 (commercial + US Gov SSL inspection and handshake sweeps) + 10-12 | First pass on any capture |
| `-Domain <FQDN>` | One hostname, e.g. `winatp-gw-eus3.microsoft.com` | Sections 1-6 for that host + 10-12 | A URL was flagged by -All |
| `-Detailed` | `-Domain` | Every Client Hello, Server Hello, and per-IP conversation for that host | The -Domain summary isn't enough |

`-All` and `-Domain` can be combined in one run.

## Status tags

`[OK]` passed | `[FAILED]` connection failed (stage shown) | `[WARNING]` suspicious, possible SSL inspection | `[UNKNOWN]` inconclusive | `[PROXY]` explicit proxy seen | `[PROXY AUTH REQUIRED]` 407 from the proxy | `[PRESENT]` / `[MISSING]` required cipher suite | `[SYSTEMIC PATTERN]` proxy-wide behavior

## Failure stages

| Stage | Look at |
|---|---|
| Network (ICMP) | Firewall / routing explicit deny |
| SYN-ACK | Outbound TCP 443 blocked or filtered |
| ACK | Asymmetric routing / mid-handshake drop |
| TLS Server Hello | SNI filtering / proxy dropping TLS |
| TLS Alert | SSL inspection / untrusted CA / URL filtering |

## Copilot setting

| Setting | Result |
|---|---|
| **Auto** | Copilot CLI answers in the app if it's ready, otherwise Copilot Chat |
| **Chat** | Prompt copied to the clipboard; Microsoft 365 Copilot Chat opens |
| **Off** | No Copilot; everything stays local |

## Command line

```powershell
$analyzer = "<folder>\PCAP-Analyzer.ps1"
$cap      = "<folder>\ConvertedTrace.pcapng"
$ts       = "C:\Program Files\Wireshark\tshark.exe"

& $analyzer -PcapPath $cap -All -TsharkPath $ts
& $analyzer -PcapPath $cap -Domain winatp-gw-eus3.microsoft.com -TsharkPath $ts
& $analyzer -PcapPath $cap -Domain winatp-gw-eus3.microsoft.com -Detailed -TsharkPath $ts
& $analyzer -PcapPath $cap -All -TsharkPath $ts -Copilot Off
```

Other switches: `-AllCommercial` (commercial sweep only), `-AllGov` (US Gov sweep only), `-CheckMdeUrlsOnly` (fastest: SSL inspection check only), `-ExportCsv <folder>` (raw extracts as CSV).

Run PowerShell **as administrator** if the capture came from MDE Client Analyzer.

## Output files

- `<capture>_CopilotPlan_<date-time>.md` - Copilot's recommended fix, saved next to the capture
- **Save output...** in the app - `.rtf` keeps the colors, `.txt` is plain text

---

*Results are generated automatically from packet-capture analysis and AI-assisted recommendations. Validate findings in Wireshark before acting on them or sharing them with customers, particularly where a result appears inconsistent or unexpected.*
