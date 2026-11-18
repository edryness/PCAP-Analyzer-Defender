# PCAP Analyzer for MDE - User Reference

*[Home](../README.md) | [Setup Guide](setup-guide.md) | [User Reference](user-reference.md) | [Quick Reference](quick-reference.md) | [Troubleshooting & FAQ](troubleshooting-faq.md)*

What each section checks, how to read the output, and what the common findings mean.

---

## What it checks

| Section | Name | Runs with | What it tells you |
|---|---|---|---|
| 1 | TLS Version | `-Domain` | TLS version offered vs. negotiated |
| 2 | Ciphers | `-Domain` | Cipher suites offered vs. selected |
| 3 | Handshake Status | `-Domain` | Each session broken into SYN, SYN-ACK, ACK, and TLS stages |
| 4 | Outbound Connectivity | `-Domain` | Per-IP results with byte counts |
| 5 | Microsoft TLS Cipher Compliance | `-Domain` | Required TLS 1.2 / 1.3 suites present or missing |
| 6 | SSL Inspection Check (commercial) | `-All`, `-Domain` | Re-signed certificates or downgraded TLS on commercial MDE URLs |
| 7 | Handshake Status sweep (commercial) | `-All` | Pass / fail / failing stage for every commercial MDE URL |
| 8 | SSL Inspection Check (US Gov) | `-All` | The same inspection check for GCC / GCC High / DoD URLs |
| 9 | Handshake Status sweep (US Gov) | `-All` | Pass / fail / failing stage for every US Gov URL |
| 10 | Proxy Detection | Always | HTTP CONNECT tunnels, what the proxy answered (407, 504, 403...), and direct port-80 connections that got no answer |
| 11 | Summary & Recommended Actions | Always | Actionable issues only, with cause, fix, and evidence |
| 12 | Copilot Action Plan | Always (unless Copilot is Off) | Engineer-facing recommended fix |

**Switches in one line each:**
- **-All** - Check everything MDE needs, commercial and US Gov. Start here.
- **-Domain `<FQDN>`** - Deep dive on one hostname (hostname only, no `https://`). Use it after -All flags a URL.
- **-Detailed** - With -Domain, adds every Client Hello, every Server Hello, and full per-IP conversation stats.

Full details are in the [Setup and User Guide](setup-guide.md#the-switches).

---

## Reading the results

### Status tags

| Tag | Meaning |
|---|---|
| `[OK]` | The check passed. |
| `[FAILED]` | A connection failed. The line names the stage where it stopped. |
| `[WARNING]` | A suspicious result, such as a deprecated TLS version negotiated, which suggests possible SSL inspection. |
| `[UNKNOWN]` | Inconclusive. For example, no connection attempt to that IP, or a session closed in a way that can't be read. Not counted as a failure. |
| `[INFO]` | Informational only. |
| `[PROXY]` | An explicit proxy was seen (HTTP CONNECT tunnel). |
| `[PROXY AUTH REQUIRED]` | The proxy answered `407 Proxy Authentication Required`. |
| `[PRESENT]` / `[MISSING]` | A required cipher suite was or wasn't offered by the device (Section 5). |
| `[SYSTEMIC PATTERN]` | The same proxy behavior repeats across most CONNECT tunnels, so it points to a proxy-wide cause rather than one URL. |
| `[NOTE]` | Context worth reading. For example, the device used more than one proxy endpoint. |

### Where a failing connection stops

| Stage | What it usually means | Where to look |
|---|---|---|
| Network (ICMP error) | Something actively rejected the connection | Firewall / routing ACLs for an explicit deny |
| SYN-ACK | No response at all to the connection attempt | Outbound TCP 443 blocked or filtered; stale DNS |
| SYN-ACK (port 80) | A plain-HTTP request (certificate revocation or issuer download) never got an answer | Outbound TCP 80 to the Microsoft host; a component bypassing the proxy |
| ACK | TCP handshake didn't complete | Asymmetric routing, or a device dropping mid-handshake |
| TLS Server Hello | Client Hello sent, server never answered | SNI-based filtering, or a proxy/firewall dropping TLS to that hostname |
| TLS Alert | TLS was actively rejected | SSL inspection, an untrusted CA on the device, or URL/SNI filtering. If the device itself refused a genuine Microsoft certificate chain, the finding is Certificate trust instead (see below) |

---

## Common findings and fixes

| Finding | Typical cause | Typical fix |
|---|---|---|
| **Possible SSL inspection** on an MDE URL | A proxy, firewall, or security tool is re-signing the traffic, or forcing an older TLS version | Add an SSL-inspection bypass for the MDE URLs on that device; if one exists, confirm it's actually applied |
| **CONNECT rejected with 407** | The proxy requires authentication; Sense runs as SYSTEM and has no proxy credentials | Add a proxy-authentication exception for MDE URLs, or configure SYSTEM/WinHTTP proxy access |
| **407 on plain-HTTP (CRL/OCSP)** | Certificate-validation requests are challenged too | Extend the exception to CRL/OCSP endpoints |
| **CONNECT answered 403 (or another 4xx)** | The proxy is blocking the destination by policy | Allow-list the MDE URLs on the proxy |
| **CONNECT answered 504 Unknown Host** | The proxy could not resolve the name: its own DNS, not a block. Names that exist only in another cloud (for example `mdav.usm` or `mdav.usd`) normally fail this way and are harmless unless the tenant is in that cloud | Fix the proxy's DNS for the name only if the tenant needs it |
| **CONNECT answered 5xx or 3xx** | A gateway error, or a redirect to a sign-in or block page | Check the proxy's upstream path and its authentication or block-page rules for the MDE URLs |
| **Direct connection (port 80) gets no answer** | A plain-HTTP request to a Microsoft host (certificate revocation, issuer download) is dropped, often because it bypasses the proxy that carries the other MDE traffic | Allow outbound TCP 80 to the Microsoft certificate endpoints, or make the request use the proxy (WinHTTP system proxy) |
| **Certificate trust: the device rejected Microsoft's genuine certificate chain** | The device sent a fatal TLS alert (`bad_certificate`, `certificate_unknown`, `unknown_ca`) after a normal Microsoft chain, so Windows cannot build trust: Cryptographic Services (CryptSvc) missing permissions on the `AuthRoot` registry keys, `ctldl.windowsupdate.com` blocked, the "Turn off Automatic Root Certificates Update" policy, or an unpatched Windows. TLS 1.2 captures only | Run the read-only checks listed in the finding and compare the `AuthRoot` and `AutoUpdate` key permissions with a working server of the same OS. Do not add an SSL-inspection exclusion: the certificate is genuine |
| **Connection failed at a stage** | See the stage table above | See the stage table above |
| **Missing required TLS 1.2 / 1.3 suites** | Device cipher-suite policy (GPO, registry, or an old OS build) | Update the cipher suite order, then re-test |

> **TLS 1.3 caveat:** The cipher-compliance baseline comes from Microsoft's Power Platform documentation, not MDE-specific guidance. Not every MDE URL requires TLS 1.3. Before reporting a TLS 1.3 gap to a customer, confirm with [SSL Labs](https://www.ssllabs.com/ssltest/) whether that URL actually needs it.

---

## Copilot and data handling

- **The capture stays on your machine.** tshark reads it locally.
- **Only the Section 11 findings text is sent to Copilot:** the Microsoft URLs involved, the issue / cause / fix text, and which switches were used. No IP addresses and no capture file name.
- **Copilot's output is engineer-facing only.** It does not draft customer emails. Anything customer-facing that Copilot adds anyway is cut before display.
- **Two routes:**
  - **Copilot CLI** (GitHub Copilot) - the fix prints in the app and is saved as `<capture>_CopilotPlan_<date-time>.md` next to the capture.
  - **Copilot Chat** (Microsoft 365) - the prompt is copied to your clipboard and Copilot Chat opens for you to paste.
- **Off** - Set **Copilot: Off** to keep the entire run local.

Follow your organization's data-handling requirements for customer data before using Copilot, particularly for government-cloud (GCC / GCC High / DoD) cases.

---

## Limitations

- It analyzes only what's in the capture. If the failing traffic wasn't captured, it can't be analyzed.
- It can't decrypt TLS. Findings come from handshake metadata, certificates, and TCP behavior.
- Findings are strong indicators, not proof. Always confirm in Wireshark.
- Copilot recommendations are AI-generated and must be reviewed.
- Unsigned builds of the app may be flagged by antivirus/EDR or SmartScreen. Download the latest build from the [Releases](../../../releases) page.

---

---

## Disclaimer

Results are generated automatically from packet-capture analysis and AI-assisted recommendations. Validate findings in Wireshark before acting on them or sharing them with customers, particularly where a result appears inconsistent or unexpected.
