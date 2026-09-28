# Changelog

## V16.5.2
- Copilot output is engineer-facing only; customer-email drafting removed. Customer-facing text Copilot adds anyway is cut before display and saving.

## V16.5.1
- Stops with tshark's own error when a capture can't be read (access denied, not a capture file, empty), instead of reporting a clean result.
- Credit header at the start of every run and a disclaimer at the end.

## Copilot hand-off and Windows app
- Section 12: sends the Section 11 findings to Copilot (GitHub Copilot CLI or Microsoft 365 Copilot Chat) for a recommended fix.
- Copilot pre-check: finds the CLI, checks sign-in, and tests it on first run.
- Windows app (`PCAP-Analyzer.exe`) with -All / -Domain / -Detailed options, live colored output, and Copilot install/sign-in buttons.

## V17
- Added US Gov streamlined-connectivity hostnames (`endpoint.security.microsoft.us`, `*.endpoint.security.microsoft.us`).

## V16
- Added US Gov Defender portal and Entra sign-in hostnames (`security.microsoft.us`, `login.microsoftonline.us`, `securitycenter.microsoft.us`, `*.securitycenter.microsoft.us`).

## V15
- Handshake sweeps now catch failures before TLS (SYN with no SYN-ACK, ICMP unreachable) using DNS-resolved IPs.
- Hostnames seen only in DNS are now checked at the IP level.
- Added bare `endpoint.security.microsoft.com` to the commercial list.
- Fixed ICMP unreachable matching to use the original destination.

## V14
- Added Section 11, Summary & Recommended Actions.
- TLS 1.3 cipher-compliance findings carry a note to confirm the requirement with SSL Labs.
