# Changelog

## V16.5.6
- New finding, **Certificate trust**. When the device itself sends a fatal TLS alert (`bad_certificate`, `certificate_unknown` or `unknown_ca`) right after a genuine Microsoft certificate chain (Microsoft / DigiCert / Baltimore / GlobalSign names, no inspecting vendor in it), the result is no longer a plain Connectivity failure or "possible SSL inspection". It points at the device's own trusted-root list (Cryptographic Services missing permissions on the `AuthRoot` registry keys, `ctldl.windowsupdate.com` blocked, the "Turn off Automatic Root Certificates Update" policy, an unpatched Windows) and lists read-only checks to run on the device.
- TLS 1.2 only: under TLS 1.3 the certificate and the alert are encrypted. An alert sent by the server, `certificate_expired` / `certificate_revoked`, or a chain with an inspecting vendor in it keep their old findings.

## V16.5.5
- Proxy answers are read, not just counted. A CONNECT answered `504 Unknown Host` is the proxy failing to resolve the name (its DNS, not a block); other 5xx is a gateway error, 3xx a redirect to a sign-in or block page, and only the other 4xx (403...) is called a policy block. The finding's cause and fix follow the answer.
- `-Domain` for a host the device only asked a proxy for (HTTP CONNECT): lists the CONNECT requests with the proxy's answers and why there is no DNS or TLS, instead of "No DNS or TLS traffic found". Such hosts also appear in the "similar domains" list.
- Plain HTTP (TCP 80) is followed. Certificate revocation and issuer downloads (for example `www.microsoft.com/pkiops`, `caissuers.microsoft.com`) that never get a SYN-ACK are listed in Section 10 as direct connections to Microsoft hosts that got no answer, with a Connectivity finding.
- Windows PowerShell 5.1 fix: a single matching Client Hello, 407 or DNS record looked like none ("0 had a TLS Client Hello follow" for a tunnel that did have one; `-Domain` skipping sections for a host with a single Client Hello).

## V16.5.4
- The Copilot prompt starts with data-handling rules: Copilot must not ask for, repeat or retain customer identifying data (hostnames, domains, usernames, emails, company names, tenant IDs, case numbers).

## V16.5.3
- Added US Gov / DoD and commercial portal URL coverage (`security.apps.mil`, `*.gcc.securitycenter.microsoft.us`, `security.microsoft.com`, `login.microsoftonline.com`, the portal auth/CDN hosts and the Linux configuration hosts).

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
