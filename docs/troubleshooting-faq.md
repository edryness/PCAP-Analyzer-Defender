# PCAP Analyzer for MDE - Troubleshooting and FAQ

*[Home](../README.md) | [Setup Guide](setup-guide.md) | [User Reference](user-reference.md) | [Quick Reference](quick-reference.md) | [Troubleshooting & FAQ](troubleshooting-faq.md)*

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| **"Windows won't let this app read the capture (access denied)"** | The capture was created by an admin tool such as MDE Client Analyzer | Click **Yes** to restart as administrator, or copy the capture to a folder you own |
| **"ERROR: tshark could not read '...' - no analysis was done"** | tshark couldn't open the file. The line underneath shows tshark's own reason. | "Permission denied": run as administrator. "Isn't a capture file": re-export it from Wireshark as `.pcapng`. |
| **"ERROR: '...' contains no packets"** | The capture is empty | Re-collect the capture while reproducing the issue |
| **"ERROR: Could not run tshark"** | Wireshark isn't installed, or the tshark path is wrong | Install Wireshark, or browse to `C:\Program Files\Wireshark\tshark.exe` |
| **"Provide -Domain ... or -All"** | No switch was selected | Tick **-All** and/or **-Domain** |
| **"Enter one FQDN for -Domain"** | The box has a URL, path, port, or is empty | Enter the hostname only, e.g. `winatp-gw-eus3.microsoft.com` |
| **Copilot status: "not installed"** | Copilot CLI isn't installed for this user | Click **Install Copilot CLI** - see the [Setup and User Guide](setup-guide.md) |
| **Copilot status: "not signed in"** | GitHub sign-in hasn't been completed | Click **Sign in** and finish the GitHub page |
| **Copilot status mentions "policy" or "not enabled"** | Copilot CLI is disabled for your GitHub account by your organization | Use **Copilot: Chat** |
| **Copilot status shows a proxy or certificate error** | Something is intercepting HTTPS to GitHub | Use **Copilot: Chat** until it's resolved |
| **Section 12 opened Copilot Chat instead of answering in the app** | Copilot CLI wasn't ready for this run | Check the Copilot status line; fix the item it shows |
| **The app is blocked or flagged when launched** | Unsigned executables are often flagged by antivirus/EDR or SmartScreen | Download the latest build from the [Releases](../../../releases) page |

## FAQ

**Which capture should I use?**
`ConvertedTrace.pcapng` from MDE Client Analyzer works well. Any Wireshark capture taken while reproducing the issue works too, as long as it includes the device's traffic to Microsoft.

**Do I always need -All?**
It's the recommended first pass because it checks every required URL. If you already know the environment, `-AllCommercial` or `-AllGov` (command line) runs just that half.

**What's the difference between -All and -Domain?**
-All checks every MDE URL and reports pass / fail / stage. -Domain examines one hostname in depth: TLS versions, ciphers, per-stage handshake results, byte counts, and cipher compliance.

**Why is -Detailed greyed out?**
It only applies to -Domain. Tick -Domain first.

**Section 11 says "no actionable issues" but the customer is still broken. Why?**
Section 11 deliberately leaves out ambiguous and informational results. Review Sections 6-10 for `[UNKNOWN]` and `[INFO]` lines, confirm the capture covers the failure window, and consider causes outside the network path (device health, onboarding state, time sync).

**Section 5 says a TLS 1.3 cipher suite is missing. Is that a problem?**
Not necessarily. That baseline comes from Power Platform documentation, not MDE guidance, and not every MDE URL needs TLS 1.3. Confirm with [SSL Labs](https://www.ssllabs.com/ssltest/) before raising it with the customer.

**What does Copilot see?**
Only the Section 11 findings text (Microsoft URLs, issue / cause / fix) and the switches used. It never sees the capture, IP addresses, or file names. Set **Copilot: Off** to keep everything local.

**Can Copilot write the customer email?**
No. Copilot's output is limited to an engineer-facing recommended fix. Write customer communication yourself, after validating in Wireshark.

**Where is Copilot's answer saved?**
Next to the capture, as `<capture>_CopilotPlan_<date-time>.md`.

**Does it work on government-cloud (GCC / GCC High / DoD) captures?**
Yes. -All checks the US Gov URL list in Sections 8 and 9. Follow your organization's data-handling requirements before using Copilot on those cases.

**Can I run it without the app?**
Yes. Run the PowerShell script directly - see the [Quick Reference](quick-reference.md#command-line).

---

*Results are generated automatically from packet-capture analysis and AI-assisted recommendations. Validate findings in Wireshark before acting on them or sharing them with customers, particularly where a result appears inconsistent or unexpected.*
