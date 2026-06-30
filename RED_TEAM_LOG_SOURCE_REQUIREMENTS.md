# Detection Rule Coverage - Log Source & Tool Requirements
## Red Team & Deployment Readiness Reference

> **Purpose:** This document lists every log source, tool, agent, and Windows configuration required
> for the custom detection rules in this repository to fire correctly.
> If any of these are not active or forwarded to your SIEM, the corresponding rules will be blind.
> Share this with the red team before any testing exercise and with your mentor/SOC lead before deployment.

---

## 1. Required Endpoint Agents & Tools

| # | Tool / Agent | Required? | Notes |
|---|---|---|---|
| 1 | **Sysmon (System Monitor)** | MANDATORY | Covers ~80% of all rules. Deploy on all Windows endpoints with a config that enables the EIDs in Section 2. |
| 2 | **Windows Event Logging** | MANDATORY | Native Windows. Ensure Security, System, Application channels are not filtered or disabled. |
| 3 | **PowerShell Script Block Logging** | MANDATORY | Group Policy: Computer Config > Admin Templates > Windows Components > Windows PowerShell > Turn on Script Block Logging. Required for 6+ rules. |
| 4 | **PowerShell Module Logging** | Recommended | Supplements Script Block Logging; captures imported module names even when blocks are obfuscated. |
| 5 | **Command Line Auditing** | MANDATORY | Audit Process Creation with command-line included. Without this, all process_creation rules will have a blank CommandLine field. |
| 6 | **WMI Activity Logging** | MANDATORY | Required for WMI subscription rules (AN0024-B). Enable: `wevtutil sl Microsoft-Windows-WMI-Activity/Operational /e:true` |
| 7 | **AMSI (Antimalware Scan Interface)** | Recommended | Required to capture deobfuscated PowerShell payloads for AN1440-A and AN0543-B. Must not be disabled by AV policy. |
| 8 | **Web Proxy with SSL Inspection** | For Recon rules | AN2075 rules require decrypted outbound HTTPS logs. Needs SSL-inspecting proxy (Zscaler, Palo Alto, Squid with SSL bump). |
| 9 | **Exchange / Mail Gateway Logs** | For Phishing rules | AN2073 rules require Exchange transport logs or mail gateway integration (Proofpoint, Mimecast). |
| 10 | **IIS / Web Server Access Logs** | For Web rules | AN2069 web path discovery / web shell rules require IIS W3C or NGINX/Apache access logs forwarded to SIEM. |
| 11 | **Log Forwarding Agent** | MANDATORY | Winlogbeat, NXLog, or Azure Monitor Agent must be running and healthy on all endpoints. |

---

## 2. Sysmon Event IDs - Must Be Enabled in Sysmon Config

Configure your `sysmonconfig.xml` to capture ALL of the following Event IDs.
Any gap will silently blind the rules that depend on it.

| Sysmon EID | Schema Category Name | Rules Depending On It | Key Rules |
|---|---|---|---|
| **EID 1** | `process_creation` | 60+ | AN0243-A, AN0282-A, AN0823-A/B, AN1091-A/B, AN1274-A, AN1290-A, AN1321, AN1440-B, all lateral movement and privilege escalation rules |
| **EID 3** | `network_connection` | 15+ | AN1274-B, AN1290-B, AN0504-B, AN0590-B, AN1137-B, AN1283-B, AN1543-B, AN0147 |
| **EID 6** | `driver_load` | 1 | AN1419 (BYOVD - Known Vulnerable Driver) |
| **EID 7** | `image_load` | 6 | AN0282-B, AN0389-B, AN0577, AN0757-B |
| **EID 8** | `create_remote_thread` | 3 | AN0297, AN1095, AN1399 (process injection chains) |
| **EID 10** | `process_access` | 9 | AN0389-A (LSASS access), AN0277, AN0608, AN0822, AN0941, AN1076, AN1144-B, AN1289 |
| **EID 11** | `file_event` | 12+ | AN1321, AN0108-B, AN0258-B, AN0516-B, AN0577-B, AN1298, AN2069-WebShell-Files |
| **EID 12** | `registry_event` (add/delete) | 12+ | AN0243-B, AN0543-A, AN0757-C, AN0814-A, AN1094-B, AN0609-B, AN0074-B, AN0094-B, AN0170-B, AN0791-B |
| **EID 13** | `registry_event` (value set) | 12+ | Same as EID 12 - registry value writes |
| **EID 20/21** | `wmi_event` | 1 | AN0024-B (WMI subscription persistence) |
| **EID 22** | `dns_query` | Correlation rules | DNS tunneling detection in new work/command-and-control/ |

> **Recommended base config:** SwiftOnSecurity sysmon-config (https://github.com/SwiftOnSecurity/sysmon-config)
> After applying, verify none of the above EIDs are silently excluded by the config's exclude clauses for your test binaries.

---

## 3. Windows Event Log Channels - Must Be Forwarded to SIEM

| Channel | Key Event IDs | Required For |
|---|---|---|
| `Security` | 4624, 4625, 4648, 4688, 4703, 4738, 4768, 4769, 4771, 5156 | Lateral movement, privilege escalation, MFA tampering (AN0543), account modification (AN1621) |
| `System` | 7045, 7036 | Service creation/modification (AN0778, AN1468) |
| `Microsoft-Windows-PowerShell/Operational` | **4104** (Script Block Logging) | AN1440-A, AN0543-B, AN0147-B, AN0327-B, AN0623-B, AN0931-B, AN1313-B -- CRITICAL, rule cannot fire without this |
| `Microsoft-Windows-WMI-Activity/Operational` | 5857, 5858, 5860, 5861 | AN0024-B (WMI subscription registration) |
| `Microsoft-Windows-Sysmon/Operational` | All EIDs from Section 2 | All Sysmon-based rules |
| `Microsoft-Windows-PrintService/Operational` | 316 | AN0074 (custom print processor installation) |

---

## 4. Per-Tactic Log Source Coverage Map

### COLLECTION (T1056 + T1557) - 17 Rules

| Rule ID | Technique | Sigma Log Source | Windows Channel Required |
|---|---|---|---|
| AN0243-A | T1056.001 - Keylogging | process_creation / windows | Sysmon EID 1 |
| AN0243-B | T1056.001 - Keylogging | registry_event / windows | Sysmon EID 13 |
| AN0282-A | T1056 - Input Capture | process_creation / windows | Sysmon EID 1 |
| AN0282-B | T1056 - Input Capture | image_load / windows | Sysmon EID 7 |
| AN0389-A | T1056.004 - Credential API Hooking | process_access / windows | Sysmon EID 10 |
| AN0389-B | T1056.004 - Credential API Hooking | image_load / windows | Sysmon EID 7 |
| AN1321 | T1056.003 - Web Portal Capture | file_event / windows | Sysmon EID 11 |
| AN1440-A | T1056.002 - GUI Input Capture | ps_script / windows | PowerShell EID 4104 |
| AN1440-B | T1056.002 - GUI Input Capture | process_creation / windows | Sysmon EID 1 |
| AN0823-A | T1557 - AiTM | process_creation / windows | Sysmon EID 1 |
| AN0823-B | T1557 - AiTM | process_creation / windows | Sysmon EID 1 |
| AN1091-A | T1557.002 - ARP Cache Poisoning | process_creation / windows | Sysmon EID 1 |
| AN1091-B | T1557.002 - ARP Cache Poisoning | process_creation / windows | Sysmon EID 1 |
| AN1274-A | T1557.001 - LLMNR/NBT-NS Poisoning | process_creation / windows | Sysmon EID 1 |
| AN1274-B | T1557.001 - LLMNR/NBT-NS Poisoning | network_connection / windows | Sysmon EID 3 |
| AN1290-A | T1557.003 - DHCP Spoofing | process_creation / windows | Sysmon EID 1 |
| AN1290-B | T1557.003 - DHCP Spoofing | network_connection / windows | Sysmon EID 3 |

---

### DEFENSE IMPAIRMENT (T1556 + T1484) - 15 Rules

| Rule ID | Technique | Sigma Log Source | Windows Channel Required |
|---|---|---|---|
| AN0543-A | T1556.006 - MFA Tampering | registry_event / windows | Sysmon EID 13 |
| AN0543-B | T1556.006 - MFA Tampering | ps_script / windows | PowerShell EID 4104 |
| AN0757-A | T1556.001 - LSASS Driver | process_access / windows | Sysmon EID 10 |
| AN0757-B | T1556.001 - LSASS Driver | image_load / windows | Sysmon EID 7 |
| AN0757-C | T1556.001 - LSASS Driver | registry_event / windows | Sysmon EID 13 |
| AN0814-A | T1556.007 - Hybrid Identity | registry_event / windows | Sysmon EID 13 |
| AN0814-B | T1556.007 - Hybrid Identity | file_event / windows | Sysmon EID 11 |
| AN1259-A | T1484.002 - Domain Trust Mod | process_creation / windows | Sysmon EID 1 |
| AN1259-B | T1484.002 - Domain Trust Mod | registry_event / windows | Sysmon EID 12/13 |
| AN1303-A | T1556.002 - Password Filter DLL | registry_event / windows | Sysmon EID 13 |
| AN1303-B | T1556.002 - Password Filter DLL | file_event / windows | Sysmon EID 11 |
| AN1598-A | T1556.008 - Network Provider | registry_event / windows | Sysmon EID 13 |
| AN1598-B | T1556.008 - Network Provider | file_event / windows | Sysmon EID 11 |
| AN1621-A | T1556.005 - Reversible Encryption | windows / Security | Security EID 4738 |
| AN1621-B | T1556.005 - Reversible Encryption | windows / Security | Security EID 4738 |

---

### EXECUTION - 18 Rules (summary by log source)

| Sigma Log Source | Rules | Windows Channel |
|---|---|---|
| process_creation / windows | AN0108, AN0172, AN0176, AN0178, AN0209, AN0258, AN0278, AN0550, AN0578, AN0609, AN0628, AN0699, AN0733, AN0778, AN0797, AN0819 | Sysmon EID 1 |
| file_event / windows | AN0108-B, AN0209-B, AN0258-B, AN0278-B, AN0550-B, AN0577-B | Sysmon EID 11 |
| image_load / windows | AN0577 | Sysmon EID 7 |
| registry_set / windows | AN0609-B | Sysmon EID 13 |

---

### LATERAL MOVEMENT - 25 Rules (summary by log source)

| Sigma Log Source | Rules | Windows Channel |
|---|---|---|
| process_creation / windows | AN0216, AN0327, AN0504-A, AN0516, AN0623, AN0750, AN0791, AN0931, AN0954-B, AN1000, AN1144-B, AN1298-B, AN1313, AN1468, AN1620 | Sysmon EID 1 |
| network_connection / windows | AN0147, AN0504-B | Sysmon EID 3 |
| ps_script / windows | AN0147-B, AN0327-B, AN0623-B, AN0931-B, AN1313-B | PowerShell EID 4104 |
| file_event / windows | AN0516-B, AN1298 | Sysmon EID 11 |
| registry_set / windows | AN0791-B | Sysmon EID 13 |

---

### PRIVILEGE ESCALATION - 33 Rules (summary by log source)

| Sigma Log Source | Rules | Windows Channel |
|---|---|---|
| process_creation / windows | AN0024, AN0051, AN0074, AN0094, AN0170, AN0786, AN0975, AN1094, AN1137-A, AN1253, AN1283-A, AN1324, AN1351, AN1501, AN1543-A | Sysmon EID 1 |
| process_access / windows | AN0277, AN0608, AN0822, AN0941, AN1076, AN1144-B, AN1289 | Sysmon EID 10 |
| create_remote_thread / windows | AN0297, AN1095, AN1399 | Sysmon EID 8 |
| network_connection / windows | AN0590-B, AN1137-B, AN1283-B, AN1543-B | Sysmon EID 3 |
| wmi_event / windows | AN0024-B | WMI EID 5861 |
| registry_set / windows | AN0051-B, AN0074-B, AN0094-B, AN0170-B, AN0975-B, AN1094-B | Sysmon EID 13 |
| driver_load / windows | AN1419 | Sysmon EID 6 |

---

### RECONNAISSANCE - 11 Rules

| Rule ID | Sigma Log Source | Windows Channel / External Source |
|---|---|---|
| AN2067, AN2067-Registry, AN2067-WMIC | process_creation / windows | Sysmon EID 1 |
| AN2069-WebShell-Spawning | process_creation / windows | Sysmon EID 1 |
| AN2069-WebShell-Files | file_event / windows | Sysmon EID 11 |
| AN2069 (CDN/web path discovery) | webserver / windows | IIS W3C Extended Logging or NGINX/Apache access logs |
| AN2073, AN2073-Phishing-Internal | email / msexchange | Exchange Transport Logs or mail gateway (Proofpoint/Mimecast) |
| AN2075, AN2075-Unlisted-GenAI, AN2075-Decrypted-Leaking | web_proxy / proxy | SSL-inspecting proxy logs (Zscaler, Palo Alto, Squid) |

---

## 5. Red Team Pre-Test Verification Checklist

Run through every item before starting a test session. If any item fails, the corresponding rules will not fire.

### Sysmon Verification
- [ ] Sysmon service is running on target endpoints: `sc query sysmon64`
- [ ] Sysmon version >= 14.0 (check with: `sysmon64 -s`)
- [ ] Sysmon config has EIDs 1, 3, 6, 7, 8, 10, 11, 12, 13, 22 enabled without filtering test binaries
- [ ] Sysmon events are reaching SIEM - verify last event is less than 5 minutes old

### PowerShell Script Block Logging
- [ ] Run `Write-Output "test_sbl"` in PowerShell on endpoint
- [ ] Verify Event ID 4104 appears in Microsoft-Windows-PowerShell/Operational in Event Viewer
- [ ] Confirm SIEM receives this event

### Command Line Auditing
- [ ] Run any process (e.g., `whoami`) on endpoint
- [ ] Verify Event 4688 in Security log includes the ProcessCommandLine / CommandLine field
- [ ] OR verify Sysmon EID 1 CommandLine field is populated in SIEM

### Windows Event Channels
- [ ] Security log is enabled and forwarding (verify with recent 4624 login events)
- [ ] Security log max size is >= 1 GB (prevents overwrite before collection)
- [ ] System log is forwarding
- [ ] Microsoft-Windows-WMI-Activity/Operational is enabled and forwarding
- [ ] Microsoft-Windows-PowerShell/Operational is forwarding

### Network Telemetry
- [ ] Sysmon EID 3 events appear in SIEM for a known outbound connection test
- [ ] [If AN2075 in scope] SSL inspection proxy logs ingest into SIEM
- [ ] [If AN2073 in scope] Mail gateway or Exchange transport logs ingest into SIEM
- [ ] [If AN2069 web rules in scope] IIS / web server logs ingest into SIEM

### Log Pipeline Health
- [ ] Log forwarding agent (Winlogbeat / NXLog / AMA) is running and not dropping events
- [ ] No sampling, filtering, or size-limit truncation in the forwarding pipeline
- [ ] SIEM query for the last 5 minutes returns events from each required channel

---

## 6. Known Gaps & Limitations

| Gap | Affected Rules | Notes |
|---|---|---|
| No Linux endpoint agent | All product: windows rules | Deploy Sysmon for Linux or Auditd equivalent if Linux hosts are in red team scope |
| No SSL inspection proxy | AN2075 series | HTTPS payload is opaque without SSL inspection; rules will not fire |
| No Exchange/mail gateway log | AN2073 series | No email telemetry = no phishing detection |
| No IIS/web server logs | AN2069 (web path/web shell) | Filesystem writes captured by Sysmon EID 11, but HTTP access log rules need IIS logs |
| Renamed binaries bypass | All Image endswith rules | Attacker renames python.exe to helper.exe = bypass; mitigate with OriginalFileName or hash baselines |
| Process injection via explorer.exe / svchost.exe | AN0243-B | Filter excludes injected-code scenario. Known, documented, acceptable tradeoff for noise reduction. |
| Obfuscated PowerShell | AN1440-A, AN0543-B | AMSI must be active for deobfuscated script block capture. Verify AMSI is not disabled by AV policy. |
| Compiled Go tools | AN0823-B | go.exe added, but pre-compiled Go binaries with renamed binary will bypass Image filter |

---

*Document Version: 1.0*
*Last Updated: 2026-06-30*
*Sprint Coverage: Collection (T1056 + T1557) - 17 rules verified and closed*
*Maintainer: Krishna Gupta*
