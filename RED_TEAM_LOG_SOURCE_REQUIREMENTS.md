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
| 3 | **PowerShell Script Block Logging** | MANDATORY | Group Policy: Computer Config > Admin Templates > Windows Components > Windows PowerShell > Turn on Script Block Logging. Required for PowerShell execution rules. |
| 4 | **PowerShell Module Logging** | Recommended | Supplements Script Block Logging; captures imported module names even when blocks are obfuscated. |
| 5 | **Command Line Auditing** | MANDATORY | Audit Process Creation with command-line included. Without this, all process_creation rules will have a blank CommandLine field. |
| 6 | **WMI Activity Logging** | MANDATORY | Required for WMI activity/persistence rules. Enable: `wevtutil sl Microsoft-Windows-WMI-Activity/Operational /e:true` |
| 7 | **AMSI (Antimalware Scan Interface)** | Recommended | Required to capture deobfuscated PowerShell payloads. Must not be disabled by AV policy. |
| 8 | **Web Proxy with SSL Inspection** | For Recon rules | Reconnaissance rules (e.g. AN2075) require decrypted outbound HTTPS logs (Zscaler, Palo Alto, Squid). |
| 9 | **Exchange / Mail Gateway Logs** | For Phishing rules | Phishing rules (e.g. AN2073) require Exchange transport logs or mail gateway integration (Proofpoint, Mimecast). |
| 10 | **IIS / Web Server Access Logs** | For Web rules | Web rules (e.g. AN2069) require IIS W3C or NGINX/Apache access logs forwarded to SIEM. |
| 11 | **Log Forwarding Agent** | MANDATORY | Winlogbeat, NXLog, or Azure Monitor Agent must be running and healthy on all endpoints. |

---

## 2. Sysmon Event IDs - Must Be Enabled in Sysmon Config

Configure your `sysmonconfig.xml` to capture ALL of the following Event IDs. Any gap will silently blind the rules that depend on it.

| Sysmon EID | Schema Category Name | Key Rules Coverage |
|---|---|---|
| **EID 1** | `process_creation` | Keylogger utility, input capture process, LOLBins, BITS, certutil, wscript/cscript, domain discovery, all Sprints 1 & 2 Discovery rules |
| **EID 3** | `network_connection` | Inbound SSH reverse shells, LLMNR/NBT-NS binding, DHCP spoofing, netstat execution, port scan tool execution |
| **EID 6** | `driver_load` | BYOVD (Bring Your Own Vulnerable Driver) |
| **EID 7** | `image_load` | Keylogger DLLs, LSASS access packages, input hooking libraries |
| **EID 8** | `create_remote_thread` | Memory injection chains, remote thread injection |
| **EID 10** | `process_access` | LSASS memory access, credential dumping, process credential reading |
| **EID 11** | `file_event` | Web shell creation, installer file dropping, BITS file staging |
| **EID 12/13** | `registry_event` | Keyboard layout registry tampering, MFA registry tampering, Hybrid Identity agent registry modifications |
| **EID 20/21** | `wmi_event` | WMI persistence event filter/consumer binding |
| **EID 22** | `dns_query` | DNS tunneling queries |

---

## 3. Windows Event Log Channels - Must Be Forwarded to SIEM

| Channel | Key Event IDs | Required For |
|---|---|---|
| `Security` | 4624, 4625, 4648, 4688, 4703, 4738, 4768, 4769, 4771, 5156 | Lateral movement logons, privilege escalation, MFA tampering, account modifications |
| `System` | 7045, 7036 | Service creation/modification, kernel driver operations |
| `Microsoft-Windows-PowerShell/Operational` | **4104** (Script Block Logging) | GUI Input capture, PowerShell MFA tampering scripts, remote PowerShell executions |
| `Microsoft-Windows-WMI-Activity/Operational` | 5857, 5858, 5860, 5861 | WMI operational activity and subscription registrations |
| `Microsoft-Windows-Sysmon/Operational` | All EIDs from Section 2 | All Sysmon-based detection rules |
| `Microsoft-Windows-PrintService/Operational` | 316 | Custom print processor installations |

---

## 4. Per-Tactic Log Source Coverage Map

This section lists all rules currently present on disk, grouped by tactic, and mapped to their exact logging requirements.

### COLLECTION (41 Rules)

| Rule ID | Technique | Log Source Required | Target Channel | Title |
|---|---|---|---|---|
| AN0040 | T1074 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Data Staging via Archive Utilities in Temp Directories |
| AN0040 | T1074 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Staging Directory File Creation |
| AN0130 | T1114.001 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Local Outlook Email Archive Access by Non-Outlook Process |
| AN0130 | T1114.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Local Outlook Email Archive CLI Search |
| AN0131 | T1114.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Collection - Remote Email Collection via Exchange API Query |
| AN0194 | T1074.002 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Collection - Archive File Written to Remote UNC Share |
| AN0243 | T1056.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Keylogger Utility Process Execution |
| AN0243 | T1056.001 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Keyboard Layout Registry Tampering |
| AN0282 | T1056 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Input Sniffing Process Execution |
| AN0282 | T1056 | Sysmon EID 7 (image_load) | Microsoft-Windows-Sysmon/Operational | Suspicious Module Load in Interactive User Processes |
| AN0389 | T1056.004 | Sysmon EID 10 (process_access) | Microsoft-Windows-Sysmon/Operational | Logon Process Memory Access |
| AN0389 | T1056.004 | Sysmon EID 7 (image_load) | Microsoft-Windows-Sysmon/Operational | Logon UI Suspicious DLL Load |
| AN0531 | T1119 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Automated File Collection via Recursive Enumeration |
| AN0531 | T1119 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Automated Collection Staged File Creation |
| AN0677 | T1213.006 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious Database Client Execution for Data Collection |
| AN0677 | T1213.006 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Suspicious Database Client Network Connection |
| AN0724 | T1074.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Local Data Staging via Bulk File Copy |
| AN0724 | T1074.001 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Local Data Staging File Creation |
| AN0823 | T1557 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AiTM Interception Tool Execution |
| AN0823 | T1557 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Scripting Process Invoked as Proxy Listener |
| AN0831 | T1560.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Collection - Data Archiving via Utility |
| AN0965 | T1115 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Collection - Clipboard Data Retrieval Command |
| AN0980 | T1113 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Collection - Screen Capture Utility Execution |
| AN1070 | T1005 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Collection - Search Loop for Sensitive Local Files |
| AN1091 | T1557.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | ARP Spoofing Tool Execution |
| AN1091 | T1557.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Native ARP Table Static Modification |
| AN1145 | T1039 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Collection - Copy of Data from Remote UNC Share |
| AN1160 | T1213 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Collection - Programmatic or Excessive Information Repository Access |
| AN1213 | T1560.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Collection - Archiving or Encryption via Custom Method |
| AN1274 | T1557.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | LLMNR/NBT-NS Spoofing Tool Execution |
| AN1274 | T1557.001 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Scripting Process Binding to LLMNR or NetBIOS Ports |
| AN1290 | T1557.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | DHCP Spoofing Tool Execution |
| AN1290 | T1557.003 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Unofficial DHCP Server Port Binding |
| AN1309 | T1114 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Collection - Local Email Database Access and Collection |
| AN1321 | T1056.003 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Web Server Root Folder File Creation |
| AN1398 | T1185 | Sysmon EID 10 (process_access) | Microsoft-Windows-Sysmon/Operational | Collection - Browser Process Access and Session Hijacking |
| AN1410 | T1025 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Collection - Data Access and Copy from Removable Media |
| AN1440 | T1056.002 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | GUI Input Capture via PowerShell Script Block |
| AN1440 | T1056.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | GUI Input Capture Command Line |
| AN1458 | T1560 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Collection - Archiving and Encryption of Data via Utility |
| AN1589 | T1114.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Collection - Email Inbox Forwarding Rule Creation |

### COMMAND-AND-CONTROL (22 Rules)

| Rule ID | Technique | Log Source Required | Target Channel | Title |
|---|---|---|---|---|
| AN0100 | T1102.002 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Bidirectional C2 Communication via Web Service API |
| AN0100 | T1102.002 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Bidirectional C2 via PowerShell Script Block |
| AN0109 | T1568 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | DNS Connection from Non-Network System Utility |
| AN0109 | T1568 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious Non-Network System Utility Execution |
| AN0158 | T1102.001 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Scripting Host Connection to Dead Drop Web Service |
| AN0158 | T1102.001 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Dead Drop Web Service via PowerShell Script Block |
| AN0165 | T1105 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Ingress Tool Transfer via CLI |
| AN0165 | T1105 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Ingress Tool Transfer via PowerShell Script Block |
| AN0165 | T1105 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Ingress Tool Transfer Network Connection |
| AN0400 | T1573.001 | Sysmon EID 7 (image_load) | Microsoft-Windows-Sysmon/Operational | Cryptographic DLL Loaded by Non-Cryptographic Process |
| AN0400 | T1573.001 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Outbound Network Connection from Non-Cryptographic Process |
| AN0633 | T1571 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Outbound Network Connection via Non-Standard Port |
| AN0633 | T1571 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Outbound Connection via Non-Standard Port via CLI |
| AN0637 | T1104 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Multi-Stage C2 Channel Process spawning with Network Connection |
| AN0637 | T1104 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Multi-Stage C2 Process Spawning |
| AN0714 | T1219 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Unauthorized Remote Management and Monitoring Software Execution |
| AN0714 | T1219 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Unauthorized Remote Management and Monitoring Network Connection |
| AN0728 | T1568.003 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | DNS TXT Query via PowerShell Script Block |
| AN0728 | T1568.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | DNS TXT Query via CLI |
| AN2110 | T1008 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Redundant Fallback Channel Proxy Execution |
| AN2113 | T1092 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Script or Binary Execution from Removable Media Path |
| AN2116 | T1132 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Process Command Line Data Encoding or Decoding Activity |

### CREDENTIAL ACCESS (3 Rules)

| Rule ID | Technique | Log Source Required | Target Channel | Title |
|---|---|---|---|---|
| AN2103 | T1552 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Credential String Search in Files and Registry |
| AN2104 | T1187 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Forced Authentication via UNC Path or SCF File Creation |
| AN2107 | T1539 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Browser Cookie Database Access by Non-Browser Process |

### CREDENTIAL-ACCESS (19 Rules)

| Rule ID | Technique | Log Source Required | Target Channel | Title |
|---|---|---|---|---|
| AN0105 | T1555.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious Browser Credential Store Access via CLI |
| AN0105 | T1555.003 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Suspicious Browser Credential Store Access via File Event |
| AN0235 | T1003.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious SAM Registry Hive Export via CLI |
| AN0235 | T1003.002 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Suspicious SAM Registry Hive Modification via Registry Set |
| AN0235 | T1003.002 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Suspicious SAM Registry Hive Export via File Event |
| AN0292 | T1110.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Local Password Cracking Activity via CLI |
| AN0292 | T1110.002 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Local Password Cracking Activity via PowerShell Script Block |
| AN0316 | T1558.004 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AS-REP Roasting Tool Execution via CLI |
| AN0316 | T1558.004 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | AS-REP Roasting Tool Execution via PowerShell Script Block |
| AN0378 | T1555.004 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious Windows Credential Manager Access via CLI |
| AN0378 | T1555.004 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Suspicious Windows Credential Manager Access via PowerShell Script Block |
| AN0405 | T1558.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Golden Ticket Forging Tool Execution via CLI |
| AN0405 | T1558.001 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Golden Ticket Forging Tool Execution via PowerShell Script Block |
| AN0444 | T1558.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious SPN Enumeration and Kerberoasting Activity via CLI |
| AN0444 | T1558.003 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Suspicious SPN Enumeration and Kerberoasting Activity via PowerShell Script Block |
| AN2115 | T1111 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Custom Security Support Provider or LSA Package Registration |
| AN2118 | T1212 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Print Spooler Service Spawning Suspicious Child Process |
| AN2123 | T1649 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Authentication Certificate or Private Key Export Tool Execution |
| AN2128 | T1684 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Social Engineering Script-Based Credential Dialog Prompt |

### DEFENSE EVASION (18 Rules)

| Rule ID | Technique | Log Source Required | Target Channel | Title |
|---|---|---|---|---|
| AN2097 | T1622 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Debugger Presence Check via Registry or Process Query |
| AN2099 | T1140 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | File Decode or Deobfuscation via LOLBins |
| AN2100 | T1202 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Indirect Command Execution via Trusted Windows Utilities |
| AN2101 | T1216 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Microsoft-Signed Script Proxy Execution |
| AN2102 | T1220 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | XSL Script Execution via WMIC or MSXSL |
| AN2105 | T1036 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | System Binary Name Used from Non-Standard Path |
| AN2106 | T1027 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | PowerShell Encoded Command or Heavy Obfuscation Execution |
| AN2108 | T1001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Steganography or Data Obfuscation Utility Execution |
| AN2109 | T1006 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Direct Volume Access Command Line Detection |
| AN2111 | T1014 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Rootkit Installation or Kernel Driver Bypass Tool Execution |
| AN2117 | T1211 | Sysmon EID 10 (process_access) | Microsoft-Windows-Sysmon/Operational | Anomalous Handle Access to System Process for Exploitation or Stealth |
| AN2119 | T1221 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Microsoft Office Application Spawning Script Interpreter |
| AN2120 | T1480 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Execution Guardrails Target Discovery Query |
| AN2122 | T1620 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | PowerShell Reflective Code Loading API Call |
| AN2124 | T1665 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Network DNS Resolver or Interface Routing Hijack |
| AN2125 | T1674 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Input Keystroke Automation or Injection Tool Execution |
| AN2126 | T1678 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Artificial Execution Delay or Anti-Sandbox Sleep |
| AN2127 | T1679 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Windows Defender Selective Exclusion Configuration |

### DEFENSE-EVASION (57 Rules)

| Rule ID | Technique | Log Source Required | Target Channel | Title |
|---|---|---|---|---|
| AN0071 | T1218.015 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Electron Application Abuse for Proxy Execution |
| AN0071 | T1218.015 | Sysmon EID 7 (image_load) | Microsoft-Windows-Sysmon/Operational | Suspicious Electron Library Load |
| AN0071 | T1218.015 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Electron ASAR File Modification |
| AN0091 | T1564.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Hidden File or Directory Attribute Setting |
| AN0091 | T1564.001 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Alternate Data Stream (ADS) File Creation |
| AN0113 | T1070.009 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Persistence Artifact Removal for Anti-Forensics |
| AN0113 | T1070.009 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Registry Persistence Key Deletion |
| AN0113 | T1070.009 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Scheduled Task Deletion via Security Logs |
| AN0118 | T1218.012 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Verclsid LOLBin Abuse for COM Object Execution |
| AN0118 | T1218.012 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Verclsid Network Connection |
| AN0118 | T1218.012 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Verclsid Custom CLSID Registry Modification |
| AN0139 | T1564.012 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AV Exclusion Path Addition or Abuse |
| AN0139 | T1564.012 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AV Exclusion Registry Modification |
| AN0153 | T1553.004 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Installation of Root Certificate via CLI |
| AN0153 | T1553.004 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Installation of Root Certificate via Registry |
| AN0182 | T1564.011 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | PowerShell Silent Error Suppression for Evasion |
| AN0182 | T1564.011 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | PowerShell Error Suppression Command-Line Option |
| AN0182 | T1564.011 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Cmd Error Stream Suppression |
| AN0277 | T1055.004 | Sysmon EID 10 (process_access) | Microsoft-Windows-Sysmon/Operational | Suspicious Process Access for Memory Injection |
| AN0297 | T1055.002 | Sysmon EID 8 (create_remote_thread) | Microsoft-Windows-Sysmon/Operational | Suspicious Remote Thread Creation (PE Injection) |
| AN0323 | T1688 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Force Safe Mode Boot or Tamper SafeBoot Configuration |
| AN0323 | T1688 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Tamper SafeBoot Registry Configuration |
| AN0406 | T1686 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Disabling or Tampering with Windows Firewall |
| AN0406 | T1686 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Windows Firewall Registry Modification |
| AN0420 | T1606.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious AD FS Database Query for SAML Certificate Extraction via CLI |
| AN0420 | T1606.002 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Suspicious AD FS Database Query for SAML Certificate Extraction via PowerShell Script Block |
| AN0535 | T1685.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Disabling or Tampering with Windows Event Logging |
| AN0535 | T1685.001 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Windows Event Logging Service Registry Modification |
| AN0550 | T1127.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | ClickOnce Proxy Execution Abuse |
| AN0550 | T1127.002 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Developer Utility Project File Creation |
| AN0608 | T1055.011 | Sysmon EID 10 (process_access) | Microsoft-Windows-Sysmon/Operational | Suspicious Process Access indicating EWM Injection |
| AN0643 | T1553.002 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Detect Suspicious or Malicious Code Signing Abuse |
| AN0643 | T1553.002 | Sysmon EID 7 (image_load) | Microsoft-Windows-Sysmon/Operational | Execution of DLL with Suspicious or Revoked Code Signature |
| AN0712 | T1553.005 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Subvert Trust Controls - Mark-of-the-Web Bypass via Container Mount |
| AN0770 | T1207 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Rogue Domain Controller - Kerberos DRS SPN Request by Non-DC Host |
| AN0822 | T1055.003 | Sysmon EID 10 (process_access) | Microsoft-Windows-Sysmon/Operational | Suspicious Process Access indicating Thread Hijacking |
| AN0868 | T1685.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Disable or Modify Tools - Spoof Tool UI |
| AN0941 | T1055.015 | Sysmon EID 10 (process_access) | Microsoft-Windows-Sysmon/Operational | Suspicious Process Access indicating ListPlanting |
| AN0975 | T1548 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Abuse of UAC Elevation Control Mechanisms |
| AN0975 | T1548 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | UAC Bypass Registry Key Modification |
| AN0995 | T1689 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Downgrade Attack - PowerShell v2 Execution |
| AN1076 | T1055.012 | Sysmon EID 10 (process_access) | Microsoft-Windows-Sysmon/Operational | Suspicious Process Access indicating Process Hollowing |
| AN1094 | T1548.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Registry Modification CLI for UAC Bypass |
| AN1094 | T1548.002 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Registry Value Set for UAC Bypass |
| AN1095 | T1055.001 | Sysmon EID 8 (create_remote_thread) | Microsoft-Windows-Sysmon/Operational | Suspicious Remote Thread Creation (LoadLibrary Injection) |
| AN1177 | T1222.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | File and Directory Permissions Modification |
| AN1222 | T1553.003 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | SIP and Trust Provider Hijacking |
| AN1246 | T1553 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Subvert Trust Controls - Malicious Root Cert Install |
| AN1289 | T1055.005 | Sysmon EID 10 (process_access) | Microsoft-Windows-Sysmon/Operational | Suspicious Process Access indicating TLS Callback Injection |
| AN1351 | T1134.004 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Parent PID Spoofing Detection |
| AN1369 | T1685 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Disable or Modify Tools - Kill Security Process |
| AN1399 | T1055 | Sysmon EID 8 (create_remote_thread) | Microsoft-Windows-Sysmon/Operational | Generic Process Injection (Remote Thread Creation) |
| AN1446 | T1553.006 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Code Signing Policy Modification - Bcdedit DSE Disable |
| AN1472 | T1685.005 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Clear Windows Event Logs - CLI Utilities |
| AN1501 | T1055.013 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious Process Creation indicating Process Doppelgänging |
| AN1557 | T1690 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Prevent Command History Logging - Set-PSReadLineOption |
| AN2043 | T1686.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Disable or Modify Windows Host Firewall |

### DEFENSE-IMPAIRMENT (15 Rules)

| Rule ID | Technique | Log Source Required | Target Channel | Title |
|---|---|---|---|---|
| AN0543 | T1556.006 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | MFA Registry Configuration Tampering |
| AN0543 | T1556.006 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | MFA Administrative Tampering via PowerShell |
| AN0757 | T1556.001 | Sysmon EID 10 (process_access) | Microsoft-Windows-Sysmon/Operational | LSASS Process Access on Domain Controller |
| AN0757 | T1556.001 | Sysmon EID 7 (image_load) | Microsoft-Windows-Sysmon/Operational | LSASS Suspicious Image Load |
| AN0757 | T1556.001 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | LSA Security Packages Registry Modification |
| AN0814 | T1556.007 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Hybrid Identity Service Registry Tampering |
| AN0814 | T1556.007 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Hybrid Identity Agent DLL Modification |
| AN1259 | T1484.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | CLI Domain Trust Modification Command |
| AN1259 | T1484.002 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Active Directory Trust Object Modification |
| AN1303 | T1556.002 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | LSA Password Filter DLL Registration |
| AN1303 | T1556.002 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | LSA Password Filter DLL File Write |
| AN1598 | T1556.008 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Network Provider DLL Registry Modification |
| AN1598 | T1556.008 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Network Provider DLL File Creation |
| AN1621 | T1556.005 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Reversible Encryption Enabled on User Account |
| AN1621 | T1556.005 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Reversible Encryption Enabled via Active Directory Attribute modification |

### DISCOVERY (39 Rules)

| Rule ID | Technique | Log Source Required | Target Channel | Title |
|---|---|---|---|---|
| AN0016 | T1482 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Domain Trust Discovery via nltest and PowerShell |
| AN0016 | T1482 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Domain Trust Discovery via PowerShell Script Block |
| AN0037 | T1217 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Browser Artifact Access for Reconnaissance |
| AN0037 | T1217 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | CommandLine Browser Data Access |
| AN0048 | T1518.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Security Software Discovery via Service and WMI Queries |
| AN0048 | T1518.001 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Security Software Discovery via PowerShell Script Block |
| AN0048 | T1518.001 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Security Software Registry Key Modifications |
| AN0095 | T1057 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Process Discovery via Enumeration Utilities |
| AN0095 | T1057 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Process Discovery via PowerShell Script Block |
| AN0240 | T1518.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Backup Software Discovery via CLI |
| AN0240 | T1518.002 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Backup Software Discovery via PowerShell Script Block |
| AN0240 | T1518.002 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Backup Software Registry Key Modifications |
| AN0254 | T1033 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | System Owner and User Discovery via Built-in Utilities |
| AN0254 | T1033 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | System Owner and User Discovery via PowerShell Script Block |
| AN0271 | T1010 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Application Window Enumeration via Scripting Host |
| AN0271 | T1010 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Application Window Enumeration via CLI |
| AN0455 | T1201 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Password Policy Discovery via CLI |
| AN0455 | T1201 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Password Policy Discovery via PowerShell Script Block |
| AN2076 | T1007 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | System Service Enumeration |
| AN2077 | T1012 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Registry Query for Sensitive Configurations |
| AN2078 | T1016 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | System Network Configuration Enumeration |
| AN2079 | T1018 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Remote System Discovery via Native Tools |
| AN2080 | T1046 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Local Network Service Port Discovery |
| AN2081 | T1049 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | SMB Share and Session Discovery |
| AN2082 | T1069 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Local and Domain Group Discovery |
| AN2083 | T1082 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | System and Hardware Information Enumeration |
| AN2084 | T1083 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Recursive Directory Enumeration |
| AN2085 | T1087 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Local and Domain Account Enumeration |
| AN2086 | T1120 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Peripheral Device Discovery via PowerShell or WMI |
| AN2087 | T1135 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Network Share Enumeration via Native Tools |
| AN2088 | T1614 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | System Locale and Keyboard Layout Discovery |
| AN2089 | T1124 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | System Time and Timezone Discovery |
| AN2090 | T1615 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Group Policy Enumeration |
| AN2091 | T1654 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Windows Event Log Enumeration |
| AN2092 | T1652 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Device Driver Enumeration |
| AN2093 | T1040 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Network Packet Capture Tool Execution |
| AN2094 | T1497 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | VM and Sandbox Detection Artifact Queries |
| AN2095 | T1673 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Virtual Machine Infrastructure Enumeration |
| AN2096 | T1680 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Local Storage Device Enumeration |

### EXECUTION (38 Rules)

| Rule ID | Technique | Log Source Required | Target Channel | Title |
|---|---|---|---|---|
| AN0052 | T1129 | Sysmon EID 7 (image_load) | Microsoft-Windows-Sysmon/Operational | Loading of Suspicious DLL from User-Writable Directory |
| AN0052 | T1129 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Loading Shared Modules via PowerShell |
| AN0172 | T1059.006 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious Python Interpreter Execution |
| AN0178 | T1204.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | User Execution - Malicious Link Clicking Behavioral Chain |
| AN0209 | T1059.005 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious Visual Basic Script Execution |
| AN0209 | T1059.005 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Visual Basic Script File Drop in Temp Directories |
| AN0278 | T1059.011 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious Lua Script Execution |
| AN0278 | T1059.011 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Lua Script File Drop in Temp Directories |
| AN0511 | T1505.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AN0511 - Server Software Component: SQL Stored Procedures |
| AN0511 | T1505.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AN0511 - Server Software Component: SQL Stored Procedures (OCSF) |
| AN0578 | T1059.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious Windows Command Shell Execution |
| AN0628 | T1559.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Component Object Model (COM) Execution |
| AN0699 | T1204.005 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious Execution via Malicious Installer/Package Manager |
| AN0733 | T1059.007 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious JavaScript Execution via WSH |
| AN0778 | T1569 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | System Service Creation or Modification |
| AN0797 | T1203 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Exploitation for Client Execution - Suspicious Child Process |
| AN0819 | T1204.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | User Execution - Malicious File Opened |
| AN0942 | T1059.010 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AutoHotKey or AutoIT Interpreter Execution |
| AN0942 | T1059.010 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | AutoHotKey or AutoIT Script File Drop |
| AN0962 | T1204.004 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Command Shell Spawned from User Application Context |
| AN0962 | T1204.004 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Download Utility Spawned by User Application |
| AN1031 | T1047 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious Process Spawned by WMI Host |
| AN1031 | T1047 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | WMIC CommandLine Process Creation Invitation |
| AN1185 | T1569.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious Child Process of Service Control Manager |
| AN1185 | T1569.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Service Controller CommandLine Creation |
| AN1252 | T1059.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Obfuscated or Encoded PowerShell CommandLine |
| AN1252 | T1059.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Unusual PowerShell Parent Process |
| AN1314 | T1204 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Office Application Spawning Living-off-the-Land Binaries |
| AN1314 | T1204 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Archiver Spawning Scripting Hosts or Command Shells |
| AN1357 | T1559 | Sysmon / Security Logs | Sysmon / Security | Anomalous Named Pipe Creation |
| AN1357 | T1559 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious COM Execution Registration |
| AN1393 | T1559.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Office Application Spawning Shell via DDE |
| AN1393 | T1559.002 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Registry Modification Enabling DDE Execution |
| AN1428 | T1059 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious Script Execution CommandLine |
| AN1428 | T1059 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Unusual Script Host Parent Process |
| AN1465 | T1106 | Sysmon EID 7 (image_load) | Microsoft-Windows-Sysmon/Operational | Hook Evasion via Non-Standard System DLL Load |
| AN1465 | T1106 | Sysmon EID 10 (process_access) | Microsoft-Windows-Sysmon/Operational | Process Access Handle for Direct Syscalls |
| ANxxxx | T1505.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious Process Spawning from Web Server Parent |

### EXFILTRATION (23 Rules)

| Rule ID | Technique | Log Source Required | Target Channel | Title |
|---|---|---|---|---|
| AN0212 | T1011 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | WiFi or Secondary Network Interface Configuration via CLI |
| AN0212 | T1011 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Bluetooth Device Connection or Configuration |
| AN0342 | T1052 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Archive File Creation on Removable Media |
| AN0342 | T1052 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | CLI Copy to Removable Drive |
| AN0367 | T1048 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Outbound Alternative Protocol Exfiltration via CLI |
| AN0367 | T1048 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | CLI Alternative Protocol Utility Execution |
| AN0436 | T1567.004 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Outbound Data Exfiltration via Webhooks |
| AN0436 | T1567.004 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Webhook Exfiltration Command Execution |
| AN0616 | T1052.001 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | File Copy to USB Storage via CLI |
| AN0616 | T1052.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | CLI Copy Command Targeting Removable Media |
| AN0787 | T1567.003 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Outbound Data Exfiltration to Paste Sites via CLI |
| AN0787 | T1567.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Paste Site Exfiltration Command Execution |
| AN0895 | T1567.001 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Outbound Data Exfiltration to Code Repository via CLI |
| AN0895 | T1567.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Code Repository Exfiltration Command Execution |
| AN1113 | T1020 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Automated Archiving and Staging via CLI |
| AN1113 | T1020 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Automated Staging Directory Archive Creation |
| AN1118 | T1029 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Scheduled File Transfer via CLI |
| AN1118 | T1029 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Scheduled Task Staging File Creation |
| AN1389 | T1048.001 | Sysmon EID 7 (image_load) | Microsoft-Windows-Sysmon/Operational | Cryptographic DLL Loaded by Scripting Host |
| AN1389 | T1048.001 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Outbound Encrypted File Upload |
| AN1413 | T1048.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Exfiltration - Asymmetric Encryption of Data Archive |
| AN1531 | T1011.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Exfiltration - Bluetooth File Transfer Wizard Execution |
| AN1571 | T1567.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Exfiltration - Command-Line Cloud Storage Sync Execution |

### IMPACT (61 Rules)

| Rule ID | Technique | Log Source Required | Target Channel | Title |
|---|---|---|---|---|
| AN0061 | T1489 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Stopping or Disabling Critical System Services via CLI |
| AN0061 | T1489 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Stopping or Disabling Critical System Services via PowerShell Script Block |
| AN0080 | T1496.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Execution of Bandwidth Hijacking or Proxyjacking Software via CLI |
| AN0080 | T1496.002 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Execution of Bandwidth Hijacking or Proxyjacking Software via Network Connection |
| AN0162 | T1565 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Database or Log File Modification by Non-Database Process via File Event |
| AN0162 | T1565 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Database or Log File Modification by Non-Database Process via CLI |
| AN0229 | T1491.001 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Registry Modification for System Logon Defacement via Registry Set |
| AN0229 | T1491.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Registry Modification for System Logon Defacement via CLI |
| AN0334 | T1531 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | User Account Access Removal via CLI |
| AN0334 | T1531 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | User Account Access Removal via PowerShell Script Block |
| AN0384 | T1561 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Disk Wiping and Partition Destruction Utilities via CLI |
| AN0384 | T1561 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Disk Wiping and Partition Destruction Utilities via PowerShell Script Block |
| AN0411 | T1485 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | File Wiping or Volume Shadow Copy Deletion via CLI |
| AN0411 | T1485 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | File Wiping or Volume Shadow Copy Deletion via PowerShell Script Block |
| AN0474 | T1495 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Boot Configuration Tampering via CLI |
| AN0474 | T1495 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Boot Configuration Tampering via PowerShell Script Block |
| AN0489 | T1499.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Potential Endpoint Service Exhaustion Flood Tool Execution via CLI |
| AN0489 | T1499.002 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Potential Endpoint Service Exhaustion Flood Tool Execution via Network Connection |
| AN0555 | T1565.001 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Stored Office Document Modification by Scripting Host via File Event |
| AN0555 | T1565.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Stored Office Document Modification by Scripting Host via CLI |
| AN0584 | T1499 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Endpoint CPU or Memory Stressing Execution |
| AN0584 | T1499 | System (7045, 7036) | system | Windows Service Unexpected Termination |
| AN0602 | T1486 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Ransom Note File Drop |
| AN0602 | T1486 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Suspicious Wiping/Encryption File Extensions |
| AN0602 | T1486 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Volume Shadow Copy Deletion via Native Utilities |
| AN0662 | T1491 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Static Web Page Modification by Non-Webserver Process |
| AN0662 | T1491 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Logon Warning Banner Registry Modification |
| AN0702 | T1565.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | MitM and Redirection Tool Execution |
| AN0702 | T1565.002 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Hosts File Tampering or Static DNS Routing Modification |
| AN0741 | T1496 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Cryptomining Utility Process Execution |
| AN0741 | T1496 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Outbound Network Connection to Cryptomining Stratum Pools |
| AN0827 | T1561.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Raw Physical Drive Access Command Line |
| AN0827 | T1561.002 | Sysmon / Security Logs | Sysmon / Security | Unauthorized Raw Disk Partition Access |
| AN0850 | T1499.004 | System (7045, 7036) | system | SCM Event Log Service Crash Loop |
| AN0850 | T1499.004 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Exploit Framework Induced Denial of Service Execution |
| AN0882 | T1561.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Bulk Content Wiping Utilities Command Line |
| AN0882 | T1561.001 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | EldoS RawDisk Driver Registration |
| AN0933 | T1490 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Backup Catalog and Shadow Copy Deletion |
| AN0933 | T1490 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Recovery Environment Disabling via PowerShell |
| AN0969 | T1498.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Network Flooding Tools Execution |
| AN0969 | T1498.001 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Scripting Process Outbound Connection Burst |
| AN1008 | T1667 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | High Frequency SMTP Tool Execution |
| AN1008 | T1667 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Outbound Mail Connection Burst |
| AN1012 | T1499.001 | System (7045, 7036) | system | Windows Resource Exhaustion Diagnosis Event |
| AN1012 | T1499.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | High Thread Spawning Utilities Execution |
| AN1097 | T1565.003 | Sysmon EID 10 (process_access) | Microsoft-Windows-Sysmon/Operational | Code Injection into Transaction Applications |
| AN1097 | T1565.003 | Sysmon EID 8 (create_remote_thread) | Microsoft-Windows-Sysmon/Operational | Remote Thread Creation in Transaction Application Processes |
| AN1140 | T1498.002 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Scripting Process Outbound DNS or NTP Connection Burst |
| AN1140 | T1498.002 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Outbound Connections to Amplification Ports |
| AN1165 | T1499.003 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | High Connection Burst to Web Server Port |
| AN1165 | T1499.003 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | High Connection Burst to Database Server Port |
| AN1361 | T1657 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Point-of-Sale RAM Scraper Process Creation |
| AN1361 | T1657 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Transaction Database File Manipulation |
| AN1434 | T1498 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Denial of Service Script Engine Execution |
| AN1434 | T1498 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Denial of Service Custom Executables |
| AN1489 | T1496.001 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Persistent Miner Service Registration |
| AN1489 | T1496.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Scheduled Task Creation for Mining Tasks |
| AN1538 | T1529 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Local System Shutdown/Reboot Invocations |
| AN1538 | T1529 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Remote System Shutdown Invocations |
| AN1622 | T1491.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | CDN or External Hosting Update Command Line |
| AN1622 | T1491.002 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Local DNS Server Zone File Modification |

### INITIAL-ACCESS (29 Rules)

| Rule ID | Technique | Log Source Required | Target Channel | Title |
|---|---|---|---|---|
| AN0021 | T1195.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Supply Chain Tampering - Suspicious Process Spawned by Development Tool via CLI |
| AN0021 | T1195.001 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Supply Chain Tampering - Suspicious Process Spawned by Development Tool via PowerShell Script Block |
| AN0188 | T1566 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Phishing - Suspicious Child Process Spawned by Mail Client |
| AN0188 | T1566 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Phishing - Suspicious File Attachment Written by Mail Client |
| AN0219 | T1190 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Exploit Public-Facing Application - Suspicious Child Process of Web Server |
| AN0219 | T1190 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Exploit Public-Facing Application - Outbound Network Connection from Web Server |
| AN0298 | T1566.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Spearphishing Link - Browser Spawned by Mail/Chat App with Suspicious URL |
| AN0298 | T1566.002 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Spearphishing Link - Script Block executing Email Link Parser |
| AN0320 | T1566.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Spearphishing via Service - Suspicious Child Process Spawned by Browser or Chat Application |
| AN0320 | T1566.003 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Spearphishing via Service - Suspicious Script Block executing Browser-Downloaded Content |
| AN0498 | T1189 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Drive-by Compromise - Suspicious Child Process Spawned by Browser |
| AN0498 | T1189 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Drive-by Compromise - PowerShell Script Block executing from Web Browser Parent |
| AN0655 | T1566.001 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Spearphishing Attachment - Dangerous File Written by Mail Client |
| AN0655 | T1566.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Spearphishing Attachment - Execution of Process from Mail Attachment Cache |
| AN0841 | T1091 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Removable Media - Execution of Script or Command from Removable Drive |
| AN0841 | T1091 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Removable Media - Suspicious Script Block executing from Removable Drive |
| AN0862 | T1195.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Software Supply Chain - Installer Spawning Suspicious Child Process |
| AN0862 | T1195.002 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Software Supply Chain - Installer Writing Suspicious File |
| AN0992 | T1659 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Content Injection - Unauthorized Process Writing Web Content |
| AN0992 | T1659 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Content Injection - Execution of Web Server Configuration Tool |
| AN1004 | T1133 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | External Remote Services - Suspicious Command Execution Post-Remote Logon |
| AN1004 | T1133 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | External Remote Services - Successful Remote Logon Event |
| AN1035 | T1195.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Hardware Supply Chain - Firmware Flashing Tool Execution |
| AN1035 | T1195.003 | Sysmon EID 6 (driver_load) | Microsoft-Windows-Sysmon/Operational | Hardware Supply Chain - Firmware Flashing Driver Load |
| AN1344 | T1199 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Trusted Relationship Abuse - Anomalous Third-Party Administrative Logon |
| AN1476 | T1669 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Wi-Fi Network Anomalies - Wireless Profile Query |
| AN1476 | T1669 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Wi-Fi Network Anomalies - Wireless Profile Query via Script Block |
| AN1480 | T1195 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Supply Chain Compromise - Installer Executing Anomalous Shell |
| AN1480 | T1195 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Supply Chain Compromise - Installer Spawned Script Block |

### LATERAL-MOVEMENT (32 Rules)

| Rule ID | Technique | Log Source Required | Target Channel | Title |
|---|---|---|---|---|
| AN0147 | T1566.002 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Lateral Movement - Script Host Initiating Outbound SMTP Connection |
| AN0147 | T1566.002 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Internal Spearphishing via PowerShell Script |
| AN0216 | T1563.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | RDP Session Hijacking via tscon.exe |
| AN0216 | T1563.002 | System (7045, 7036) | system | RDP Session Hijacking via Service Creation |
| AN0327 | T1210 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Lateral Movement - Windows Service Spawning Suspicious Shell |
| AN0327 | T1210 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Windows Service Service Account PowerShell Execution |
| AN0504 | T1021.005 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious VNC Server Binary Execution |
| AN0504 | T1021.005 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | VNC Network Connection on Default Port |
| AN0516 | T1570 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Lateral Tool Transfer to Administrative Shares |
| AN0516 | T1570 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | File Copy to Administrative Shares |
| AN0623 | T1072 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Lateral Movement - Deployment Agent Spawning Suspicious Shell |
| AN0623 | T1072 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Software Deployment Agent Activity in Script Block |
| AN0750 | T1021 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Lateral Movement - Post-Logon Administrative Process Execution |
| AN0750 | T1021 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Remote Logon Session Creation |
| AN0791 | T1021.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Lateral Movement - DCOM Server Spawning Suspicious Shell |
| AN0791 | T1021.003 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | DCOM Configuration Modification |
| AN0931 | T1021.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Lateral Movement - Command Execution in RDP Session |
| AN0931 | T1021.001 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Command Execution in RDP Session via PowerShell Script |
| AN0954 | T1550 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Alternate Authentication Material - Logon Type 9 |
| AN0954 | T1550 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Runas with Netonly Flag |
| AN1000 | T1550.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Pass the Ticket Kerberos Command Line |
| AN1000 | T1550.003 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Pass the Ticket Kerberos Authentication Activity |
| AN1144 | T1550.002 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Lateral Movement - NTLM Pass the Hash Detection |
| AN1144 | T1550.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | LSASS Process Access for Credential Replay |
| AN1298 | T1080 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Tainted Content Dropped on Shared Storage |
| AN1298 | T1080 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Executable Run from Shared Storage |
| AN1313 | T1021.006 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Lateral Movement - WinRM Host Spawning Command Shell |
| AN1313 | T1021.006 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | WinRM Remote Command Execution in Script Block |
| AN1468 | T1021.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Lateral Movement - Suspicious Service Executable Spawned by Services.exe |
| AN1468 | T1021.002 | System (7045, 7036) | system | Lateral Movement - Service Installation of Suspicious Service Executable |
| AN1620 | T1563.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | RDP Session Hijacking via tscon |
| AN1620 | T1563.002 | System (7045, 7036) | system | RDP Session Hijacking via Service Creation |

### PERSISTENCE (49 Rules)

| Rule ID | Technique | Log Source Required | Target Channel | Title |
|---|---|---|---|---|
| AN0006 | T1136.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Domain Account Creation via CLI |
| AN0006 | T1136.002 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Domain Account Creation Event ID 4720 |
| AN0045 | T1668 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Exclusive Control via Service Termination or Self-Patching |
| AN0045 | T1668 | System (7045, 7036) | system | Exclusive Control Service State Change |
| AN0085 | T1137.003 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AN0085 - Office Application Startup: Outlook Forms |
| AN0085 | T1137.003 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AN0085 - Office Application Startup: Outlook Forms (OCSF) |
| AN0123 | T1176.001 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AN0123 - Software Extensions: Browser Extensions |
| AN0123 | T1176.001 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AN0123 - Software Extensions: Browser Extensions (OCSF) |
| AN0137 | T1137.006 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Malicious Office Add-in Registry Persistence |
| AN0137 | T1137.006 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Malicious Office Add-in Drop for Persistence |
| AN0184 | T1505.004 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Malicious IIS Module or ISAPI Filter Installation |
| AN0184 | T1505.004 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Malicious IIS Component File Drop |
| AN0251 | T1176 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AN0251 - Generic Software Extensions |
| AN0251 | T1176 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AN0251 - Generic Software Extensions (OCSF) |
| AN0263 | T1137.005 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AN0263 - Office Application Startup: Outlook Rules |
| AN0263 | T1137.005 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AN0263 - Office Application Startup: Outlook Rules (OCSF) |
| AN0287 | T1556.002 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Suspicious LSA Authentication Package Modification via Registry Set |
| AN0287 | T1556.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious LSA Authentication Package Modification via CLI |
| AN0472 | T1505.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AN0472 - Server Software Component: Transport Agent |
| AN0472 | T1505.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AN0472 - Server Software Component: Transport Agent (OCSF) |
| AN0502 | T1137.004 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AN0502 - Office Application Startup: Outlook Home Page |
| AN0502 | T1137.004 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AN0502 - Office Application Startup: Outlook Home Page (OCSF) |
| AN0595 | T1505.005 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AN0595 - Server Software Component: Terminal Services DLL |
| AN0595 | T1505.005 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AN0595 - Server Software Component: Terminal Services DLL (OCSF) |
| AN0781 | T1112 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Registry Modification via CLI |
| AN0781 | T1112 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Registry Modification of System Security Configurations |
| AN0880 | T1137.002 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AN0880 - Office Application Startup: Office Test |
| AN0880 | T1137.002 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AN0880 - Office Application Startup: Office Test (OCSF) |
| AN0949 | T1554 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | AN0949 - Compromise Host Software Binary |
| AN0949 | T1554 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | AN0949 - Compromise Host Software Binary (OCSF) |
| AN1116 | T1137 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AN1116 - Generic Office Application Startup |
| AN1116 | T1137 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AN1116 - Generic Office Application Startup (OCSF) |
| AN1174 | T1653 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AN1174 - Power Settings |
| AN1174 | T1653 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AN1174 - Power Settings (OCSF) |
| AN1235 | T1136.001 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | AN1235 - Create Account: Local Account |
| AN1235 | T1136.001 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | AN1235 - Create Account: Local Account (OCSF) |
| AN1436 | T1137.001 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | AN1436 - Office Application Startup: Office Template Macros |
| AN1436 | T1137.001 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | AN1436 - Office Application Startup: Office Template Macros (OCSF) |
| AN1507 | T1505 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AN1507 - Generic Server Software Component |
| AN1507 | T1505 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | AN1507 - Generic Server Software Component (OCSF) |
| AN1548 | T1176.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AN1548 - Software Extensions: IDE Extensions |
| AN1548 | T1176.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AN1548 - Software Extensions: IDE Extensions (OCSF) |
| AN1604 | T1136 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AN1604 - Generic Create Account |
| AN1604 | T1136 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AN1604 - Generic Create Account (OCSF) |
| AN2098 | T1197 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | BITS Job Transfer or Notification Command Abuse |
| AN2112 | T1037 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | User Logon Initialization Script Registry Modification |
| AN2114 | T1098 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Privileged Account or Group Membership Manipulation |
| AN2121 | T1542 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | System Firmware or BIOS Flash Utility Execution |
| ANxxxx | T1505.003 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Web Shell File Creation |

### PRIVILEGE-ESCALATION (44 Rules)

| Rule ID | Technique | Log Source Required | Target Channel | Title |
|---|---|---|---|---|
| AN0009 | T1574.007 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Environment PATH Variable Modification via CLI |
| AN0009 | T1574.007 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Environment PATH Variable Modification via Registry |
| AN0024 | T1546 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | WMI Event Subscription Creation via CLI |
| AN0024 | T1546 | Sysmon EID 20/21 (wmi_event) | Microsoft-Windows-Sysmon/Operational | WMI Event Subscription Event Registration |
| AN0051 | T1546.011 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Application Shim Database Installation |
| AN0051 | T1546.011 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Application Shim Database File Creation |
| AN0074 | T1547.012 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Custom Print Processor Installation via CLI |
| AN0074 | T1547.012 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Custom Print Processor Registry Modification |
| AN0094 | T1546.008 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Accessibility Features Abuse Detection |
| AN0094 | T1546.008 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Accessibility Features Registry Debugger Configuration |
| AN0108 | T1574.005 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Elevated Execution from Weak Permissions Installer Directory |
| AN0108 | T1574.005 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Weak Permission Directory Executable File Write |
| AN0170 | T1546.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Change Default File Association via CLI |
| AN0170 | T1546.001 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | File Association Registry Modification |
| AN0176 | T1574.009 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Creation of Service with Unquoted Binary Path via CLI |
| AN0176 | T1574.009 | System (7045, 7036) | system | Service Installation of Unquoted Binary Path |
| AN0258 | T1053.005 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Creation of Scheduled Task via CLI |
| AN0258 | T1053.005 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | Scheduled Task Configuration File Creation |
| AN0383 | T1134.005 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | SID-History Injection |
| AN0577 | T1574.001 | Sysmon EID 7 (image_load) | Microsoft-Windows-Sysmon/Operational | DLL Side-Loading Image Load |
| AN0577 | T1574.001 | Sysmon EID 11 (file_event) | Microsoft-Windows-Sysmon/Operational | DLL Side-Loading File Drop |
| AN0590 | T1078.002 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Domain Administrator Logon on Workstation |
| AN0590 | T1078.002 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Domain Administrator Network Connection |
| AN0609 | T1574 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Service Execution Flow Hijacking via CLI |
| AN0609 | T1574 | Sysmon EID 13 (registry_set) | Microsoft-Windows-Sysmon/Operational | Image File Execution Options Debugger Hijack |
| AN0755 | T1484 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Command-Line Domain Trust or Policy Modification |
| AN0755 | T1484 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Domain Trust or Policy Modification via Script Block |
| AN0786 | T1134 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious Privilege Escalation via Token Manipulation |
| AN0834 | T1222.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious File and Directory Permissions Modification |
| AN0834 | T1222.001 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Permissions Modification via Script Block |
| AN0854 | T1484.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Command-Line Group Policy Modification |
| AN0854 | T1484.001 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | Group Policy Modification via Script Block |
| AN1108 | T1505.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AN1108 - Server Software Component: Web Shell |
| AN1108 | T1505.003 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | AN1108 - Server Software Component: Web Shell (OCSF) |
| AN1137 | T1078.003 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Local Administrator Network Logon |
| AN1137 | T1078.003 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Local Administrator Network Connection |
| AN1253 | T1134.002 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Privilege Escalation via CreateProcessWithToken |
| AN1283 | T1078.001 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Default Account Remote Logon |
| AN1283 | T1078.001 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Default Account Network Connection |
| AN1324 | T1134.001 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Token Impersonation / Theft |
| AN1375 | T1134.003 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Make and Impersonate Token (NewCredentials Logon) |
| AN1419 | T1068 | Sysmon EID 6 (driver_load) | Microsoft-Windows-Sysmon/Operational | Known Vulnerable Driver Loaded (BYOVD) |
| AN1543 | T1078 | Security (4624, 4625, 4648, 4688, 4703, 4738, etc.) | security | Anomalous Administrative Account Logon |
| AN1543 | T1078 | Sysmon EID 3 (network_connection) | Microsoft-Windows-Sysmon/Operational | Anomalous Administrative Account Network Connection |

### RECONNAISSANCE (14 Rules)

| Rule ID | Technique | Log Source Required | Target Channel | Title |
|---|---|---|---|---|
| AN2067 | T1592 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Suspicious System Information Gathering |
| AN2069 | T1594 | Sysmon / Security Logs | Sysmon / Security | Rapid Web Path Discovery from Single Source |
| AN2070 | T1595 | Sysmon / Security Logs | Sysmon / Security | External Port Scanning Detection |
| AN2073 | T1598 | Sysmon / Security Logs | Sysmon / Security | Phishing for Information |
| AN2075 | T1682 | Sysmon / Security Logs | Sysmon / Security | Outbound Data Upload to Public GenAI Services |
| ANxxxx | T1592 | PowerShell operational logs | Microsoft-Windows-PowerShell/Operational (EID 4104) | PowerShell System Information Gathering via WMI/CIM |
| ANxxxx | T1592 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | Registry System Information Query |
| ANxxxx | T1592 | Sysmon EID 1 (process_creation) | Microsoft-Windows-Sysmon/Operational | WMI Command Line System Information Gathering |
| ANxxxx | T1594 | Sysmon / Security Logs | Sysmon / Security | Web Path Discovery in CDN Access Logs |
| ANxxxx | T1595 | Sysmon / Security Logs | Sysmon / Security | Distributed External Port Scanning |
| ANxxxx | T1595 | Sysmon / Security Logs | Sysmon / Security | Low-and-Slow Active Scanning |
| ANxxxx | T1598 | Sysmon / Security Logs | Sysmon / Security | Phishing for Information from Compromised Internal Account |
| ANxxxx | T1682 | Sysmon / Security Logs | Sysmon / Security | Connection to Unlisted Public GenAI Services |
| ANxxxx | T1682 | Sysmon / Security Logs | Sysmon / Security | Outbound Secret Leakage to GenAI Services via Decrypted SSL |

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

*Document Version: 2.0 (Automated Build)*
