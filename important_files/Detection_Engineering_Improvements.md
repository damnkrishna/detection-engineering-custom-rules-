# Detection Engineering Improvements & Recommendations

**Date:** July 8, 2026
**Scope:** Analysis of 480 Distinct Correlation Rules (840 Total Variations)

## 1. Executive Summary

This document provides a strategic review of our current detection engineering posture based on a deep-dive analysis of our existing ~480 unique correlation rules (spanning over 800 title variations and 370+ definition files). The goal of this review is to highlight current strengths, identify coverage gaps, categorize major sources of alert fatigue (false positives), and provide actionable recommendations for immediate tuning and future maturity.

---

## 2. Current Detection Coverage & Tactic Distribution

An analysis of the MITRE ATT&CK mappings across our entire rule repository (including the JSON correlation rules in the `new work` folder and the tracking Excel sheets) shows coverage spanning **195 Parent Techniques**. 

When categorized by high-level tactic, our coverage breaks down as follows (combining alternate tag naming conventions like `defense-evasion` and `defense_evasion`):

1. **Defense Evasion (295 rules):** Extensive rules covering log clearing, security tool impairment, and obfuscation.
2. **Impact (193 rules):** Strong coverage for data destruction, ransomware behaviors, and system disruption.
3. **Persistence (192 rules):** Excellent visibility into registry run keys, scheduled tasks, and service creation.
4. **Discovery (172 rules):** Solid detection of active directory enumeration and local system profiling.
5. **Execution (153 rules):** Good coverage of script interpreters and LOLBins.
6. **Privilege Escalation (149 rules):** Coverage for token manipulation and privilege abuse.
7. **Collection (127 rules):** Detection of automated data collection and clipboard scraping.
8. **Credential Access (103 rules):** Detections for LSASS dumping, DCSync, and Kerberoasting.
9. **Lateral Movement (100 rules):** Coverage for remote service creation and WMI remote instantiation.
10. **Initial Access (98 rules):** Detection around Office macro execution and malicious attachments.
11. **Reconnaissance (75 rules):** Coverage for network and vulnerability scanning behaviors.
12. **Exfiltration (69 rules):** Detection of automated data transfers and archive creation.
13. **Command and Control (66 rules):** Network-centric detections and beaconing behavior.
14. **Defense Impairment (45 rules):** Specialized rules focusing heavily on disabling specific security agents.

> [!TIP]
> **Strength:** Our repository is highly optimized for detecting an adversary *after* they have established a foothold. We are covering **195 Parent Techniques**, with immense depth in **Defense Evasion** and **Persistence**, ensuring that quiet, long-term adversaries will likely trip multiple wires.

---

## 3. Gaps Identified

While our overall technique coverage (spanning 195 Parent Techniques) is robust, the tactic distribution above highlights areas where our defense is "bottom-heavy":

> [!WARNING]
> **Network-Centric Tactics (Exfiltration & Command and Control):** Sitting at the bottom of our coverage with only 69 and 66 rules respectively, network-centric detections are sparse. We rely too heavily on endpoint process creation rather than network connections.
>
> **Initial Access (98 rules):** Given the volume of phishing and external exploitation in modern attacks, our Initial Access coverage should ideally be higher up the list to catch adversaries before they require Defense Evasion or Persistence.

---

## 4. Top False-Positive Issues

A programmatic extraction of the `falsepositives:` fields across all rules revealed the primary drivers of alert noise. Addressing these specific categories will drastically reduce SOC fatigue:

1. **Generic Administrative Activity (100+ occurrences):** The number one cause of false positives is baseline IT administration.
2. **Software Deployment Tools (SCCM, Ansible):** Highly prevalent in triggering rules looking for encoded PowerShell commands and rapid process spawning.
3. **Vulnerability Scanners (Qualys, Nessus):** Security scanners frequently trigger rules looking for plaintext credential exposure or aggressive network discovery.
4. **Certificate Management:** Legitimate use of `certutil.exe` for certificate import/export routinely triggers credential theft and download rules.
5. **Windows Update (BITS):** Legitimate WSUS clients using BITSadmin generate noise on network transfer rules.
6. **Network Drive Mapping:** IT staff using `net use` by IP address instead of hostname triggers lateral movement alerts.

---

## 5. Recommendations for Rule Tuning

To address the false positives and improve signal-to-noise ratio, the following immediate tuning actions are recommended:

*   **Establish a Global "Known-Good" Lookup Table:** Instead of hardcoding exclusions in every rule for SCCM or Nessus, move to a SIEM-level lookup table (e.g., `approved_scanners_ip`, `approved_deployment_hashes`).
*   **Contextual Filtering for CertUtil:** Modify the `certutil` rules to explicitly filter out `ParentImage` paths belonging to known MDM or certificate management software, focusing the rule strictly on instances where the parent is `cmd.exe`, `powershell.exe`, or Microsoft Office.
*   **Enforce Hierarchy in BITS/Net Use:** Update these rules to require a secondary condition, such as triggering only if the process was spawned by an interactive user session (excluding `SYSTEM` or service accounts) unless it's a known risky parent.

---

## 6. Future Improvements

To elevate our detection engineering program to the next level of maturity, we should focus on the following strategic initiatives:

### A. Transition to Behavioral Constraints
Currently, many rules are highly deterministic (matching specific strings or filenames). We must pivot to behavioral analytics—for example, detecting *anomalous parent-child process relationships* rather than just looking for `powershell.exe -enc`.

### B. Implement Risk Scoring
Move away from binary alerts (High/Medium/Low). Implement a risk-based alerting (RBA) model where individual rules add points to a user or host entity. An alert is only fired to the SOC when the entity crosses a specific threshold (e.g., 100 points within 4 hours). This inherently solves the "Administrative Activity" false positive issue.

### C. Threat Intelligence Integration
Enrich rules dynamically. If a process execution rule triggers, it should automatically query the destination IP or file hash against our Threat Intelligence Platform (TIP). If a match is found, the severity should dynamically upgrade.

### D. Testing Automation (Detection as Code)
**Action Item:** We must implement an automated testing pipeline. Using tools like Atomic Red Team integrated into a CI/CD pipeline, every rule in this repository should be tested nightly against a sandbox to verify it still fires, ensuring that SIEM schema changes or Windows updates haven't silently broken our detections.
