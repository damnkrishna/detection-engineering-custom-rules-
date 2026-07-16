# SOAR Coverage Matrix Update Summary

This document serves as a verification record of the SOAR planning assumption updates applied to `detection_coverage_matrix_final.xlsx`.

**Planning Assumption Applied:**
> "This matrix assumes a SOAR platform is deployed and able to execute response actions across our EDR, firewall, IAM/AD, and ITSM tooling. Rows marked 'Covered – SOAR-dependent' reflect this planning assumption, not a verified current-state integration. Rows with both a detection gap and a response gap remain classified as detection gaps, since SOAR cannot act on an alert that never fires."

---

## 1. Fully Upgraded to "Covered – SOAR-dependent"
*These 5 capabilities possessed a pure response/action gap with no underlying detection/telemetry limitations.*

| Capability Name | Required SOAR Action |
| :--- | :--- |
| **Behavioural detection & prevention** | SOAR playbook: take-response-action via EDR API |
| **Endpoint isolation & network containment** | SOAR playbook: isolate-host via EDR API |
| **Live response & remote remediation** | SOAR playbook: live-response via EDR API |
| **Ransomware detection, rollback & vaccination** | SOAR playbook: isolate-host-and-restore-files via EDR API |
| **Hash-based IOC blocking** | SOAR playbook: block-hash/IOC via EDR/TIP API |

---

## 2. Kept as Detection Gaps with SOAR Side-note (Hybrid)
*These 11 capabilities have a response gap, but also suffer from a missing log or missing rule. They were kept as detection gaps because SOAR cannot orchestrate a response for an alert that never fires.*

| Capability Name | Underlying Detection Limiter |
| :--- | :--- |
| **Fileless & in-memory attack prevention** | Missing rule (EDR Platform) |
| **Script-based attack detection** | Missing log (Windows AMSI / EDR Platform) |
| **USB & removable device control** | Missing log/rule (EDR Device Control / DLP Agent) |
| **Agent tamper protection** | Missing rule (EDR Platform) |
| **Server EDR (Windows + Linux)** | Missing log (Server EDR / CWPP) |
| **Credential dumping prevention** | Missing rule (EDR Platform) |
| **MFA & conditional access enforcement** | Missing log (IAM Platform (e.g., Entra ID, Okta)) |
| **DNS security & sinkholing** | Missing log (Secure DNS Platform / NDR) |
| **DMARC / DKIM / SPF enforcement** | Missing log (Secure Email Gateway (SEG)) |
| **Outbound email DLP** | Missing log (Email DLP / Secure Email Gateway (SEG)) |
| **AI bot & GenAI application control** | Missing log (CASB / SWG) |

---

## 3. Left Completely Untouched
*These 34 capabilities were skipped because they either have no response limitation at all, or they represent an architectural gap where no sensor/agent exists for SOAR to trigger through.*

| Capability Name | Reason for Skipping / Gap Type |
| :--- | :--- |
| **Next-gen AV + ML prevention** | Tooling / Capability Gap |
| **Exploit & memory protection** | Tooling / Capability Gap |
| **Offline protection & remediation** | Tooling / Capability Gap |
| **Deep telemetry (process, file, network, registry)** | Covered |
| **Privilege escalation detection** | Missing Logs |
| **Identity threat detection & response (ITDR)** | Missing Logs |
| **Privileged access management (PAM) integration** | Tooling / Capability Gap |
| **Service account & NHI monitoring** | Missing Logs |
| **C2 & beacon detection** | Tooling / Capability Gap |
| **Lateral movement detection** | Covered |
| **Network traffic analysis (NDR/NTA)** | Tooling / Capability Gap |
| **Web reputation & URL filtering** | Tooling / Capability Gap |
| **Zero Trust network access (ZTNA)** | Tooling / Capability Gap |
| **Anti-phishing & BEC detection** | Missing Logs |
| **Attachment sandboxing & detonation** | Tooling / Capability Gap |
| **URL rewriting & time-of-click protection** | Tooling / Capability Gap |
| **Tender & financial fraud email detection** | Tooling / Capability Gap |
| **Mailbox takeover detection** | Missing Logs |
| **Automated data discovery & classification** | Tooling / Capability Gap |
| **Endpoint DLP (print, copy, USB, screenshot)** | Tooling / Capability Gap |
| **Network DLP & cloud DLP (CASB)** | Tooling / Capability Gap |
| **Data-in-transit encryption enforcement** | Tooling / Capability Gap |
| **Information rights management (IRM/MIP)** | Tooling / Capability Gap |
| **Insider threat detection** | Tooling / Capability Gap |
| **Predictive machine learning engine** | Tooling / Capability Gap |
| **Threat intelligence platform (TIP) integration** | Tooling / Capability Gap |
| **External attack surface management (EASM)** | Tooling / Capability Gap |
| **AI-assisted alert triage & investigation** | Tooling / Capability Gap |
| **Deception technology & honeypots** | Tooling / Capability Gap |
| **Cloud security posture management (CSPM)** | Tooling / Capability Gap |
| **Cloud workload protection (CWPP)** | Tooling / Capability Gap |
| **CASB — SaaS data & access control** | Missing Logs |
| **IoT/OT & agentless device discovery** | Tooling / Capability Gap |
| **CNAPP (cloud-native application protection)** | Tooling / Capability Gap |