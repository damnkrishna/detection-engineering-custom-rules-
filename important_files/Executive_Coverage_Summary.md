# Executive Detection Coverage Summary & Strategic Roadmap

**Date:** July 8, 2026
**Scope:** Review of 480 Active Correlation Rules (195 MITRE ATT&CK Parent Techniques)

## 1. Executive Summary

Our current detection engineering repository provides broad, resilient coverage across the MITRE ATT&CK lifecycle, with particularly strong capabilities in post-compromise detection (Defense Evasion and Persistence). However, a systematic analysis of our 480 correlation rules identified three strategic opportunities for program maturity: 

1. **Improving early-stage attack visibility** to catch adversaries before they establish a foothold.
2. **Reducing analyst workload** through aggressive false-positive reduction targeting standard IT administration.
3. **Increasing detection resilience** through automated validation and contextual threat intelligence.

Executing on the roadmap below will directly decrease SOC alert fatigue, lower our Mean Time to Respond (MTTR), and shift our detection posture from reactive to proactive.

---

## 2. Current Posture & Gaps

We are currently tracking **195 Parent Techniques** across our active correlation rules.

### Strategic Strengths
Our repository is highly optimized for detecting an adversary *after* they have bypassed initial defenses. 
* **Defense Evasion (295 rules):** Extensive coverage of log clearing, security tool impairment, and obfuscation.
* **Impact & Persistence (~190 rules each):** Deep visibility into registry modifications, service creation, and data destruction.

### Strategic Weaknesses
We currently rely too heavily on endpoint telemetry (process creation) at the expense of network visibility.
* **Initial Access (98 rules):** Given the volume of phishing and external exploitation, our early-stage visibility is comparatively low.
* **Network-Centric Tactics:** Exfiltration (69 rules) and Command and Control (66 rules) are our least covered tactics. 
* **Credential Access (103 rules):** Detections for advanced identity attacks (DCSync, Kerberoasting) require expansion to protect against domain-wide compromise.

---

## 3. False-Positive Analysis

A programmatic review of rule logic reveals that the vast majority of our false positives are self-inflicted by benign IT operations rather than poorly written rules. The primary drivers of SOC noise are:

1. **Generic Administrative Activity:** Baseline IT administration (e.g., mapping drives via `net use`).
2. **Software Deployment Tools:** Legitimate use of SCCM and Ansible executing encoded PowerShell.
3. **Vulnerability Scanners:** Qualys and Nessus triggering plaintext credential and discovery alerts.
4. **Certificate Management:** Legitimate PKI maintenance via `certutil`.
5. **Windows Update:** BITSadmin transfers for WSUS patching.

Addressing these specific benign activities systemically will yield the highest immediate ROI for the SOC.

---

## 4. Strategic Recommendations & Prioritization

To address our gaps and reduce alert fatigue, the following initiatives should be prioritized.

### Implementation Matrix

| Recommendation | Impact | Effort |
| :--- | :--- | :--- |
| **Global Allowlists** | High | Low |
| **Certutil & BITS Tuning** | High | Low |
| **Behavioral Constraints** | High | Medium |
| **Risk Scoring (RBA)** | Very High | Medium |
| **Threat Intelligence Integration** | Medium | Medium |
| **Detection as Code (CI/CD)** | Very High | High |

---

### Phase 1: Immediate (1–2 weeks)
*   **Global Allowlists:** Move hardcoded exclusions out of individual rules and into SIEM-level lookup tables (e.g., `approved_scanners`, `approved_deployment_hashes`).
*   **Certutil Tuning:** Filter out `certutil` activity where the parent process belongs to known MDM or PKI software.
*   **BITS Tuning:** Restrict BITSadmin alerts to interactive user sessions, excluding `SYSTEM` or service accounts.
    *   **Expected Outcome:** Reduce SOC alerts by 35–50% and immediately improve the analyst signal-to-noise ratio.

### Phase 2: Medium (1 month)
*   **Behavioral Constraints:** Pivot from deterministic string-matching (e.g., `powershell.exe -enc`) to anomalous parent-child process relationships.
*   **Risk Scoring (RBA):** Move away from binary High/Medium/Low alerts. Configure rules to add risk points to entities, only firing an alert when a threshold (e.g., 100 points in 4 hours) is crossed.
    *   **Expected Outcome:** Correlate low-confidence events into higher-confidence incidents, virtually eliminating alerts for standard administrative tasks.

### Phase 3: Long term
*   **Detection as Code (CI/CD):** Implement automated testing pipelines (e.g., Atomic Red Team) to test rules nightly against a sandbox.
*   **Threat Intelligence Integration:** Dynamically enrich triggered rules against our Threat Intelligence Platform (TIP) to auto-upgrade severity on hash/IP matches.
    *   **Expected Outcome:** Ensure SIEM schema changes or Windows updates do not silently break critical detections.

---

## 5. Success Metrics

To quantify the success of these engineering improvements, the following KPIs will be tracked post-implementation:

*   **False Positive Rate (FPR):** Percentage reduction in benign alerts closed by the SOC.
*   **Alert Volume/Day:** Total reduction in raw alerts hitting the analyst queue.
*   **Rules Requiring Manual Tuning:** Decrease in weekly requests from the SOC to modify rule logic.
*   **Mean Time To Detect (MTTD):** Faster identification of true positives due to reduced queue noise.
*   **Mean Time To Respond (MTTR):** Faster triage enabled by higher-fidelity alerting.
*   **Coverage Increase:** Measured expansion into Initial Access, C2, and Exfiltration tactics.
