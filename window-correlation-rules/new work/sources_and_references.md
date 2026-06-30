# Correlation Rule Threat Intelligence & Design Reference Sources

To construct high-fidelity multi-stage correlation rules, we utilize a combination of open-source projects, endpoint telemetry frameworks, and network security rule bases. This document lists the primary sources used to design the 50+ correlation rules.

---

## 1. Attack Sequence & Chain Reference Platforms

These repositories serve as the foundation for multi-stage correlation sequencing:

* **Splunk Security Content**
  * **URL**: [github.com/splunk/security_content](https://github.com/splunk/security_content)
  * **Use Case**: Examining "Analytical Stories" to trace sequential malicious behaviors (e.g., Active Directory lateral movement progression from reconnaissance to execution).
* **Elastic Detection Rules**
  * **URL**: [github.com/elastic/detection-rules](https://github.com/elastic/detection-rules)
  * **Use Case**: Reference for timeline analysis, sliding window durations, and field join mapping logic in native correlation environments.
* **SigmaHQ**
  * **URL**: [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
  * **Use Case**: Translating baseline single-event alerts (like process spawning or registry writes) into individual stages of our correlation rules.

---

## 2. Network-Based Sensor Catalogs (Suricata & Zeek)

For stage definitions involving network alerts or network telemetry:

* **MITRE BZAR (Bro/Zeek ATT&CK-based Analytics)**
  * **URL**: [github.com/mitre-attack/bzar](https://github.com/mitre-attack/bzar)
  * **Use Case**: Mapping Zeek network logs (SMB, RPC, Kerberos) directly to specific MITRE techniques.
* **Emerging Threats (ET) Rules**
  * **URL**: [rules.emergingthreats.net](https://rules.emergingthreats.net)
  * **Use Case**: Extracting precise NIDS signature names and keywords for Suricata-based detection stages.

---

## 3. Emulation & Telemetry Validation

To confirm what signals actually appear on the host/network:

* **Atomic Red Team**
  * **URL**: [github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)
  * **Use Case**: Validating the exact telemetry (such as specific process command lines or Windows Event IDs) generated during simulated attacks.
