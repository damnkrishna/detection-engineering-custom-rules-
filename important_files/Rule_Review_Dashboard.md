# Detection Engineering: Rule Review Dashboard
**Last Updated:** 2026-07-08 10:55

This dashboard provides a live, programmatic health check of our detection repository, evaluating all active rules for production readiness, noise levels, and testing validation.

---

## 📊 Repository Health

<div align="center">

| Metric | Count | Status |
| :--- | :---: | :--- |
| **Total Rules Evaluated** | **1465** | 🔵 Active |
| **Production Ready** | **453** | 🟢 Deployed & Validated |
| **Needs Tuning** | **1011** | 🟡 High False Positive Risk |
| **Needs Testing** | **1** | 🔴 Missing Validation/Tags |

</div>

---

## 🛠 Action Items & Work Queue

### 🟡 Rules Requiring Tuning (Top Contributors to Alert Fatigue)
*These rules trigger frequently on benign administrative activity or security scanners and require strict global allowlists or contextual filtering.*
- Focus Areas: `certutil.exe` execution, BITSadmin network connections, and generic `net use` drive mapping.

### 🔴 Rules Requiring Testing
*These rules are missing critical MITRE ATT&CK technique tags or lack validation against known offensive tooling (e.g., Atomic Red Team).*
- Action: Route to CI/CD pipeline for sandbox detonation and validation.

---

> **Note to Engineering Management:** 
> Our repository currently has an **31% Production Readiness** score. By addressing the tuning backlog during the next sprint, we expect to significantly reduce SOC alert volume and improve Mean Time To Detect (MTTD).
