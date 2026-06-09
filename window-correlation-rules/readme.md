# Windows OCSF-Normalized Correlation Ruleset

A comprehensive repository currently containing **179 custom Windows security correlation rules** (out of an expanding scope of 375) mapped to both standard **Sigma** formats and the **OCSF (Open Cybersecurity Schema Framework)** schema. This ruleset is designed to bridge the gap between vendor-specific logging and industry-standard security telemetry schemas, ensuring vendor-agnostic detection engineering.

---

## ?? Repository Structure

All rules are organized logically by their respective **MITRE ATT&CK® Tactic** folders inside the main directory:

`
window-correlation-rules/
+-- ocsf_mapped_new_sprint.xlsx  # Status tracking spreadsheet for all 375 analytics
+-- Copy of WIndowsSec OCSF mappings.xlsx # Official reference for standardized OCSF field mappings
+-- problem.md                   # Verification report detailing schema discrepancies and unmapped usages
+-- collection/                  # Data staging, local collection, automated harvesting
+-- command-and-control/         # Remote access, web service backchannels, encrypted C2
+-- credential-access/           # LSASS dumping, Kerberoasting, browser credential harvesting
+-- defense-impairment/          # AV tampering, logging disables, policy modification
+-- discovery/                   # System/user enumeration, process/trust discovery
+-- execution/                   # Scheduled tasks, shell execution, interpreter abuse
+-- exfiltration/                # Data exfiltration over web/USB/alternative channels
+-- impact/                      # Data destruction, system shutdowns, resource hijacking
+-- initial-access/              # Phishing, initial vectors, browser-spawned threats
+-- lateral-movement/            # Tool transfers, service execution, RDP hijacking
+-- persistence/                 # Web modules (IIS), startup add-ins, account creation
+-- privilege-escalation/        # Token impersonation, process injection, kernel exploits
+-- stealth/                     # Indicator removal, attribute tampering, hidden artifacts
`

---

## ?? Rule Documentation Format

Every rule file inside this repository is documented in a standardized, developer-friendly Markdown format containing four key components:

1.  **Technique Breakdown**: Explains the threat model, mechanics of the specific sub-technique, and event log requirements (e.g., Sysmon vs. Windows Security Event IDs).
2.  **Custom Sigma Rule**: A standard Windows process/file/network event detection rule, ready to be deployed or imported. Includes an explicit ields: array mapping the detection logic to native SIEM fields.
3.  **OCSF Normalized Rule**: A future-proof detection rule mapped strictly to the OCSF schema class (process_activity, ile_activity, uthentication, etc.) using standardized fields (e.g. process.file.path, ctor.user.name). Includes an explicit ields: array. Note: fields not yet standardized internally are prefixed with unmapped.*.
4.  **Blind Spots & Tuning**: A practical operational runbook outlining:
    *   Known false positives (e.g., standard administrative scripts, updates).
    *   Specific bypasses or detection evasion techniques.
    *   Tuning and baseline advice for SOC teams.

---

## ??? How to Navigate and Use

### 1. View Tactic Coverage
Each folder corresponds to a major MITRE ATT&CK tactic. Open any folder to find rules named in the following format:
[Analytic ID]-[MITRE Technique]-[Strategy ID].md (e.g., AN0320-T1566.003-DET0115.md).

### 2. Check Rule Tracker
The ocsf_mapped_new_sprint.xlsx spreadsheet tracks the development status, log source requirements, mapping feasibility, and completion status of all 375 rules in the current sprint.

### 3. Read Verification Reports
The problem.md file contains a comprehensive analysis showing:
*   Strict compliance constraints mapping back to Copy of WIndowsSec OCSF mappings.xlsx.
*   Handling of unmapped standard OCSF fields using the unmapped.* schema structure.
*   Areas for naming convention standardization (process.parent_process vs ctor.process).

---

## ?? Authors & Maintainers
*   **Krishna Gupta** (Detection Engineer) — Original author of the core ruleset, OCSF mapping, and structural verification.
