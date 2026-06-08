# Windows OCSF-Normalized Correlation Ruleset

A comprehensive repository containing **94 custom Windows security correlation rules** mapped to both standard **Sigma** formats and the **OCSF (Open Cybersecurity Schema Framework)** schema. This ruleset is designed to bridge the gap between vendor-specific logging and industry-standard security telemetry schemas, ensuring vendor-agnostic detection engineering.

---

## 📁 Repository Structure

All rules are organized logically by their respective **MITRE ATT&CK® Tactic** folders inside the main directory:

```
window-correlation-rules/
├── ocsf_mapped_updated.csv      # Status tracking spreadsheet for all 94 analytics
├── problem.md                   # Verification report detailing schema discrepancies
├── collection/                  # Data staging, local collection, automated harvesting
├── command-and-control/         # Remote access, web service backchannels, encrypted C2
├── credential-access/           # LSASS dumping, Kerberoasting, browser credential harvesting
├── defense-impairment/          # AV tampering, logging disables, policy modification
├── discovery/                   # System/user enumeration, process/trust discovery
├── execution/                   # Scheduled tasks, shell execution, interpreter abuse
├── exfiltration/                # Data exfiltration over web/USB/alternative channels
├── impact/                      # Data destruction, system shutdowns, resource hijacking
├── initial-access/              # Phishing, initial vectors, browser-spawned threats
├── lateral-movement/            # Tool transfers, service execution, RDP hijacking
├── persistence/                 # Web modules (IIS), startup add-ins, account creation
└── stealth/                     # Indicator removal, attribute tampering, hidden artifacts
```

---

## 📄 Rule Documentation Format

Every rule file inside this repository is documented in a standardized, developer-friendly Markdown format containing four key components:

1.  **Technique Breakdown**: Explains the threat model, mechanics of the specific sub-technique, and event log requirements (e.g., Sysmon vs. Windows Security Event IDs).
2.  **Custom Sigma Rule**: A standard Windows process/file/network event detection rule, ready to be deployed or imported.
3.  **OCSF Normalized Rule**: A future-proof detection rule mapped strictly to the OCSF schema class (`process_activity`, `file_activity`, `authentication`, etc.) using standardized fields (e.g. `process.file.path`, `actor.user.name`).
4.  **Blind Spots & Tuning**: A practical operational runbook outlining:
    *   Known false positives (e.g., standard administrative scripts, updates).
    *   Specific bypasses or detection evasion techniques.
    *   Tuning and baseline advice for SOC teams.

---

## 🛠️ How to Navigate and Use

### 1. View Tactic Coverage
Each folder corresponds to a major MITRE ATT&CK tactic. Open any folder to find rules named in the following format:
`[Analytic ID]-[MITRE Technique]-[Strategy ID].md` (e.g., `AN0320-T1566.003-DET0115.md`).

### 2. Check Rule Tracker
The [ocsf_mapped_updated.csv](window-correlation-rules/ocsf_mapped_updated.csv) spreadsheet tracks the development status, log source requirements, mapping feasibility, and completion status of all 94 rules.

### 3. Read Verification Reports
The [problem.md](window-correlation-rules/problem.md) file contains a comprehensive analysis showing:
*   Standard OCSF fields used which are outside the baseline mapping sheet.
*   Areas for naming convention standardization (`process.parent_process` vs `actor.process`).

---

## 👥 Authors & Maintainers
*   **Krishna Gupta** (Detection Engineer) — Original author of the core ruleset, OCSF mapping, and structural verification.
