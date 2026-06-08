# Windows Correlation Ruleset

This directory houses the **94 custom OCSF-Normalized Windows correlation rules**, categorized by their respective MITRE ATT&CK tactics.

## 📁 Tactic Directories
*   `collection/`, `command-and-control/`, `credential-access/`, `defense-impairment/`, `discovery/`, `execution/`, `exfiltration/`, `impact/`, `initial-access/`, `lateral-movement/`, `persistence/`, `privilege-escalation/`, `stealth/`

## 📄 Rule Structure
Each rule contains:
1.  **Threat Analysis**: In-depth breakdown of the MITRE technique.
2.  **Custom Sigma Rule**: Traditional query format for immediate deployment.
3.  **OCSF Normalized Rule**: Unified OCSF class format for SIEM/EDR standardization.
4.  **Tuning Runbook**: Practical instructions to address blind spots and suppress false positives.

For the status tracking index and discrepancy analysis, see the `ocsf_mapped_updated.csv` and `problem.md` files in this directory.
