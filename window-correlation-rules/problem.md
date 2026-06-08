# OCSF Field Verification & Mapping Discrepancies

This document tracks inconsistencies and discrepancies identified when validating the OCSF-Normalized rules against the `Copy of WIndowsSec OCSF mappings.xlsx` spreadsheet.

---

## ⚠️ Actionable Issue: Non-Standard OCSF Fields
These rules use `process.parent_process.file.path` to denote the parent process executable. Under OCSF standards (specifically for `process_activity`, class `1007`), parent process attributes belong to the `actor.process` object.
*   **Fix**: Update these to standard OCSF `actor.process.file.path`.

| File Path | Non-Standard Field Used | Recommended Standard Field |
| :--- | :--- | :--- |
| [AN0637-T1104-DET0228.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/command-and-control/AN0637-T1104-DET0228.md) | `process.parent_process.file.path` | `actor.process.file.path` |
| [AN0209-T1059.005-DET0076.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/execution/AN0209-T1059.005-DET0076.md) | `process.parent_process.file.path` | `actor.process.file.path` |
| [AN0278-T1059.011-DET0101.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/execution/AN0278-T1059.011-DET0101.md) | `process.parent_process.file.path` | `actor.process.file.path` |
| [AN0550-T1127.002-DET0191.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/execution/AN0550-T1127.002-DET0191.md) | `process.parent_process.file.path` | `actor.process.file.path` |
| [AN1113-T1020-DET0397.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/exfiltration/AN1113-T1020-DET0397.md) | `process.parent_process.file.path` | `actor.process.file.path` |
| [AN1118-T1029-DET0399.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/exfiltration/AN1118-T1029-DET0399.md) | `process.parent_process.file.path` | `actor.process.file.path` |
| [AN0094-T1546.008-DET0042.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/privilege-escalation/AN0094-T1546.008-DET0042.md) | `process.parent_process.file.path` | `actor.process.file.path` |
| [AN0975-T1548-DET0345.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/privilege-escalation/AN0975-T1548-DET0345.md) | `process.parent_process.file.path` | `actor.process.file.path` |

---

## ℹ️ Information: Standard OCSF Fields Missing from Excel
These fields are completely standard in OCSF but are not mapped in `Copy of WIndowsSec OCSF mappings.xlsx` because the Excel sheet contains only subset events (Authentication/Logon, basic Process Creation, and basic registry/system activity).
*   **Action**: No immediate action required; these are necessary for detecting respective techniques (File, Library, DNS, or Parent Process).

| File Path | Field (Not in Excel) | OCSF Category / Log Source |
| :--- | :--- | :--- |
| [AN0130-T1114.001-DET0047.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/collection/AN0130-T1114.001-DET0047.md) | `file.path`, `file.name` | File Access (Outlook PST/OST) |
| [AN0137-T1137.006-DET0050.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/persistence/AN0137-T1137.006-DET0050.md) | `file.path`, `file.name` | File Creation (Office Add-in drop) |
| [AN0037-T1217-DET0013.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/discovery/AN0037-T1217-DET0013.md) | `file.path`, `file.name` | File Access (Browser Bookmarks) |
| [AN0342-T1052-DET0123.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/exfiltration/AN0342-T1052-DET0123.md) | `file.path`, `file.name` | File Activity (USB / Exfiltration) |
| [AN0616-T1052.001-DET0220.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/exfiltration/AN0616-T1052.001-DET0220.md) | `file.path` | File Activity (USB / Exfiltration) |
| [AN1298-T1080-DET0471.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/lateral-movement/AN1298-T1080-DET0471.md) | `file.path`, `file.name` | File Creation (Shared App Files) |
| [AN0162-T1565-DET0162.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/impact/AN0162-T1565-DET0162.md) | `file.name` | File Activity (Data Destruction) |
| [AN0555-T1565.001-DET0555.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/impact/AN0555-T1565.001-DET0555.md) | `file.name` | File Activity (Data Destruction) |
| [AN0158-T1102.001-DET0058.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/command-and-control/AN0158-T1102.001-DET0058.md) | `dns_query.name` | DNS Query (Sysmon Event ID 22) |
| [AN0728-T1568.003-DET0262.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/command-and-control/AN0728-T1568.003-DET0262.md) | `dns_query.type` | DNS Query (Sysmon Event ID 22) |
| [AN0400-T1573.001-DET0143.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/command-and-control/AN0400-T1573.001-DET0143.md) | `library.file.path` | Library Load (Sysmon Event ID 7) |
| [AN0643-T1553.002-DET0230.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/defense-impairment/AN0643-T1553.002-DET0230.md) | `library.file.path`, `library.file.signature.status` | Library Load (Sysmon Event ID 7) |
| [AN0052-T1129-DET0018.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/execution/AN0052-T1129-DET0018.md) | `library.file.path`, `library.file.signature.status` | Library Load (Sysmon Event ID 7) |
| [AN1389-T1048.001-DET0503.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/exfiltration/AN1389-T1048.001-DET0503.md) | `library.file.path` | Library Load (Sysmon Event ID 7) |
| [AN0677-T1213.006-DET0242.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/collection/AN0677-T1213.006-DET0242.md) | `actor.process.file.path` | Parent Process Image (Sysmon Event 1) |
| [AN0320-T1566.003-DET0115.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/initial-access/AN0320-T1566.003-DET0115.md) | `actor.process.file.path` | Parent Process Image (Sysmon Event 1) |
| [AN0045-T1668-DET0015.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/persistence/AN0045-T1668-DET0015.md) | `actor.process.file.path` | Parent Process Image (Sysmon Event 1) |
| [AN0071-T1218.015-DET0025.md](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/stealth/AN0071-T1218.015-DET0025.md) | `actor.process.file.path` | Parent Process Image (Sysmon Event 1) |

---

## 📈 Summary of Working Rules (Statistics)

Below is the execution status breakdown of the **88 total generated rule files**:

### Scenario A: Real-World OCSF Environment (Standard Compliance)
*   **Working Rules**: **80 / 88 (90.9%)**
    *   *62 Rules* match Excel perfectly.
    *   *18 Rules* use valid, standard OCSF fields (File, Library, DNS, Actor) that are missing from the Excel mapping sheet, but fully supported by standard OCSF SIEM/EDR platforms.
*   **Problematic Rules**: **8 / 88 (9.1%)**
    *   *8 Rules* use the non-standard field `process.parent_process.file.path`. They will require a quick update to `actor.process.file.path` to be standard-compliant.

### Scenario B: Strict Validation Against the Provided Excel Mapping Sheet Only
*   **Passing Rules**: **62 / 88 (70.5%)**
    *   These rules contain exclusively OCSF fields listed in the `Copy of WIndowsSec OCSF mappings.xlsx` sheet.
*   **failing Rules**: **26 / 88 (29.5%)**
    *   These contain fields that are not in the Excel sheet (8 non-standard fields + 18 standard fields that are unmapped).
