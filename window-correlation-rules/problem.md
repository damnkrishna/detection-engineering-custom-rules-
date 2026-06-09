# OCSF Field Verification & Mapping Discrepancies

This document tracks inconsistencies and discrepancies identified when validating the OCSF-Normalized rules against the Copy of WIndowsSec OCSF mappings.xlsx spreadsheet.

---

## ? Actionable Issue: Strict Mapping Compliance (Resolved)
The project strictly adheres to the provided Copy of WIndowsSec OCSF mappings.xlsx spreadsheet to avoid polluting the target SIEM with rogue or unstandardized OCSF properties.

*   **Rule**: Any field that exists in the global OCSF specification (e.g. ctor.process.file.path) but DOES NOT exist in the Copy of WIndowsSec OCSF mappings.xlsx spreadsheet must be safely tucked under the unmapped.* object array until officially standardized.
*   **Fix**: All newly generated rules across execution and privilege-escalation sprints strictly implement unmapped.parent_image, unmapped.parent_cmd_line, and unmapped.granted_access rather than adopting global schemas prematurely.

---

## ? Actionable Issue: Non-Standard OCSF Fields (Fixed)
Legacy rules used process.parent_process.file.path to denote the parent process executable. Under OCSF standards (specifically for process_activity, class 1007), parent process attributes belong to the ctor.process object, which has since been pushed to unmapped.parent_image.
*   **Fix**: These have all been programmatically corrected during the sprint updates.

---

## ?? Information: Expected Unmapped Elements
The Copy of WIndowsSec OCSF mappings.xlsx is primarily geared towards Sysmon/Windows Native event generation. 
As such, any detection strategy requiring data outside this paradigm natively falls into unmapped.*:
*   **CloudTrail/AWS**: unmapped.api_operation, unmapped.resource_owner_uid
*   **Advanced Memory Manipulation**: unmapped.granted_access, unmapped.start_address
*   **Parent Execution Vectors**: unmapped.parent_image, unmapped.parent_cmd_line

---

## ?? Summary of Working Rules (Statistics)

Below is the execution status breakdown of the **179 total generated rule files**:

*   **Sprint 1 (Legacy Core)**: 151 rules successfully updated with explicit ields: arrays injected into both Sigma and OCSF configurations.
*   **Sprint 2 (Execution)**: 10 new rules written, strictly following the unmapped.* compliance mandate.
*   **Sprint 3 (Privilege Escalation)**: 18 new rules written, strictly following the unmapped.* compliance mandate.
*   **Total "Done" in Tracker**: 89 Analytics completed out of the 375 total scope.


## ?? Tracking of Unmapped OCSF Fields in Use

The following rules currently utilize unmapped.* prefix schemas because the required OCSF native fields do not explicitly exist in the Copy of WIndowsSec OCSF mappings.xlsx documentation yet. These will be formally normalized upon future updates to the standardized mapping spreadsheet.

| File Path | Unmapped Fields Used |
| :--- | :--- |
| execution/AN0172-T1059.006-DET0063.md | unmapped.parent_image |
| execution/AN0178-T1204.001-DET0066.md | unmapped.parent_image |
| execution/AN0209-T1059.005-DET0076.md | unmapped.parent_image |
| execution/AN0278-T1059.011-DET0101.md | unmapped.parent_image |
| execution/AN0550-T1127.002-DET0191.md | unmapped.parent_image |
| execution/AN0578-T1059.003-DET0202.md | unmapped.parent_image |
| execution/AN0628-T1559.001-DET0224.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0692-T1204.003-DET0248.md | unmapped.api_operation, unmapped.resource_owner_uid, unmapped.resource_type, unmapped.resource_uid |
| execution/AN0699-T1204.005-DET0252.md | unmapped.parent_image |
| execution/AN0733-T1059.007-DET0264.md | unmapped.parent_image |
| execution/AN0797-T1203-DET0287.md | unmapped.parent_image |
| execution/AN0819-T1204.002-DET0294.md | unmapped.parent_image |
| privilege-escalation/AN0277-T1055.004-DET0100.md | unmapped.granted_access, unmapped.parent_image |
| privilege-escalation/AN0297-T1055.002-DET0106.md | unmapped.parent_image, unmapped.start_address |
| privilege-escalation/AN0383-T1134.005-DET0136.md | unmapped.sid_history |
| privilege-escalation/AN0608-T1055.011-DET0217.md | unmapped.granted_access, unmapped.parent_image |
| privilege-escalation/AN0614-T1611-DET0219.md | unmapped.parent_image |
| privilege-escalation/AN0786-T1134-DET0283.md | unmapped.parent_image |
| privilege-escalation/AN0822-T1055.003-DET0295.md | unmapped.granted_access, unmapped.parent_image |
| privilege-escalation/AN0941-T1055.015-DET0331.md | unmapped.granted_access, unmapped.parent_image |
| privilege-escalation/AN1076-T1055.012-DET0382.md | unmapped.granted_access, unmapped.parent_image |
| privilege-escalation/AN1095-T1055.001-DET0389.md | unmapped.parent_image, unmapped.start_function |
| privilege-escalation/AN1253-T1134.002-DET0456.md | unmapped.parent_image |
| privilege-escalation/AN1289-T1055.005-DET0467.md | unmapped.granted_access, unmapped.parent_image |
| privilege-escalation/AN1324-T1134.001-DET0482.md | unmapped.parent_image |
| privilege-escalation/AN1351-T1134.004-DET0489.md | unmapped.parent_image |
| privilege-escalation/AN1375-T1134.003-DET0498.md | unmapped.process_name |
| privilege-escalation/AN1399-T1055-DET0508.md | unmapped.parent_image |
| privilege-escalation/AN1501-T1055.013-DET0544.md | unmapped.hashes |

