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
| collection/AN0040-T1074-DET0014.md | unmapped.parent_cmd_line, unmapped.parent_image |
| collection/AN0131-T1114.002-DET0048.md | unmapped.parent_cmd_line, unmapped.parent_image |
| collection/AN0531-T1119-DET0186.md | unmapped.parent_cmd_line, unmapped.parent_image |
| collection/AN0677-T1213.006-DET0242.md | unmapped.parent_cmd_line, unmapped.parent_image |
| collection/AN0724-T1074.001-DET0261.md | unmapped.parent_cmd_line, unmapped.parent_image |
| collection/AN0831-T1560.001-DET0298.md | unmapped.parent_cmd_line, unmapped.parent_image |
| collection/AN0965-T1115-DET0341.md | unmapped.parent_cmd_line, unmapped.parent_image |
| collection/AN0980-T1113-DET0346.md | unmapped.parent_cmd_line, unmapped.parent_image |
| collection/AN1070-T1005-DET0380.md | unmapped.parent_cmd_line, unmapped.parent_image |
| collection/AN1145-T1039-DET0410.md | unmapped.parent_cmd_line, unmapped.parent_image |
| collection/AN1160-T1213-DET0413.md | unmapped.parent_cmd_line, unmapped.parent_image |
| collection/AN1213-T1560.003-DET0438.md | unmapped.parent_cmd_line, unmapped.parent_image |
| collection/AN1309-T1114-DET0476.md | unmapped.parent_cmd_line, unmapped.parent_image |
| collection/AN1410-T1025-DET0511.md | unmapped.parent_cmd_line, unmapped.parent_image |
| collection/AN1458-T1560-DET0526.md | unmapped.parent_cmd_line, unmapped.parent_image |
| collection/AN1589-T1114.003-DET0576.md | unmapped.parent_cmd_line, unmapped.parent_image |
| command-and-control/AN0109-T1568-DET0039.md | unmapped.parent_image |
| command-and-control/AN0165-T1105-DET0060.md | unmapped.parent_cmd_line, unmapped.parent_image |
| command-and-control/AN0637-T1104-DET0228.md | unmapped.parent_image |
| command-and-control/AN0714-T1219.002-DET0259.md | unmapped.parent_cmd_line, unmapped.parent_image |
| credential-access/AN0105-T1555.003-DET0037.md | unmapped.parent_cmd_line, unmapped.parent_image |
| credential-access/AN0235-T1003.002-DET0085.md | unmapped.parent_cmd_line, unmapped.parent_image |
| credential-access/AN0292-T1110.002-DET0105.md | unmapped.parent_cmd_line, unmapped.parent_image |
| credential-access/AN0316-T1558.004-DET0113.md | unmapped.parent_cmd_line, unmapped.parent_image |
| credential-access/AN0378-T1555.004-DET0134.md | unmapped.parent_cmd_line, unmapped.parent_image |
| credential-access/AN0405-T1558.001-DET0144.md | unmapped.parent_cmd_line, unmapped.parent_image |
| credential-access/AN0420-T1606.002-DET0148.md | unmapped.parent_cmd_line, unmapped.parent_image |
| credential-access/AN0444-T1558.003-DET0157.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN0153-T1553.004-DET0056.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN0323-T1688-DET0116.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN0406-T1686-DET0145.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN0535-T1685.001-DET0187.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN0712-T1553.005-DET0257.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN0755-T1484-DET0270.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN0770-T1207-DET0276.md | unmapped.api_operation, unmapped.granted_access, unmapped.parent_image |
| defense-impairment/AN0781-T1112-DET0280.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN0834-T1222-DET0299.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN0854-T1484.001-DET0305.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN0868-T1685.003-DET0311.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN0995-T1689-DET0350.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN1177-T1222.001-DET0418.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN1246-T1553-DET0452.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN1369-T1685-DET0497.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN1446-T1553.006-DET0523.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN1472-T1685.005-DET0532.md | unmapped.parent_cmd_line, unmapped.parent_image |
| defense-impairment/AN2043-T1686.003-DET0901.md | unmapped.parent_cmd_line, unmapped.parent_image |
| discovery/AN0016-T1482-DET0007.md | unmapped.parent_cmd_line, unmapped.parent_image |
| discovery/AN0048-T1518.001-DET0016.md | unmapped.parent_cmd_line, unmapped.parent_image |
| discovery/AN0095-T1057-DET0034.md | unmapped.parent_cmd_line, unmapped.parent_image |
| discovery/AN0240-T1518.002-DET0088.md | unmapped.parent_cmd_line, unmapped.parent_image |
| discovery/AN0254-T1033-DET0093.md | unmapped.parent_cmd_line, unmapped.parent_image |
| discovery/AN0455-T1201-DET0161.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0009-T1574.007-DET0004.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0108-T1574.005-DET0038.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0172-T1059.006-DET0063.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0176-T1574.009-DET0064.md | unmapped.event_id, unmapped.image_path, unmapped.parent_cmd_line, unmapped.parent_image, unmapped.service_name |
| execution/AN0178-T1204.001-DET0066.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0209-T1059.005-DET0076.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0258-T1053-DET0094.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0278-T1059.011-DET0101.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0550-T1127.002-DET0191.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0578-T1059.003-DET0202.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0609-T1574-DET0218.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0628-T1559.001-DET0224.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0699-T1204.005-DET0252.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0733-T1059.007-DET0264.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0778-T1569-DET0279.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0797-T1203-DET0287.md | unmapped.parent_cmd_line, unmapped.parent_image |
| execution/AN0819-T1204.002-DET0294.md | unmapped.parent_cmd_line, unmapped.parent_image |
| exfiltration/AN0212-T1011-DET0077.md | unmapped.parent_cmd_line, unmapped.parent_image |
| exfiltration/AN1113-T1020-DET0397.md | unmapped.parent_cmd_line, unmapped.parent_image |
| exfiltration/AN1118-T1029-DET0399.md | unmapped.parent_cmd_line, unmapped.parent_image |
| exfiltration/AN1413-T1048.002-DET0512.md | unmapped.parent_cmd_line, unmapped.parent_image |
| exfiltration/AN1531-T1011.001-DET0554.md | unmapped.parent_cmd_line, unmapped.parent_image |
| exfiltration/AN1571-T1567.002-DET0570.md | unmapped.parent_cmd_line, unmapped.parent_image |
| impact/AN0061-T1489-DET0021.md | unmapped.parent_cmd_line, unmapped.parent_image |
| impact/AN0080-T1496.002-DET0028.md | unmapped.parent_cmd_line, unmapped.parent_image |
| impact/AN0229-T1491.001-DET0082.md | unmapped.parent_image |
| impact/AN0334-T1531-DET0334.md | unmapped.parent_cmd_line, unmapped.parent_image |
| impact/AN0384-T1561-DET0384.md | unmapped.parent_cmd_line, unmapped.parent_image |
| impact/AN0411-T1485-DET0146.md | unmapped.parent_cmd_line, unmapped.parent_image |
| impact/AN0474-T1495-DET0167.md | unmapped.parent_cmd_line, unmapped.parent_image |
| impact/AN0489-T1499.002-DET0173.md | unmapped.parent_cmd_line, unmapped.parent_image |
| initial-access/AN0021-T1195.001-DET0009.md | unmapped.parent_cmd_line, unmapped.parent_image |
| initial-access/AN0188-T1566-DET0070.md | unmapped.parent_cmd_line, unmapped.parent_image |
| initial-access/AN0219-T1190-DET0080.md | unmapped.parent_cmd_line, unmapped.parent_image |
| initial-access/AN0298-T1566.002-DET0107.md | unmapped.parent_cmd_line, unmapped.parent_image |
| initial-access/AN0320-T1566.003-DET0115.md | unmapped.parent_cmd_line, unmapped.parent_image |
| initial-access/AN0498-T1189-DET0176.md | unmapped.parent_cmd_line, unmapped.parent_image |
| initial-access/AN0841-T1091-DET0301.md | unmapped.parent_cmd_line, unmapped.parent_image |
| initial-access/AN0862-T1195.002-DET0309.md | unmapped.parent_cmd_line, unmapped.parent_image |
| initial-access/AN1004-T1133-DET0354.md | unmapped.parent_cmd_line, unmapped.parent_image |
| initial-access/AN1035-T1195.003-DET0368.md | unmapped.driver_path, unmapped.parent_cmd_line, unmapped.parent_image |
| initial-access/AN1476-T1669-DET0536.md | unmapped.parent_cmd_line, unmapped.parent_image |
| initial-access/AN1480-T1195-DET0537.md | unmapped.parent_cmd_line, unmapped.parent_image |
| lateral-movement/AN0216-T1563-DET0079.md | unmapped.event_id, unmapped.image_path, unmapped.parent_cmd_line, unmapped.parent_image, unmapped.service_name |
| lateral-movement/AN0327-T1210-DET0118.md | unmapped.parent_cmd_line, unmapped.parent_image |
| lateral-movement/AN0504-T1021.005-DET0178.md | unmapped.parent_cmd_line, unmapped.parent_image |
| lateral-movement/AN0516-T1570-DET0183.md | unmapped.parent_cmd_line, unmapped.parent_image |
| lateral-movement/AN0623-T1072-DET0223.md | unmapped.parent_cmd_line, unmapped.parent_image |
| lateral-movement/AN0750-T1021-DET0269.md | unmapped.event_id, unmapped.logon_type, unmapped.parent_cmd_line, unmapped.parent_image |
| lateral-movement/AN0791-T1021.003-DET0285.md | unmapped.parent_cmd_line, unmapped.parent_image |
| lateral-movement/AN0931-T1021.001-DET0327.md | unmapped.parent_cmd_line, unmapped.parent_image |
| lateral-movement/AN1313-T1021.006-DET0477.md | unmapped.parent_cmd_line, unmapped.parent_image |
| lateral-movement/AN1468-T1021.002-DET0530.md | unmapped.event_id, unmapped.image_path, unmapped.parent_cmd_line, unmapped.parent_image, unmapped.service_name |
| lateral-movement/AN1620-T1563.002-DET0588.md | unmapped.event_id, unmapped.image_path, unmapped.parent_cmd_line, unmapped.parent_image, unmapped.service_name |
| persistence/AN0006-T1136.002-DET0003.md | unmapped.parent_cmd_line, unmapped.parent_image |
| persistence/AN0045-T1668-DET0015.md | unmapped.event_id, unmapped.parent_cmd_line, unmapped.parent_image |
| persistence/AN0085-T1137.003-DET0029.md | unmapped.api_operation, unmapped.granted_access, unmapped.parent_image |
| persistence/AN0123-T1176.001-DET0044.md | unmapped.api_operation, unmapped.granted_access, unmapped.parent_image |
| persistence/AN0184-T1505.004-DET0068.md | unmapped.parent_cmd_line, unmapped.parent_image |
| persistence/AN0251-T1176-DET0092.md | unmapped.granted_access, unmapped.parent_cmd_line, unmapped.parent_image |
| persistence/AN0263-T1137.005-DET0095.md | unmapped.api_operation, unmapped.granted_access, unmapped.parent_image |
| persistence/AN0472-T1505.002-DET0166.md | unmapped.granted_access, unmapped.parent_cmd_line, unmapped.parent_image |
| persistence/AN0502-T1137.004-DET0177.md | unmapped.api_operation, unmapped.granted_access, unmapped.parent_image |
| persistence/AN0511-T1505.001-DET0181.md | unmapped.granted_access, unmapped.parent_cmd_line, unmapped.parent_image |
| persistence/AN0595-T1505.005-DET0212.md | unmapped.api_operation, unmapped.granted_access, unmapped.parent_image |
| persistence/AN0880-T1137.002-DET0315.md | unmapped.api_operation, unmapped.granted_access, unmapped.parent_image |
| persistence/AN0949-T1554-DET0336.md | unmapped.api_operation, unmapped.granted_access, unmapped.parent_image |
| persistence/AN1108-T1505.003-DET0394.md | unmapped.api_operation, unmapped.granted_access, unmapped.parent_image |
| persistence/AN1116-T1137-DET0398.md | unmapped.api_operation, unmapped.granted_access, unmapped.parent_image |
| persistence/AN1174-T1653-DET0417.md | unmapped.granted_access, unmapped.parent_cmd_line, unmapped.parent_image |
| persistence/AN1235-T1136.001-DET0447.md | unmapped.api_operation, unmapped.granted_access, unmapped.parent_image |
| persistence/AN1436-T1137.001-DET0519.md | unmapped.api_operation, unmapped.granted_access, unmapped.parent_image |
| persistence/AN1507-T1505-DET0547.md | unmapped.api_operation, unmapped.granted_access, unmapped.parent_image |
| persistence/AN1548-T1176.002-DET0561.md | unmapped.granted_access, unmapped.parent_cmd_line, unmapped.parent_image |
| persistence/AN1604-T1136-DET0583.md | unmapped.granted_access, unmapped.parent_cmd_line, unmapped.parent_image |
| privilege-escalation/AN0024-T1546-DET0033.md | unmapped.event_id, unmapped.parent_cmd_line, unmapped.parent_image |
| privilege-escalation/AN0051-T1546.011-DET0017.md | unmapped.parent_cmd_line, unmapped.parent_image |
| privilege-escalation/AN0074-T1547.012-DET0029.md | unmapped.parent_cmd_line, unmapped.parent_image |
| privilege-escalation/AN0094-T1546.008-DET0042.md | unmapped.parent_cmd_line, unmapped.parent_image |
| privilege-escalation/AN0170-T1546.001-DET0061.md | unmapped.parent_cmd_line, unmapped.parent_image |
| privilege-escalation/AN0383-T1134.005-DET0136.md | unmapped.api_operation, unmapped.granted_access, unmapped.parent_image, unmapped.sid_history |
| privilege-escalation/AN0786-T1134-DET0283.md | unmapped.parent_cmd_line, unmapped.parent_image |
| privilege-escalation/AN0975-T1548-DET0345.md | unmapped.parent_cmd_line, unmapped.parent_image |
| privilege-escalation/AN1094-T1548.002-DET0388.md | unmapped.parent_cmd_line, unmapped.parent_image |
| privilege-escalation/AN1253-T1134.002-DET0456.md | unmapped.parent_cmd_line, unmapped.parent_image |
| privilege-escalation/AN1324-T1134.001-DET0482.md | unmapped.parent_cmd_line, unmapped.parent_image |
| privilege-escalation/AN1351-T1134.004-DET0489.md | unmapped.parent_cmd_line, unmapped.parent_image |
| privilege-escalation/AN1419-T1068-DET0514.md | unmapped.driver_path |
| privilege-escalation/AN1501-T1055.013-DET0544.md | unmapped.parent_cmd_line, unmapped.parent_image |
| stealth/AN0071-T1218.015-DET0025.md | unmapped.file_operation, unmapped.parent_cmd_line, unmapped.parent_image |
| stealth/AN0091-T1564.001-DET0032.md | unmapped.file_operation, unmapped.parent_cmd_line, unmapped.parent_image |
| stealth/AN0113-T1070.009-DET0040.md | unmapped.event_id, unmapped.parent_cmd_line, unmapped.parent_image, unmapped.registry_event_type, unmapped.task_name |
| stealth/AN0118-T1218.012-DET0042.md | unmapped.parent_cmd_line, unmapped.parent_image |
| stealth/AN0139-T1564.012-DET0051.md | unmapped.parent_cmd_line, unmapped.parent_image |
