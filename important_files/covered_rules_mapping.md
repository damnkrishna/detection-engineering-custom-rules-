# Comprehensive Sigma Rule Coverage Mapping

This document provides a comprehensive mapping of all internal Sigma rules to the executive security capabilities. Unlike the executive summary which only cites examples, this document lists all applicable rules for each capability based on MITRE ATT&CK tactics and techniques. For extremely broad categories (like Behavioural Detection), a representative subset is shown.

## Behavioural detection & prevention (Partial)
**Description/Targeting:** Continuous process telemetry, MITRE ATT&CK-mapped rules, real-time blocking of anomalous behaviour chains

**Applicable Sigma Rules (Showing 10 representative rules out of 450+):**
- `AN0006-T1136.002-DET0003`
- `AN0009-T1574.007-DET0004`
- `AN0016-T1482-DET0007`
- `AN0021-T1195.001-DET0009`
- `AN0024-T1546-DET0033`
- `AN0037-T1217-DET0013`
- `AN0040-T1074-DET0014`
- `AN0045-T1668-DET0015`
- `AN0048-T1518.001-DET0016`
- `AN0051-T1546.011-DET0017`
- *...and hundreds more covering every MITRE tactic.*

---

## Fileless & in-memory attack prevention (Partial)
**Description/Targeting:** AMSI integration, reflective DLL injection detection, process hollowing, living-off-the land (LOLBAS) blocking

**Applicable Sigma Rules (35 total):**
- `AN0071-T1218.015-DET0025`
- `AN0091-T1564.001-DET0032`
- `AN0113-T1070.009-DET0040`
- `AN0118-T1218.012-DET0042`
- `AN0139-T1564.012-DET0051`
- `AN0182-T1564.011-DET0067`
- `AN0277-T1055.004-DET0100`
- `AN0297-T1055.002-DET0106`
- `AN0608-T1055.011-DET0217`
- `AN0822-T1055.003-DET0295`
- `AN0941-T1055.015-DET0331`
- `AN1076-T1055.012-DET0382`
- `AN1095-T1055.001-DET0389`
- `AN1289-T1055.005-DET0467`
- `AN1399-T1055-DET0508`
- `AN1501-T1055.013-DET0544`
- `AN2098-T1197-DET0955`
- `AN2099-T1140-DET0956`
- `AN2100-T1202-DET0957`
- `AN2101-T1216-DET0958`
- `AN2102-T1220-DET0959`
- `AN2105-T1036-DET0962`
- `AN2106-T1027-DET0963`
- `AN2108-T1001-DET0965`
- `AN2109-T1006-DET0966`
- `AN2111-T1014-DET0968`
- `AN2117-T1211-DET0974`
- `AN2119-T1221-DET0976`
- `AN2120-T1480-DET0977`
- `AN2122-T1620-DET0979`
- `AN2124-T1665-DET0981`
- `AN2125-T1674-DET0982`
- `AN2126-T1678-DET0983`
- `AN2127-T1679-DET0984`
- `AN8079-T1055-DET8079`

---

## Ransomware detection, rollback & vaccination (Partial)
**Description/Targeting:** Canary file detonation, shadow copy protection, automated rollback of encrypted files, decoy-based deception

**Applicable Sigma Rules (32 total):**
- `AN0061-T1489-DET0021`
- `AN0080-T1496.002-DET0028`
- `AN0162-T1565-DET0162`
- `AN0229-T1491.001-DET0082`
- `AN0334-T1531-DET0334`
- `AN0384-T1561-DET0384`
- `AN0411-T1485-DET0146`
- `AN0474-T1495-DET0167`
- `AN0489-T1499.002-DET0173`
- `AN0555-T1565.001-DET0555`
- `AN0584-T1499-DET0208`
- `AN0602-T1486-DET0215`
- `AN0662-T1491-DET0238`
- `AN0702-T1565.002-DET0254`
- `AN0741-T1496-DET0267`
- `AN0827-T1561.002-DET0297`
- `AN0850-T1499.004-DET0304`
- `AN0882-T1561.001-DET0316`
- `AN0933-T1490-DET0329`
- `AN0969-T1498.001-DET0343`
- `AN1008-T1667-DET0355`
- `AN1012-T1499.001-DET0356`
- `AN1097-T1565.003-DET0391`
- `AN1140-T1498.002-DET0408`
- `AN1165-T1499.003-DET0415`
- `AN1361-T1657-DET0495`
- `AN1434-T1498-DET0518`
- `AN1489-T1496.001-DET0540`
- `AN1538-T1529-DET0559`
- `AN1622-T1491.002-DET0590`
- `AN8031-T1486-DET8031`
- `AN8077-T1490-DET8077`

---

## Script-based attack detection (Partial)
**Description/Targeting:** PowerShell, WScript, Bash, Python, VBA, macro analysis — AMSI hooks at runtime, obfuscation deobfuscation engine

**Applicable Sigma Rules (12 total):**
- `AN0172-T1059.006-DET0063`
- `AN0209-T1059.005-DET0076`
- `AN0278-T1059.011-DET0101`
- `AN0578-T1059.003-DET0202`
- `AN0733-T1059.007-DET0264`
- `AN0942-T1059.010-DET0332`
- `AN1252-T1059.001-DET0455`
- `AN1428-T1059-DET0516`
- `AN1501-T1055.013-DET0544`
- `AN8046-T1059-DET8046`
- `AN8069-T1059.001-DET8069`
- `AN8083-T1059-DET8083`

---

## USB & removable device control (Partial)
**Description/Targeting:** Per-device allow/block/read-only, vendor/serial granularity, audit trail, remote exception workflow, encrypted USB enforcement

**Applicable Sigma Rules (4 total):**
- `AN0342-T1052-DET0123`
- `AN0616-T1052.001-DET0220`
- `AN0841-T1091-DET0301`
- `AN8078-T1091-DET8078`

---

## Agent tamper protection (Partial)
**Description/Targeting:** Kernel-level self-protection, anti-uninstall, driver protection, rollback-resistant agent updates, health heartbeat

**Applicable Sigma Rules (30 total):**
- `AN0061-T1489-DET0021`
- `AN0153-T1553.004-DET0056`
- `AN0323-T1688-DET0116`
- `AN0406-T1686-DET0145`
- `AN0535-T1685.001-DET0187`
- `AN0543-T1556.006-DET0190`
- `AN0643-T1553.002-DET0230`
- `AN0712-T1553.005-DET0257`
- `AN0755-T1484-DET0270`
- `AN0757-T1556.001-DET0271`
- `AN0770-T1207-DET0276`
- `AN0781-T1112-DET0280`
- `AN0814-T1556.007-DET0293`
- `AN0834-T1222-DET0299`
- `AN0854-T1484.001-DET0305`
- `AN0868-T1685.003-DET0311`
- `AN0995-T1689-DET0350`
- `AN1177-T1222.001-DET0418`
- `AN1222-T1553.003-DET0442`
- `AN1246-T1553-DET0452`
- `AN1259-T1484.002-DET0458`
- `AN1303-T1556.002-DET0472`
- `AN1369-T1685-DET0497`
- `AN1446-T1553.006-DET0523`
- `AN1472-T1685.005-DET0532`
- `AN1557-T1690-DET0563`
- `AN1598-T1556.008-DET0580`
- `AN1621-T1556.005-DET0589`
- `AN2038-T1687-DET0900`
- `AN2043-T1686.003-DET0901`

---

## Deep telemetry (process, file, network, registry) (Covered)
**Description/Targeting:** Full process tree, file create/modify/delete, network socket, registry change — 30–90 day searchable history

**Applicable Sigma Rules (2 total):**
- `AN0130-T1114.001-DET0047`
- `AN0240-T1518.002-DET0088`

---

## Server EDR (Windows + Linux) (Partial)
**Description/Targeting:** Lightweight kernel sensor for servers, workload-aware tuning, container/VM visibility, privileged process monitoring

**Applicable Sigma Rules (1 total):**
- `AN0219-T1190-DET0080`

---

## Credential dumping prevention (Partial)
**Description/Targeting:** LSASS access monitoring, mimikatz/DCSync/pass-the-hash/pass-the-ticket detection, NTLM relay blocking

**Applicable Sigma Rules (20 total):**
- `AN0105-T1555.003-DET0037`
- `AN0235-T1003.002-DET0085`
- `AN0287-T1556-DET0104`
- `AN0292-T1110.002-DET0105`
- `AN0316-T1558.004-DET0113`
- `AN0378-T1555.004-DET0134`
- `AN0405-T1558.001-DET0144`
- `AN0420-T1606.002-DET0148`
- `AN0444-T1558.003-DET0157`
- `AN0451-T1621-DET0160`
- `AN2103-T1552-DET0960`
- `AN2104-T1187-DET0961`
- `AN2107-T1539-DET0964`
- `AN2115-T1111-DET0972`
- `AN2118-T1212-DET0975`
- `AN2123-T1649-DET0980`
- `AN2128-T1684-DET0985`
- `AN8016-T1110-DET8016`
- `AN8055-T1558-DET8055`
- `AN8071-T0000-DET8071`

---

## Privilege escalation detection (Partial)
**Description/Targeting:** Token impersonation, UAC bypass, sudo abuse, SeDebugPrivilege misuse, scheduled task privilege abuse alerts

**Applicable Sigma Rules (30 total):**
- `AN0024-T1546-DET0033`
- `AN0051-T1546.011-DET0017`
- `AN0074-T1547.012-DET0029`
- `AN0094-T1546.008-DET0042`
- `AN0170-T1546.001-DET0061`
- `AN0277-T1055.004-DET0100`
- `AN0297-T1055.002-DET0106`
- `AN0383-T1134.005-DET0136`
- `AN0590-T1078.002-DET0210`
- `AN0608-T1055.011-DET0217`
- `AN0614-T1611-DET0219`
- `AN0786-T1134-DET0283`
- `AN0822-T1055.003-DET0295`
- `AN0941-T1055.015-DET0331`
- `AN0975-T1548-DET0345`
- `AN1076-T1055.012-DET0382`
- `AN1094-T1548.002-DET0388`
- `AN1095-T1055.001-DET0389`
- `AN1137-T1078.003-DET0360`
- `AN1253-T1134.002-DET0456`
- `AN1283-T1078.001-DET0350`
- `AN1289-T1055.005-DET0467`
- `AN1324-T1134.001-DET0482`
- `AN1351-T1134.004-DET0489`
- `AN1375-T1134.003-DET0498`
- `AN1399-T1055-DET0508`
- `AN1419-T1068-DET0514`
- `AN1501-T1055.013-DET0544`
- `AN1543-T1078-DET0380`
- `AN8060-T1548-DET8060`

---

## Identity threat detection & response (ITDR) (Partial)
**Description/Targeting:** AD/Entra anomaly detection, golden/silver ticket attacks, Kerberoasting, brute force, impossible travel alerts

**Applicable Sigma Rules (1 total):**
- `AN0405-T1558.001-DET0144`

---

## Privileged access management (PAM) integration (Partial)
**Description/Targeting:** Just-in-time privilege, admin account monitoring, privileged session recording, lateral movement from admin accounts

**Applicable Sigma Rules (2 total):**
- `AN0327-T1210-DET0118`
- `AN8015-T1021-DET8015`

---

## Service account & NHI monitoring (Partial)
**Description/Targeting:** Non-human identity (API keys, service accounts, tokens) anomaly detection, over privileged account alerts

**Applicable Sigma Rules (17 total):**
- `AN0383-T1134.005-DET0136`
- `AN0590-T1078.002-DET0210`
- `AN0786-T1134-DET0283`
- `AN1137-T1078.003-DET0360`
- `AN1253-T1134.002-DET0456`
- `AN1283-T1078.001-DET0350`
- `AN1324-T1134.001-DET0482`
- `AN1351-T1134.004-DET0489`
- `AN1375-T1134.003-DET0498`
- `AN1543-T1078-DET0380`
- `AN8062-T1078-DET8062`
- `AN8092-T1078-DET8092`
- `AN8098-T1078-DET8098`
- `AN8104-T1078-DET8104`
- `AN8105-T1134.004-DET8105`
- `AN8106-T1078.003-DET8106`
- `AN8109-T1078-DET8109`

---

## C2 & beacon detection (Partial)
**Description/Targeting:** DNS tunnelling, DGA domain detection, HTTPS C2 decryption, periodic beacon pattern analysis, encrypted C2 over TOR/CDN

**Applicable Sigma Rules (54 total):**
- `AN0100-T1102.002-DET0035`
- `AN0109-T1568-DET0039`
- `AN0158-T1102.001-DET0058`
- `AN0165-T1105-DET0060`
- `AN0400-T1573.001-DET0143`
- `AN0633-T1571-DET0227`
- `AN0637-T1104-DET0228`
- `AN0714-T1219.002-DET0259`
- `AN0728-T1568.003-DET0262`
- `AN2110-T1008-DET0967`
- `AN2113-T1092-DET0970`
- `AN2116-T1132-DET0973`
- `AN8001-T1071-DET8001`
- `AN8002-T1071-DET8002`
- `AN8003-T1572-DET8003`
- `AN8004-T1095-DET8004`
- `AN8005-T1095-DET8005`
- `AN8006-T1071-DET8006`
- `AN8007-T1568-DET8007`
- `AN8008-T1090-DET8008`
- `AN8009-T1071-DET8009`
- `AN8010-T1568-DET8010`
- `AN8011-T1071-DET8011`
- `AN8012-T1071-DET8012`
- `AN8013-T1205-DET8013`
- `AN8028-T1071.004-DET8028`
- `AN8029-T1071.004-DET8029`
- `AN8032-T0000-DET8032`
- `AN8034-T0000-DET8034`
- `AN8035-T1071.004-DET8035`
- `AN8037-T1071.001-DET8037`
- `AN8038-T1071-DET8038`
- `AN8068-T0000-DET8068`
- `AN8081-T1105-DET8081`
- `AN8083-T1059-DET8083`
- `AN8091-T1572-DET8091`
- `AN8093-T1568-DET8093`
- `AN8097-T1003-DET8097`
- `AN8099-T1568.002-DET8099`
- `AN8110-T1071-DET8110`
- `AN8112-T1568.002-DET8112`
- `CR0100_T1071_`
- `CR0101_T1071_`
- `CR0102_T1572_`
- `CR0103_T1095_`
- `CR0104_T1095_`
- `CR0105_T1071_`
- `CR0106_T1568_`
- `CR0107_T1090_`
- `CR0108_T1071_`
- `CR0109_T1568_`
- `CR0110_T1071_`
- `CR0111_T1071_`
- `CR0112_T1205_`

---

## Lateral movement detection (Covered)
**Description/Targeting:** SMB/WMI/RDP anomaly, pass-the-hash spread, network share enumeration, service installation across hosts

**Applicable Sigma Rules (52 total):**
- `AN0147-T1534-DET0054`
- `AN0216-T1563-DET0079`
- `AN0327-T1210-DET0118`
- `AN0504-T1021.005-DET0178`
- `AN0516-T1570-DET0183`
- `AN0623-T1072-DET0223`
- `AN0750-T1021-DET0269`
- `AN0791-T1021.003-DET0285`
- `AN0931-T1021.001-DET0327`
- `AN0954-T1550-DET0338`
- `AN1000-T1550.003-DET0352`
- `AN1144-T1550.002-DET0409`
- `AN1298-T1080-DET0471`
- `AN1313-T1021.006-DET0477`
- `AN1468-T1021.002-DET0530`
- `AN1620-T1563.002-DET0588`
- `AN8014-T1021-DET8014`
- `AN8015-T1021-DET8015`
- `AN8017-T1021-DET8017`
- `AN8018-T1021-DET8018`
- `AN8019-T1021-DET8019`
- `AN8020-T1550-DET8020`
- `AN8021-T1021-DET8021`
- `AN8022-T1563-DET8022`
- `AN8023-T1021-DET8023`
- `AN8024-T1021-DET8024`
- `AN8025-T1021-DET8025`
- `AN8026-T1021-DET8026`
- `AN8027-T1021-DET8027`
- `AN8030-T1210-DET8030`
- `AN8041-T1210-DET8041`
- `AN8042-T1210-DET8042`
- `AN8054-T1550-DET8054`
- `AN8056-T1558-DET8056`
- `AN8059-T0000-DET8059`
- `AN8086-T1003-DET8086`
- `AN8104-T1078-DET8104`
- `AN8111-T1021-DET8111`
- `CR0087_T1021_`
- `CR0088_T1021_`
- `CR0089_T1110_`
- `CR0090_T1021_`
- `CR0091_T1021_`
- `CR0092_T1021_`
- `CR0093_T1550_`
- `CR0094_T1021_`
- `CR0095_T1563_`
- `CR0096_T1021_`
- `CR0097_T1021_`
- `CR0098_T1021_`
- `CR0099_T1021_`
- `CR0113_T1021_`

---

## Network traffic analysis (NDR/NTA) (Partial)
**Description/Targeting:** East-west traffic baselining, protocol anomaly, data exfiltration detection, IoT/OT/unmanaged host visibility

**Applicable Sigma Rules (31 total):**
- `AN0436-T1567.004-DET0153`
- `AN1511-T1567-DET0548`
- `AN2064-T1589-DET0921`
- `AN2065-T1590-DET0922`
- `AN2066-T1591-DET0923`
- `AN2067-T1592-DET0924`
- `AN2068-T1593-DET0925`
- `AN2069-T1594-DET0926`
- `AN2070-T1595-DET0927`
- `AN2071-T1596-DET0928`
- `AN2072-T1597-DET0929`
- `AN2073-T1598-DET0930`
- `AN2074-T1681-DET0931`
- `AN2075-T1682-DET0932`
- `AN2080-T1046-DET0937`
- `AN8033-T1046-DET8033`
- `AN8047-T0000-DET8047`
- `AN8048-T0000-DET8048`
- `AN8049-T0000-DET8049`
- `AN8073-T0000-DET8073`
- `AN8113-T1046-DET8113`
- `AN8114-T1595-DET8114`
- `AN8115-T1595-DET8115`
- `AN8116-T1595-DET8116`
- `AN8117-T1595-DET8117`
- `AN8118-T1595-DET8118`
- `AN8119-T1594-DET8119`
- `AN8120-T1594-DET8120`
- `AN8121-T1594-DET8121`
- `AN8122-T1594-DET8122`
- `AN8123-T1590-DET8123`

---

## Web reputation & URL filtering (Partial)
**Description/Targeting:** Real-time URL categorisation, drive-by download blocking, typosquatting/lookalike domain alerts, SSL inspection

**Applicable Sigma Rules (1 total):**
- `AN0498-T1189-DET0176`

---

## Anti-phishing & BEC detection (Partial)
**Description/Targeting:** Display name spoofing, lookalike domain detection, executive impersonation alerts, vendor email compromise

**Applicable Sigma Rules (4 total):**
- `AN0188-T1566-DET0070`
- `AN0298-T1566.002-DET0107`
- `AN0320-T1566.003-DET0115`
- `AN0655-T1566.001-DET0236`

---

## Mailbox takeover detection (Partial)
**Description/Targeting:** Behavioural baseline per user, anomalous forwarding rule alerts, impossible travel logins, OAuth token abuse

**Applicable Sigma Rules (4 total):**
- `AN0130-T1114.001-DET0047`
- `AN0131-T1114.002-DET0048`
- `AN1309-T1114-DET0476`
- `AN1589-T1114.003-DET0576`

---

## Endpoint DLP (print, copy, USB, screenshot) (Partial)
**Description/Targeting:** Block/alert on sensitive data copy to USB, print, clipboard, screenshot — policy by label, content, or user group

**Applicable Sigma Rules (19 total):**
- `AN0212-T1011-DET0077`
- `AN0342-T1052-DET0123`
- `AN0367-T1048-DET0131`
- `AN0423-T1048.003-DET0149`
- `AN0436-T1567.004-DET0153`
- `AN0531-T1119-DET0186`
- `AN0596-T1030-DET0213`
- `AN0616-T1052.001-DET0220`
- `AN0787-T1567.003-DET0284`
- `AN0895-T1567.001-DET0318`
- `AN0965-T1115-DET0341`
- `AN0988-T1041-DET0348`
- `AN1113-T1020-DET0397`
- `AN1118-T1029-DET0399`
- `AN1389-T1048.001-DET0503`
- `AN1413-T1048.002-DET0512`
- `AN1511-T1567-DET0548`
- `AN1531-T1011.001-DET0554`
- `AN1571-T1567.002-DET0570`

---

## Insider threat detection (Partial)
**Description/Targeting:** User behaviour analytics (UEBA), mass download/deletion alerts, after-hours access anomalies, resignation-pattern triggers

**Applicable Sigma Rules (31 total):**
- `AN0061-T1489-DET0021`
- `AN0080-T1496.002-DET0028`
- `AN0162-T1565-DET0162`
- `AN0229-T1491.001-DET0082`
- `AN0334-T1531-DET0334`
- `AN0384-T1561-DET0384`
- `AN0411-T1485-DET0146`
- `AN0474-T1495-DET0167`
- `AN0489-T1499.002-DET0173`
- `AN0555-T1565.001-DET0555`
- `AN0584-T1499-DET0208`
- `AN0602-T1486-DET0215`
- `AN0662-T1491-DET0238`
- `AN0702-T1565.002-DET0254`
- `AN0741-T1496-DET0267`
- `AN0827-T1561.002-DET0297`
- `AN0850-T1499.004-DET0304`
- `AN0882-T1561.001-DET0316`
- `AN0933-T1490-DET0329`
- `AN0969-T1498.001-DET0343`
- `AN1008-T1667-DET0355`
- `AN1012-T1499.001-DET0356`
- `AN1097-T1565.003-DET0391`
- `AN1140-T1498.002-DET0408`
- `AN1165-T1499.003-DET0415`
- `AN1361-T1657-DET0495`
- `AN1434-T1498-DET0518`
- `AN1489-T1496.001-DET0540`
- `AN1538-T1529-DET0559`
- `AN1622-T1491.002-DET0590`
- `AN8077-T1490-DET8077`

---

## Deception technology & honeypots (Partial)
**Description/Targeting:** Fake credentials, decoy files, honey-tokens for tender docs and financial data — instant high-confidence attacker detection

**Applicable Sigma Rules (8 total):**
- `AN0016-T1482-DET0007`
- `AN0316-T1558.004-DET0113`
- `AN0405-T1558.001-DET0144`
- `AN0444-T1558.003-DET0157`
- `AN8055-T1558-DET8055`
- `AN8056-T1558-DET8056`
- `AN8085-T1558.004-DET8085`
- `AN8107-T1558.003-DET8107`

---

