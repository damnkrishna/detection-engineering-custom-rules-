# Correlation Rule Authoring Guide & Threat Modeling Framework

This guide establishes the **Rule Creation Chain** for designing Layer 2 Correlation Rules in their native production JSON format. It integrates community standards, threat intelligence feeds, and platform-specific research repositories into a unified workflow.

All rules in this project must be written in the **native `IR_v1` JSON format** used by the correlation engine.

---

## 1. The Reference Ecosystem (Where to look)

To build high-fidelity correlation rules, we leverage the following open-source resources:

### A. Attack Chain & Sequence Reference
*   **Splunk Security Content** (`github.com/splunk/security_content`): The primary reference for multi-stage correlation chains (Analytical Stories). If a rule description mentions a "story" (e.g., *AD Lateral Movement story*), look here to see the sequence of techniques.
*   **Elastic Detection Rules** (`github.com/elastic/detection-rules`): Excellent reference for modern, well-commented technique combinations and timeline logic.
*   **SigmaHQ** (`github.com/SigmaHQ/sigma`): The starting point for atomic detection logic. Filter by technique and log source to determine what triggers to use for individual stages.

### B. Network Sensors (Suricata & Zeek)
*   **MITRE BZAR** (`github.com/mitre-attack/bzar`): A set of Zeek scripts that map network logs (SMB, DCE/RPC) directly to MITRE ATT&CK techniques. Essential for constructing Zeek-based stages.
*   **Emerging Threats** (`rules.emergingthreats.net`): Free daily updated Suricata ruleset. Use this to find exact threat signature substrings (e.g., `MS17-010`, `EternalBlue`) for Suricata NIDS stage filters.

### C. Verification & Validation
*   **Atomic Red Team** (`github.com/redcanaryco/atomic-red-team`): Shows exactly what telemetry and process signatures are generated on the endpoint or network during a real test. Use this to determine signature keywords and appropriate correlation windows.

---

## 2. Updated Correlation Rule Workflow

We follow a continuous loop grounded in real-world attack data:

```
[1. Identify Gap / Tactic] 
         ??
[2. Read Splunk Security Story / SigmaHQ] (Define the logical sequence)
         ??
[3. Check Atomic Red Team / BZAR] (Identify the generated host/network indicators)
         ??
[4. Extract Signatures / Keywords] (Define signatureContains & tactics/techniques)
         ??
[5. Write IR_v1 JSON Rule] (Define stages, windows, and correlation keys)
```

---

## 3. Production `IR_v1` JSON Format Reference

Here is the standard schema structure for all correlation rules:

```json
{
  "ruleId": "WANNACRY_REPEATED_DNS",
  "ruleName": "Repeated WannaCry kill-switch DNS lookups \u2014 active ransomware infection confirmed",
  "ruleFormat": "IR_v1",
  "ruleType": "THRESHOLD",
  "ruleOrigin": "cep-translated",
  "description": "Repeated WannaCry kill-switch DNS lookups \u2014 active ransomware infection confirmed",
  "enabled": true,
  "version": 1,
  "correlationKey": "entity_key",
  "eventSources": [
    "suricata"
  ],
  "window": {
    "type": "sliding",
    "minSpanSeconds": 0,
    "durationSeconds": 1800
  },
  "output": {
    "tags": [],
    "message": "Repeated WannaCry kill-switch DNS lookups \u2014 active ransomware infection confirmed",
    "severity": "CRITICAL",
    "entityField": null,
    "mitreTactics": [
      "TA0011"
    ],
    "includeFields": [],
    "riskScoreDelta": 5,
    "mitreTechniques": [
      "T1071.004"
    ]
  },
  "stages": [
    {
      "stageIndex": 0,
      "match": {
        "groups": [
          {
            "groups": [],
            "operator": "OR",
            "conditions": [
              {
                "field": "signature_name",
                "value": "wannacry",
                "values": [],
                "operator": "contains"
              },
              {
                "field": "signature_name",
                "value": "iuqerfsodp9",
                "values": [],
                "operator": "contains"
              }
            ]
          }
        ],
        "operator": "AND",
        "conditions": []
      },
      "minGapMs": 0,
      "aggregate": {
        "field": null,
        "groupBy": [],
        "function": "count",
        "threshold": 2,
        "distinctField": null
      },
      "eventSources": [],
      "withinSeconds": 0,
      "minOccurrences": 0,
      "correlation_key": "host.name",
      "minDistinctCount": 0,
      "requireDistinctField": null,
      "excludeSignatureContains": []
    }
  ],
  "suppression": {
    "groupBy": [],
    "durationSeconds": 300
  },
  "maxGapSeconds": 0,
  "behavioralConstraints": null,
  "maxConcurrentInstances": 0
}
```

### Key Fields Breakdown:
- **`correlationKey`**: Set to `"entity_key"` (tracks the affected machine/entity) or `"src_ip"` / `"user_id"` depending on the correlation intent.
- **`window.durationSeconds`**: Time frame to correlate stages (e.g., `1800` for 30 minutes).
- **`stages[].match`**: Uses logical operators (`AND`/`OR`) and conditions (`contains`, `equals`) on event fields like `signature_name`.
- **`stages[].aggregate`**: Defines count thresholds (e.g., `threshold: 2` to require multiple hits).
- **`suppression.durationSeconds`**: Throttles duplicate alerts (default `300`).

---

## 4. Existing Rules Reference (Do NOT Duplicate)

We have already covered **86 correlation rules** in `message (3).txt`. Refer to [rules_coverage_summary.xlsx](file:///c:/Users/Sunil/OneDrive/Desktop/coorelation-rules/new%20work/rules_coverage_summary.xlsx) for the complete list. Do not write duplicates.
