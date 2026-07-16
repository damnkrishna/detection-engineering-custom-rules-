# Detection Rule Standardization Guide
**Goal:** Upgrade standard detection rule documents into self-contained "Master Documents" that serve Threat Intel, SOC Analysts, and Platform Engineering simultaneously. 

This methodology should be applied to **all** future `.md` rule files in the repository.

---

## 1. The Standard Format
Every detection rule `.md` file must contain the following core sections:
1. **Technique Breakdown & Log Source Requirements**
2. **Custom Sigma Rule**
3. **OCSF Normalized Rule**
4. **Blind Spots & Tuning (The "Problems")**
5. **Test Cases (Engine Pipeline Verification)** *(NEW)*
6. **Raw Telemetry Dataset (OCSF JSON)** *(NEW)*

## 2. Step-by-Step Implementation Guide

### Step 1: Define Human-Readable Test Cases
Do not just provide a rule; prove it works. Add a new section detailing the exact scenarios that will be tested.
* **True Positives (Full Coverage):** Write out explicit scenarios that *must* trigger the alert. Ensure every OR branch (e.g., different tools, different file paths) has a dedicated test case.
* **Benign / True Negatives:** Write out explicit scenarios that *must not* trigger the alert. Deliberately trigger the `filter_` or allowlist conditions to prove they successfully suppress benign activity.

### Step 2: Generate Raw Telemetry (JSONL)
The human-readable test cases are for analysts; the raw telemetry is for the Platform Engineering team.
* At the bottom of the `.md` file, provide the raw, OCSF-normalized events formatted as **JSONL (JSON Lines)**.
* **MANDATORY - Rule UID Mapping:** Inside the `metadata` object of every event, right after `expected_alert`, you MUST include `rule_uid`. This maps the event to the exact unique ID of the detection rule it is testing so the engine can correlate hits during replay.
* **MANDATORY - Separate Blocks:** Do not combine all events into one block. You must create two completely separate JSONL blocks:
  1. `#### Benign Telemetry` (Containing only True Negatives / expected_alert: false)
  2. `#### True Positive Telemetry` (Containing only True Positives / expected_alert: true)
* **Why:** Splitting them allows engineers to quickly pipe the benign dataset first to ensure zero false fires, and then pipe the malicious dataset to verify detection efficacy. The `rule_uid` is critical for automated validation scripts to query the SIEM/backend and prove the correct rule fired.

### Step 3: Upgrade from "Unit Test" to "Engine Stress Test"
Your dataset must test the pipeline's infrastructure, not just the rule's logic. Ensure every JSON payload includes the following engine-stress mechanics:
1. **Epoch Timestamps (`time`):** Always include an incrementing `time` field. Detection engines key their deduplication and correlation windows off time. Without it, the engine may drop the events.
2. **Schema Type Validation Failures:** Intentionally include one True Positive event where a field has the wrong data type (e.g., passing `"1"` as a string instead of an integer for `activity_id`). This tests if the JSON parser crashes or coerces gracefully.
3. **Missing Optional Blocks:** Intentionally omit an entire optional JSON object (like `unmapped`) to test parser fault tolerance.
4. **Deduplication Testing:** Include an exact duplicate of a True Positive event (same timestamp, same fields) to test if the engine correctly suppresses duplicates.
5. **Volume/Stress Testing:** Do not embed 500+ logs directly in the Markdown, as it destroys readability. Instead, add a documented instruction above the JSONL (JSON Lines) format on how to script a payload generator (e.g., replicating TP-01 500x with varying PIDs/paths) to test pipeline throughput and backpressure.

### Step 4: Rule Logic Validation
Use the act of building exact JSON test cases to scrutinize your own rule logic. 
* *Check:* Do the field names in the JSON exactly match the fields in the OCSF rule?
* *Check:* Did you forget to add a specific clause to the OCSF rule that exists in the Sigma rule (e.g., renaming evasion via `OriginalFileName`)? Fix the rule if discrepancies are found during payload generation.
