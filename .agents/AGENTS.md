# Detection Engineering Rule Standardization
When working on Detection Rules (which are stored as Markdown `.md` files) across the remaining 604 rules in this repository, you MUST follow the standardized "Master Document" format.

## The Standard Operating Procedure (SOP)
The full blueprint and rationale for this standard is located at:
`important_files/rule_improvement_methodology.md`

You MUST read that methodology document before attempting to upgrade or create a new correlation rule. 

## Strict Format Requirements
Whenever you are asked to generate or format telemetry test datasets for these rules, you must strictly adhere to the following pipeline specifications:

1. **Format:** The raw telemetry must be provided in **JSONL (JSON Lines)** format, never as a single JSON array.
2. **Rule UID Injection:** Inside the `metadata` block of every single JSONL event, you MUST include `"rule_uid"` directly after `"expected_alert"`. This `rule_uid` must match the specific UUID of the detection rule it is testing.
3. **Dataset Separation:** The telemetry must be split into two separate blocks:
   * `#### Benign Telemetry` (Containing only True Negatives / expected_alert: false)
   * `#### True Positive Telemetry` (Containing only True Positives / expected_alert: true)
4. **Engine Stress Testing Mechanics:** The JSONL dataset must not just test rule logic; it must test the engine infrastructure. This includes:
   * Adding epoch `time` fields to all events.
   * Including a duplicate event test case for deduplication logic.
   * Including a malformed schema test case (e.g. string instead of int).
   * Omission of optional blocks (e.g., completely dropping `unmapped`).
