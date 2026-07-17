# Curated Test Packs - Detection Engine Baseline

This document provides a hand-counted baseline for the Detection Engineering (DE) team. It maps open-source and benign telemetry directly to our detection rules, detailing exactly what to expect when these curated files are pushed through the replay tool.

## Rule 1: Scheduled Task Persistence
**Dataset:** `TP_T1053_Scheduled_Task.evtx` (The TP Dataset - sourced from EVTX-ATTACK-SAMPLES)
* **Target Rule:** `AN8064-T1053-DET8064` (Scheduled task or malicious service installed followed by execution)
* **Expected Behavior:** Engine should fire on the Stage 0 condition for Scheduled Task Creation.
* **Why:** This file contains Event ID 4698 (A scheduled task was created) logs and other related artifacts that match the initial persistence trigger logic of the rule.

## Rule 2: Defense Evasion (Log Clearing)
**Dataset:** `TP_T1070_Log_Cleared.evtx` (The TP Dataset - sourced from EVTX-ATTACK-SAMPLES)
* **Target Rule:** `AN8066-T0000-DET8066` (AV/EDR tampering or log clearing before malicious execution)
* **Expected Behavior:** Engine should fire on the Stage 0 condition for Log Clearing.
* **Why:** This file contains a clear Event ID 1102 (The audit log was cleared) execution, mapping directly to the defense evasion phase of the sequence.

## The Benign Baseline
**Dataset:** `benign_workstation.evtx` (The Benign Dataset - normal system telemetry)
* **Target Rule:** All Rules (including `AN8064` and `AN8066`)
* **Expected Behavior:** Engine should fire **0 times**.
* **Why:** This is normal background system traffic. A fire here indicates the engine logic is flawed or the rule conditions are too loose, leading to false positives.
