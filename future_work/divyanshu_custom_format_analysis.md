# Analysis of Custom Sigma Extensions (Divyanshu's Format)

## Overview
This document serves as a reference for the custom Sigma rule formats shared by Divyanshu (saved in `divyanshu_sigma_extensions.yml`). These extensions upgrade traditional Sigma from simple, single-event pattern matching into an advanced, stateful correlation engine.

## What's Different from Standard Sigma?
* **Standard Sigma (Current Rules):** Looks at a **single snapshot in time**. For example, *"Alert if you see someone running `powershell.exe -enc`."* The problem is that IT admins run encoded PowerShell all the time, which causes tons of false positives.
* **Custom Format (New Rules):** Looks at a **sequence of events over time**. His rules say, *"Alert if you see PowerShell run, AND THEN within 15 minutes they touch LSASS, AND THEN they talk to a firewall C2 port."* 

## Why This Helps (The Benefits)
This new format directly addresses our biggest issue: **alert fatigue and false positives**. 
By shifting from "catching a tool" to "catching a behavior sequence," we can easily filter out benign IT activity. An IT admin might run PowerShell, but an IT admin will *never* run PowerShell, dump credentials, and beacon out to an external IP in the span of 15 minutes. This format alerts on the full hacker behavior, not just a single command.

### Key Custom Blocks Introduced:
1. **Sequential Kill Chains (`sequence`, `stages`):** Tracks multi-stage attacks over time across a single entity (like a computer or user).
2. **Cross-Platform Correlation (`correlation`, `join`):** Joins two completely different log sources (e.g., CrowdStrike endpoint logs + Palo Alto network logs) to build highly confident alerts.
3. **Distinct Aggregations (`aggregation: distinct_count`):** Counts unique values instead of raw logs to catch "Fan-Out" behavior like network scanning.
4. **Explicit Thresholds & Burst Detection (`threshold`, `rate`):** Catches high-velocity automated attacks like brute-forcing or DDoS attempts.

## Potential Challenges / Problems to Watch Out For
When we are ready to implement this in the future, we need to solve two major hurdles:
1. **Breaks Standard Converters:** Standard Sigma uses open-source tools (like `sigmac` or `sigma-cli`) to instantly translate YAML into SIEM queries (like Splunk or Elastic). Because this is a custom format, standard converters will throw errors. We will have to build a custom parser script to translate these advanced blocks into native SIEM queries.
2. **SIEM Performance Strain:** Joining different log sources together and looking back over large time windows is computationally "expensive." If we write too many of these complex correlation rules without optimizing them, it can significantly slow down the SIEM backend's performance.
