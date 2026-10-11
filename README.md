
# Detection Engineering Login Failure Lab

A Python-based detection engineering lab that analyzes synthetic authentication logs and identifies suspicious login behavior.

## Project Overview

This project demonstrates basic detection engineering skills:

- Log parsing and analysis using Python
- Detection rule implementation
- Time-window and threshold-based detection
- Alert generation and severity classification
- MITRE ATT&CK mapping
- False positive / false negative analysis
- Detection rule tuning

## Detection Workflow

Synthetic Login Events (CSV)
    ↓
Python Detection Script
    ↓
Detection Rules
    ↓
Alert Results (CSV)
    ↓
Validation and Threshold Tuning

## Detection Rules

| Rule | Condition | Severity |
|---|---|---|
| Multiple Failed Logins | Same IP, at least 5 failures in 10 minutes | Medium |
| Failed Then Success | Same IP and username, at least 5 failures followed by success within 10 minutes | High |
| Possible Password Spraying | Same IP, 5 failures involving at least 5 usernames within 10 minutes | Medium |

The password spraying label is a basic heuristic, not a confirmed attack classification.

## MITRE ATT&CK

- T1110 — Brute Force
- T1110.001 — Password Guessing
- T1110.003 — Password Spraying

## How to Run

Requirements: Python 3 (standard library only).

Run from the project directory:

~~bash
python3 scripts/detect_login_failures.py
~~

The script reads:

`data/sample-login-events.csv`

And generates:

`output/alerts.csv`

## Expected Results

Using the default threshold of 5 failures within 10 minutes:

- 14 login events processed
- 3 alerts generated
- 2 Medium alerts
- 1 High alert

## Detection Tuning

The detection threshold was tested using the same synthetic dataset.

| Failure Threshold | Alerts Generated |
|---|---:|
| 2 | 4 |
| 5 | 3 |
| 6 | 0 |

Lower thresholds increase sensitivity but may cause more false positives.

Higher thresholds can miss suspicious behaviors.

The results illustrate rule behavior on this sample dataset; they do not establish real-world detection accuracy.



## Limitations

- Uses synthetic data rather than production logs
- Does not integrate with a SIEM
- IP-based thresholds can misclassify shared IP traffic
- Detection behavior depends on the configured threshold
- The first threshold crossing determines the initial Medium alert classification
- Alerts indicate suspicious patterns, not confirmed compromise

## Detection Rule Documentation

See [Detection Rule](docs/detection-rule.md) for conditions, MITRE mapping, false positive considerations, false negative considerations, and tuning ideas.

