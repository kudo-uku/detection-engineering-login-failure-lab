# Detection Rule: Suspicious Login Attempts

## Detection Goal

Identify suspicious authentication behavior from login events.

## Log Source

Synthetic login event CSV.

## Required Fields

- timestamp
- source_ip
- username
- event
- result

## Rule 1: Multiple Failed Logins

Condition:
- Same source_ip
- 5 or more failed logins
- Within a rolling 10-minute window

Severity: Medium

## Rule 2: Failed Logins Followed by Success

Condition:
- Same source_ip and username
- 5 or more failed logins
- Followed by a successful login
- Within a rolling 10-minute window

Severity: High

## MITRE ATT&CK Mapping

- T1110: Brute Force
- T1110.001: Password Guessing
- T1110.003: Password Spraying

Repeated failures against one account may indicate
password guessing.

Failures across many accounts from the same IP may
indicate password spraying.

Alerts are suspicious signals, not proof of compromise.

## False Positives

- Users forgetting passwords
- Shared public IP addresses
- VPN gateway traffic
- Authorized security testing

## False Negatives

- Low-frequency attacks
- Distributed attacks from multiple IPs
- Attacks outside the detection time window

## Tuning Ideas

- Adjust failure threshold
- Adjust time window
- Compare unique usernames
- Investigate successful logins after failures
- Evaluate false positives and missed detections
