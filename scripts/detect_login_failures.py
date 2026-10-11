
import csv
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

# Detection settings
THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=10)

# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = BASE_DIR / "data" / "sample-login-events.csv"
OUTPUT_FILE = BASE_DIR / "output" / "alerts.csv"

# Step 1: Read login logs
events = []

with INPUT_FILE.open("r", newline="", encoding="utf-8") as file:
    reader = csv.DictReader(file)

    for row in reader:
        if row["event"] != "login":
            continue

        if row["result"] not in ("failed", "success"):
            continue

        row["time"] = datetime.fromisoformat(row["timestamp"])
        events.append(row)

# Process events in time order
events.sort(key=lambda event: event["time"])

# Step 2: Prepare detection
failure_windows = defaultdict(deque)
alerts = []

for event in events:
    ip = event["source_ip"]
    username = event["username"]
    now = event["time"]

    recent_failures = failure_windows[ip]

    # Remove failures older than 10 minutes
    while recent_failures and (
        now - recent_failures[0]["time"] > TIME_WINDOW
    ):
        recent_failures.popleft()

    # Rule 1: Repeated failed logins
    if event["result"] == "failed":
        previous_count = len(recent_failures)
        recent_failures.append(event)

        if previous_count < THRESHOLD <= len(recent_failures):
            usernames = {
                item["username"] for item in recent_failures
            }

            if len(usernames) >= 5:
                detection_type = "POSSIBLE_PASSWORD_SPRAYING"
            else:
                detection_type = "MULTIPLE_FAILED_LOGINS"

            alerts.append({
                "timestamp": event["timestamp"],
                "source_ip": ip,
                "username": username if len(usernames) == 1 else "(multiple)",
                "detection_type": detection_type,
                "severity": "Medium",
                "failed_count": len(recent_failures),
            })

    # Rule 2: Failed logins followed by success
    elif event["result"] == "success":
        matching_failures = [
            item for item in recent_failures
            if item["username"] == username
        ]

        if len(matching_failures) >= THRESHOLD:
            alerts.append({
                "timestamp": event["timestamp"],
                "source_ip": ip,
                "username": username,
                "detection_type": "FAILED_THEN_SUCCESS",
                "severity": "High",
                "failed_count": len(matching_failures),
            })

# Step 3: Export detection results
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

fieldnames = [
    "timestamp",
    "source_ip",
    "username",
    "detection_type",
    "severity",
    "failed_count",
]

with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(alerts)

# Step 4: Display results
print(f"Processed {len(events)} login events.")
print(f"Generated {len(alerts)} alerts.")

for alert in alerts:
    print(
        f"[{alert['severity']}] "
        f"{alert['detection_type']} | "
        f"IP: {alert['source_ip']} | "
        f"Failed: {alert['failed_count']}"
    )

print(f"Alerts saved to: {OUTPUT_FILE}")

