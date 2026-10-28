
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

LOG_FILE = BASE_DIR / "data" / "auth_events.jsonl"
REPORT_FILE = BASE_DIR / "reports" / "security_report.json"
CASE_REPORT_FILE = BASE_DIR / "reports" / "incident_cases.json"

FAILED_LOGIN_THRESHOLD = 3
TIME_WINDOW_MINUTES = 5


def load_events(file_path):
    """Load, validate, and sort authentication events."""
    events = []

    with file_path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)

                timestamp_text = event["timestamp"]
                timestamp = datetime.fromisoformat(
                    timestamp_text.replace("Z", "+00:00")
                )

                if timestamp.tzinfo is None:
                    raise ValueError(
                        "Timestamp must include a timezone"
                    )

                if event["event_type"] not in {
                    "login_failed",
                    "login_success",
                }:
                    raise ValueError("Unsupported event type")

                for field in ("username", "source_ip", "host"):
                    if (
                        not isinstance(event.get(field), str)
                        or not event[field].strip()
                    ):
                        raise ValueError(
                            f"Missing or invalid field: {field}"
                        )

                event["_timestamp"] = timestamp
                events.append(event)

            except (
                json.JSONDecodeError,
                KeyError,
                ValueError,
                TypeError,
                AttributeError,
            ) as error:
                print(
                    f"Skipping invalid log line {line_number}: {error}"
                )

    return sorted(
        events,
        key=lambda event: event["_timestamp"],
    )


def detect_repeated_failures(events):
    """Detect repeated failures and successful logins after failures."""
    alerts = []
    failures_by_user = defaultdict(list)
    last_failure_alert_time = {}

    window = timedelta(minutes=TIME_WINDOW_MINUTES)

    for event in events:
        username = event["username"]
        timestamp = event["_timestamp"]

        # Add failed logins to this user's history.
        if event["event_type"] == "login_failed":
            failures_by_user[username].append(event)

            # Keep only failures in the current five-minute window.
            recent_failures = [
                failure
                for failure in failures_by_user[username]
                if timedelta(0)
                <= timestamp - failure["_timestamp"]
                <= window
            ]

            failures_by_user[username] = recent_failures

            # Alert once when the threshold is reached for a burst.
            last_alert_time = last_failure_alert_time.get(username)

            if (
                len(recent_failures) >= FAILED_LOGIN_THRESHOLD
                and (
                    last_alert_time is None
                    or timestamp - last_alert_time > window
                )
            ):
                alerts.append({
                    "rule": "AUTH-001",
                    "title": "Repeated Failed Logins",
                    "severity": "HIGH",
                    "username": username,
                    "source_ips": sorted({
                        failure["source_ip"]
                        for failure in recent_failures
                    }),
                    "event_count": len(recent_failures),
                    "evidence": [
                        {
                            "timestamp": failure["timestamp"],
                            "event_type": failure["event_type"],
                            "source_ip": failure["source_ip"],
                        }
                        for failure in recent_failures
                    ],
                    "recommended_action": (
                        "Review authentication records and verify "
                        "whether the activity is authorized."
                    ),
                })

                last_failure_alert_time[username] = timestamp

        # Check for a successful login after repeated failures.
        elif event["event_type"] == "login_success":
            recent_failures = [
                failure
                for failure in failures_by_user[username]
                if timedelta(0)
                <= timestamp - failure["_timestamp"]
                <= window
            ]

            if len(recent_failures) >= FAILED_LOGIN_THRESHOLD:
                alerts.append({
                    "rule": "AUTH-002",
                    "title": (
                        "Successful Login After Repeated Failures"
                    ),
                    "severity": "HIGH",
                    "username": username,
                    "source_ips": sorted({
                        failure["source_ip"]
                        for failure in recent_failures
                    } | {event["source_ip"]}),
                    "event_count": len(recent_failures) + 1,
                    "evidence": [
                        {
                            "timestamp": failure["timestamp"],
                            "event_type": failure["event_type"],
                            "source_ip": failure["source_ip"],
                        }
                        for failure in recent_failures
                    ] + [{
                        "timestamp": event["timestamp"],
                        "event_type": event["event_type"],
                        "source_ip": event["source_ip"],
                    }],
                    "recommended_action": (
                        "Investigate the login and verify the account "
                        "owner's activity before concluding compromise."
                    ),
                })

    return alerts


def build_cases(alerts):
    """Group alerts by username into investigation cases."""
    cases_by_user = {}

    for alert in alerts:
        username = alert["username"]

        if username not in cases_by_user:
            cases_by_user[username] = {
                "case_id": f"CASE-{len(cases_by_user) + 1:03d}",
                "username": username,
                "severity": alert["severity"],
                "status": "OPEN",
                "alert_count": 0,
                "alerts": [],
                "source_ips": set(),
            }

        case = cases_by_user[username]
        case["alert_count"] += 1
        case["alerts"].append(alert)
        case["source_ips"].update(alert["source_ips"])

    cases = []

    for case in cases_by_user.values():
        case["source_ips"] = sorted(case["source_ips"])
        cases.append(case)

    return cases


def save_json(file_path, data):
    """Save a Python object as a formatted JSON file."""
    file_path.parent.mkdir(parents=True, exist_ok=True)

    file_path.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )


def main():
    if not LOG_FILE.exists():
        print(f"Log file not found: {LOG_FILE}")
        return

    events = load_events(LOG_FILE)
    alerts = detect_repeated_failures(events)
    cases = build_cases(alerts)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(LOG_FILE.relative_to(BASE_DIR)),
        "total_events": len(events),
        "failed_logins": sum(
            event["event_type"] == "login_failed"
            for event in events
        ),
        "successful_logins": sum(
            event["event_type"] == "login_success"
            for event in events
        ),
        "alert_count": len(alerts),
        "case_count": len(cases),
        "alerts": alerts,
    }

    save_json(REPORT_FILE, report)
    save_json(CASE_REPORT_FILE, cases)

    print("\nSOC DETECTION REPORT")
    print("=" * 40)
    print(f"Events analyzed: {report['total_events']}")
    print(f"Failed logins: {report['failed_logins']}")
    print(f"Successful logins: {report['successful_logins']}")
    print(f"Alerts generated: {report['alert_count']}")
    print(f"Incident cases created: {report['case_count']}")

    for alert in alerts:
        print(
            f"\n[{alert['severity']}] {alert['title']} "
            f"| User: {alert['username']} "
            f"| Rule: {alert['rule']}"
        )

    print("\nINCIDENT CASES")
    print("=" * 40)

    for case in cases:
        print(
            f"{case['case_id']} "
            f"| User: {case['username']} "
            f"| Status: {case['status']} "
            f"| Alerts: {case['alert_count']}"
        )

    print(
        f"\nAlert report saved to: "
        f"{REPORT_FILE.relative_to(BASE_DIR)}"
    )
    print(
        f"Incident cases saved to: "
        f"{CASE_REPORT_FILE.relative_to(BASE_DIR)}"
    )


if __name__ == "__main__":
    main()
