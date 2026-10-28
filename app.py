
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st
import main as detection_engine


# --------------------------------------------------
# FILE PATHS
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "data" / "auth_events.jsonl"
UPDATES_FILE = BASE_DIR / "data" / "case_updates.json"
AUDIT_FILE = BASE_DIR / "data" / "case_audit.jsonl"
REPORT_DIR = BASE_DIR / "reports"

REPORT_FILE = REPORT_DIR / "security_report.json"
CASE_REPORT_FILE = REPORT_DIR / "incident_cases.json"

CASE_STATUSES = ["OPEN", "INVESTIGATING", "CLOSED"]


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="SOC Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ SOC Detection & Incident Response Lab")
st.caption(
    "Educational security monitoring dashboard using fictional "
    "authentication logs."
)


# --------------------------------------------------
# CASE UPDATE FUNCTIONS
# --------------------------------------------------

def load_case_updates():
    """Load saved incident statuses and notes."""
    if not UPDATES_FILE.exists():
        return {}

    try:
        with UPDATES_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)

        return data if isinstance(data, dict) else {}

    except (json.JSONDecodeError, OSError):
        st.error(
            "Could not read case_updates.json. "
            "Check that the file contains valid JSON."
        )
        return {}


def save_case_updates(updates):
    """Save the latest status and notes for each case."""
    UPDATES_FILE.parent.mkdir(parents=True, exist_ok=True)

    with UPDATES_FILE.open("w", encoding="utf-8") as file:
        json.dump(updates, file, indent=2)


# --------------------------------------------------
# AUDIT TRAIL FUNCTIONS
# --------------------------------------------------

def append_audit_event(event):
    """Append an audit record without deleting previous records."""
    AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with AUDIT_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


def load_audit_events():
    """Read audit records from the JSON Lines file."""
    if not AUDIT_FILE.exists():
        return []

    events = []

    with AUDIT_FILE.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                st.warning(
                    f"Skipping invalid audit record on line {line_number}."
                )

    return events


# --------------------------------------------------
# DETECTION ENGINE
# --------------------------------------------------

def run_detection():
    """Analyze logs, generate alerts, and create incident cases."""
    if not LOG_FILE.exists():
        st.error(f"Authentication log not found: {LOG_FILE}")
        st.stop()

    events = detection_engine.load_events(LOG_FILE)
    alerts = detection_engine.detect_repeated_failures(events)
    cases = detection_engine.build_cases(alerts)

    report = {
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

    detection_engine.save_json(REPORT_FILE, report)
    detection_engine.save_json(CASE_REPORT_FILE, cases)

    return events, alerts, cases, report


# --------------------------------------------------
# SIDEBAR AND ANALYST IDENTITY
# --------------------------------------------------

with st.sidebar:
    st.header("Dashboard Controls")

    analyst_name = st.text_input(
        "Analyst name or ID",
        value=st.session_state.get("analyst_name", "SOC Analyst"),
        key="analyst_name",
        help=(
            "Training-only label recorded in the audit trail. "
            "This does not verify your actual identity."
        ),
    ).strip()

    if not analyst_name:
        analyst_name = "Unspecified Analyst"

    st.caption(
        "This label identifies the analyst entered in this session. "
        "It is not a secure login system."
    )

    st.divider()
    st.write("**Detection rules**")
    st.markdown(
        "- `AUTH-001`: Repeated failed logins\n"
        "- `AUTH-002`: Successful login after repeated failures"
    )

    if st.button("🔄 Refresh analysis", use_container_width=True):
        st.rerun()


# --------------------------------------------------
# LOAD DETECTION DATA
# --------------------------------------------------

try:
    events, alerts, cases, report = run_detection()
except (OSError, ValueError, KeyError) as error:
    st.error(f"Unable to analyze security logs: {error}")
    st.stop()

updates = load_case_updates()


# --------------------------------------------------
# FILTERS
# --------------------------------------------------

st.subheader("Authentication Monitoring")

filter1, filter2, filter3 = st.columns(3)

with filter1:
    severity_options = sorted({
        alert["severity"] for alert in alerts
    })

    selected_severities = st.multiselect(
        "Filter by severity",
        options=severity_options,
        default=severity_options,
    )

with filter2:
    username_options = sorted({
        alert["username"] for alert in alerts
    })

    selected_users = st.multiselect(
        "Filter by username",
        options=username_options,
        default=username_options,
    )

with filter3:
    rule_options = sorted({
        alert["rule"] for alert in alerts
    })

    selected_rules = st.multiselect(
        "Filter by detection rule",
        options=rule_options,
        default=rule_options,
    )

filtered_alerts = [
    alert
    for alert in alerts
    if alert["severity"] in selected_severities
    and alert["username"] in selected_users
    and alert["rule"] in selected_rules
]


# --------------------------------------------------
# METRICS
# --------------------------------------------------

def get_case_status(case):
    """Return a case's saved status, defaulting to OPEN."""
    status = updates.get(case["case_id"], {}).get("status", "OPEN")

    if status not in CASE_STATUSES:
        return "OPEN"

    return status


open_cases = sum(
    get_case_status(case) == "OPEN"
    for case in cases
)

investigating_cases = sum(
    get_case_status(case) == "INVESTIGATING"
    for case in cases
)

closed_cases = sum(
    get_case_status(case) == "CLOSED"
    for case in cases
)

metric1, metric2, metric3, metric4, metric5 = st.columns(5)

metric1.metric("Events Analyzed", report["total_events"])
metric2.metric("Failed Logins", report["failed_logins"])
metric3.metric("Successful Logins", report["successful_logins"])
metric4.metric("Detection Alerts", len(alerts))
metric5.metric("Open Cases", open_cases)

st.divider()


# --------------------------------------------------
# CHARTS
# --------------------------------------------------

chart1, chart2 = st.columns(2)

with chart1:
    st.subheader("Authentication Event Breakdown")

    event_counts = pd.DataFrame({
        "Event Type": ["Failed Logins", "Successful Logins"],
        "Count": [
            report["failed_logins"],
            report["successful_logins"],
        ],
    })

    st.bar_chart(
        event_counts.set_index("Event Type"),
        y="Count",
        y_label="Number of Events",
    )

with chart2:
    st.subheader("Alerts by Detection Rule")

    if alerts:
        rule_counts = (
            pd.DataFrame(alerts)["rule"]
            .value_counts()
            .rename_axis("Detection Rule")
            .reset_index(name="Count")
        )

        st.bar_chart(
            rule_counts.set_index("Detection Rule"),
            y="Count",
            y_label="Number of Alerts",
        )
    else:
        st.info("No detection alerts were generated.")

st.divider()


# --------------------------------------------------
# ALERT INVESTIGATION
# --------------------------------------------------

st.subheader("🚨 Detection Alerts")

if filtered_alerts:
    alert_rows = []

    for index, alert in enumerate(filtered_alerts, start=1):
        alert_rows.append({
            "Alert": index,
            "Rule": alert["rule"],
            "Title": alert["title"],
            "Severity": alert["severity"],
            "Username": alert["username"],
            "Event Count": alert["event_count"],
            "Source IPs": ", ".join(alert["source_ips"]),
        })

    st.dataframe(
        pd.DataFrame(alert_rows),
        use_container_width=True,
        hide_index=True,
    )

    selected_alert_index = st.selectbox(
        "Select an alert to investigate",
        options=range(len(filtered_alerts)),
        format_func=lambda index: (
            f"{filtered_alerts[index]['rule']} — "
            f"{filtered_alerts[index]['title']} — "
            f"{filtered_alerts[index]['username']}"
        ),
    )

    alert = filtered_alerts[selected_alert_index]

    with st.expander("Alert details and evidence", expanded=True):
        detail1, detail2 = st.columns(2)

        with detail1:
            st.write(f"**Detection rule:** {alert['rule']}")
            st.write(f"**Severity:** {alert['severity']}")
            st.write(f"**Affected account:** {alert['username']}")
            st.write(f"**Events involved:** {alert['event_count']}")

        with detail2:
            st.write("**Source IP addresses**")

            for source_ip in alert["source_ips"]:
                st.code(source_ip)

        st.write("**Recommended investigation action**")
        st.write(alert["recommended_action"])

        st.write("**Evidence events**")
        st.dataframe(
            pd.DataFrame(alert["evidence"]),
            use_container_width=True,
            hide_index=True,
        )

else:
    st.info("No alerts match your selected filters.")


st.divider()


# --------------------------------------------------
# INCIDENT CASE MANAGEMENT
# --------------------------------------------------

st.subheader("📁 Incident Case Management")

st.write(
    "Update an incident's status and document the investigation. "
    "Each saved change is recorded in the audit trail."
)

if not cases:
    st.info("No incident cases currently exist.")

else:
    case_lookup = {
        case["case_id"]: case
        for case in cases
    }

    selected_case_id = st.selectbox(
        "Choose an incident case",
        options=list(case_lookup),
        format_func=lambda case_id: (
            f"{case_id} — {case_lookup[case_id]['username']}"
        ),
    )

    selected_case = case_lookup[selected_case_id]
    saved_update = updates.get(selected_case_id, {})

    current_status = saved_update.get("status", "OPEN")

    if current_status not in CASE_STATUSES:
        current_status = "OPEN"

    current_notes = saved_update.get("notes", "")

    st.markdown(f"### Case {selected_case_id}")

    case1, case2, case3 = st.columns(3)

    case1.metric("Affected Account", selected_case["username"])
    case2.metric("Severity", selected_case["severity"])
    case3.metric("Associated Alerts", selected_case["alert_count"])

    st.write(
        "**Source IP addresses:** "
        + ", ".join(selected_case["source_ips"])
    )

    with st.form("case_update_form"):
        new_status = st.selectbox(
            "Incident status",
            options=CASE_STATUSES,
            index=CASE_STATUSES.index(current_status),
        )

        new_notes = st.text_area(
            "Investigation notes",
            value=current_notes,
            height=160,
            placeholder=(
                "Document evidence reviewed, findings, "
                "and any remaining investigation steps."
            ),
            help="Do not enter real passwords or secrets.",
        )

        save_clicked = st.form_submit_button(
            "💾 Save Case Updates",
            use_container_width=True,
        )

    if save_clicked:
        previous_status = current_status
        previous_notes = current_notes

        status_changed = new_status != previous_status
        notes_changed = new_notes != previous_notes

        if not status_changed and not notes_changed:
            st.info("No changes detected. Nothing new was recorded.")

        else:
            if status_changed and notes_changed:
                action = "STATUS_AND_NOTES_UPDATED"
            elif status_changed:
                action = "STATUS_UPDATED"
            else:
                action = "NOTES_UPDATED"

            audit_event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "case_id": selected_case_id,
                "username": selected_case["username"],
                "analyst": analyst_name,
                "action": action,
                "previous_status": previous_status,
                "new_status": new_status,
                "notes_changed": notes_changed,
            }

            try:
                # Save the latest case information.
                updated_data = dict(updates)
                updated_data[selected_case_id] = {
                    "status": new_status,
                    "notes": new_notes,
                }

                save_case_updates(updated_data)

                # Append an audit record only after saving the case.
                append_audit_event(audit_event)

                st.success(
                    f"Saved {selected_case_id}. "
                    f"Audit action: {action}."
                )
                st.rerun()

            except OSError as error:
                st.error(f"Unable to save the case update: {error}")

    st.write("**Current investigation notes**")

    if current_notes.strip():
        st.write(current_notes)
    else:
        st.caption("No investigation notes have been saved.")


# --------------------------------------------------
# INCIDENT CASE SUMMARY
# --------------------------------------------------

st.divider()
st.subheader("Incident Case Summary")

case_rows = []

for case in cases:
    case_update = updates.get(case["case_id"], {})
    notes = case_update.get("notes", "")

    case_rows.append({
        "Case ID": case["case_id"],
        "Affected Account": case["username"],
        "Severity": case["severity"],
        "Status": get_case_status(case),
        "Alerts": case["alert_count"],
        "Source IPs": ", ".join(case["source_ips"]),
        "Investigation Notes": "Yes" if notes.strip() else "No",
    })

st.dataframe(
    pd.DataFrame(case_rows),
    use_container_width=True,
    hide_index=True,
)

status1, status2, status3 = st.columns(3)

status1.metric("Open", open_cases)
status2.metric("Investigating", investigating_cases)
status3.metric("Closed", closed_cases)


# --------------------------------------------------
# AUDIT TRAIL
# --------------------------------------------------

st.divider()
st.subheader("🧾 Case Audit Trail")

st.write(
    "This history records case status and note changes, including "
    "the analyst label and the affected account. "
    "Audit records are stored in data/case_audit.jsonl."
)

audit_events = load_audit_events()

if audit_events:
    audit_rows = []

    for event in reversed(audit_events):
        audit_rows.append({
            "Timestamp (UTC)": event.get("timestamp", "Unknown"),
            "Case ID": event.get("case_id", "Unknown"),
            "Affected Account": event.get("username", "Unknown"),
            "Analyst": event.get(
                "analyst",
                "Not recorded (older event)",
            ),
            "Action": event.get("action", "Unknown"),
            "Previous Status": event.get("previous_status", "Unknown"),
            "New Status": event.get("new_status", "Unknown"),
            "Notes Changed": event.get("notes_changed", False),
        })

    st.dataframe(
        pd.DataFrame(audit_rows),
        use_container_width=True,
        hide_index=True,
    )

else:
    st.info(
        "No audit events yet. Change a case status or its notes, "
        "then save to create the first audit entry."
    )


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.caption(
    "Training environment only. Logs are fictional. "
    "Alerts require investigation and are not proof of malicious activity. "
    "Analyst names are self-entered labels, not verified identities."
)
