
import json
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
# FILE AND DATA FUNCTIONS
# --------------------------------------------------

def load_case_updates():
    """Load saved analyst statuses and investigation notes."""
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
    """Save analyst updates separately from generated detections."""
    UPDATES_FILE.parent.mkdir(parents=True, exist_ok=True)

    with UPDATES_FILE.open("w", encoding="utf-8") as file:
        json.dump(updates, file, indent=2)


def run_detection():
    """Read logs and regenerate alerts and incident cases."""
    if not LOG_FILE.exists():
        st.error(f"Authentication log file not found: {LOG_FILE}")
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


def display_timestamp(value):
    """Return a readable timestamp."""
    return str(value) if value else "Unknown"


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

with st.sidebar:
    st.header("Dashboard Controls")

    st.write("**Detection rules**")
    st.markdown(
        "- `AUTH-001`: Repeated failed logins\n"
        "- `AUTH-002`: Successful login after repeated failures"
    )

    st.divider()

    if st.button("🔄 Refresh analysis", use_container_width=True):
        st.rerun()

    st.caption(
        "Refreshing reruns detection using the current log file. "
        "Saved analyst updates are stored separately."
    )


# --------------------------------------------------
# RUN DETECTION
# --------------------------------------------------

try:
    events, alerts, cases, report = run_detection()
except (OSError, ValueError, KeyError) as error:
    st.error(f"Unable to analyze the security logs: {error}")
    st.stop()

updates = load_case_updates()


# --------------------------------------------------
# FILTERS
# --------------------------------------------------

st.subheader("Authentication Monitoring")

filter_col1, filter_col2, filter_col3 = st.columns(3)

with filter_col1:
    severity_options = sorted({
        alert["severity"] for alert in alerts
    })
    selected_severities = st.multiselect(
        "Filter by severity",
        options=severity_options,
        default=severity_options,
    )

with filter_col2:
    username_options = sorted({
        alert["username"] for alert in alerts
    })
    selected_users = st.multiselect(
        "Filter by username",
        options=username_options,
        default=username_options,
    )

with filter_col3:
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

failed_logins = report["failed_logins"]
successful_logins = report["successful_logins"]

open_cases = sum(
    updates.get(case["case_id"], {}).get("status", "OPEN") == "OPEN"
    for case in cases
)

investigating_cases = sum(
    updates.get(case["case_id"], {}).get("status", "OPEN")
    == "INVESTIGATING"
    for case in cases
)

closed_cases = sum(
    updates.get(case["case_id"], {}).get("status", "OPEN") == "CLOSED"
    for case in cases
)

metric1, metric2, metric3, metric4, metric5 = st.columns(5)

metric1.metric("Events Analyzed", report["total_events"])
metric2.metric("Failed Logins", failed_logins)
metric3.metric("Successful Logins", successful_logins)
metric4.metric("Detection Alerts", len(alerts))
metric5.metric("Open Cases", open_cases)

st.divider()


# --------------------------------------------------
# CHARTS
# --------------------------------------------------

chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.subheader("Authentication Event Breakdown")

    event_counts = pd.DataFrame({
        "Event Type": ["Failed Logins", "Successful Logins"],
        "Count": [failed_logins, successful_logins],
    })

    st.bar_chart(
        event_counts.set_index("Event Type"),
        y="Count",
        y_label="Number of Events",
    )

with chart_col2:
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
        detail_col1, detail_col2 = st.columns(2)

        with detail_col1:
            st.write(f"**Detection rule:** {alert['rule']}")
            st.write(f"**Severity:** {alert['severity']}")
            st.write(f"**Username:** {alert['username']}")
            st.write(f"**Events involved:** {alert['event_count']}")

        with detail_col2:
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
    "Select a case to update its status and document your investigation. "
    "Your changes are saved separately from automatically generated alerts."
)

if not cases:
    st.info(
        "No incident cases currently exist. "
        "Cases will appear when the detection rules generate alerts."
    )

else:
    case_options = [case["case_id"] for case in cases]

    case_lookup = {
        case["case_id"]: case
        for case in cases
    }

    selected_case_id = st.selectbox(
        "Choose an incident case",
        options=case_options,
        format_func=lambda case_id: (
            f"{case_id} — "
            f"{case_lookup[case_id]['username']}"
        ),
    )

    selected_case = case_lookup[selected_case_id]
    saved_update = updates.get(selected_case_id, {})

    current_status = saved_update.get("status", "OPEN")

    if current_status not in CASE_STATUSES:
        current_status = "OPEN"

    current_notes = saved_update.get("notes", "")

    st.markdown(f"### Case {selected_case_id}")

    case_col1, case_col2, case_col3 = st.columns(3)

    case_col1.metric("Username", selected_case["username"])
    case_col2.metric("Severity", selected_case["severity"])
    case_col3.metric("Associated Alerts", selected_case["alert_count"])

    st.write(
        "**Source IP addresses:** "
        + ", ".join(selected_case["source_ips"])
    )

    with st.form("case_update_form"):
        new_status = st.selectbox(
            "Incident status",
            options=CASE_STATUSES,
            index=CASE_STATUSES.index(current_status),
            help="Choose the current stage of your investigation.",
        )

        new_notes = st.text_area(
            "Investigation notes",
            value=current_notes,
            height=160,
            placeholder=(
                "Example: Reviewed the authentication events. "
                "Need to verify whether the login activity was authorized."
            ),
            help=(
                "Record evidence reviewed, findings, and next steps. "
                "Do not enter real passwords or secrets."
            ),
        )

        save_clicked = st.form_submit_button(
            "💾 Save Case Updates",
            use_container_width=True,
        )

    if save_clicked:
        updates[selected_case_id] = {
            "status": new_status,
            "notes": new_notes,
        }

        try:
            save_case_updates(updates)
            st.success(
                f"{selected_case_id} saved with status: {new_status}"
            )
            st.rerun()

        except OSError as error:
            st.error(f"Could not save your case updates: {error}")

    st.write("**Current investigation notes**")

    if current_notes.strip():
        st.write(current_notes)
    else:
        st.caption("No investigation notes have been saved for this case.")


# --------------------------------------------------
# CASE SUMMARY
# --------------------------------------------------

st.divider()
st.subheader("Incident Case Summary")

case_rows = []

for case in cases:
    case_update = updates.get(case["case_id"], {})

    case_rows.append({
        "Case ID": case["case_id"],
        "Username": case["username"],
        "Severity": case["severity"],
        "Status": case_update.get("status", "OPEN"),
        "Alerts": case["alert_count"],
        "Source IPs": ", ".join(case["source_ips"]),
        "Investigation Notes": (
            "Yes" if case_update.get("notes", "").strip() else "No"
        ),
    })

st.dataframe(
    pd.DataFrame(case_rows),
    use_container_width=True,
    hide_index=True,
)

status_col1, status_col2, status_col3 = st.columns(3)
status_col1.metric("Open", open_cases)
status_col2.metric("Investigating", investigating_cases)
status_col3.metric("Closed", closed_cases)

st.caption(
    "Training environment only. The logs are fictional, and alerts indicate "
    "activity requiring review rather than proof of malicious behavior."
)
