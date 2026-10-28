
import json
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

import main as detection_engine


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="SOC Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
)

BASE_DIR = detection_engine.BASE_DIR
LOG_FILE = detection_engine.LOG_FILE
REPORT_FILE = detection_engine.REPORT_FILE
CASE_REPORT_FILE = detection_engine.CASE_REPORT_FILE


# --------------------------------------------------
# LOAD AND ANALYZE SECURITY EVENTS
# --------------------------------------------------

@st.cache_data
def load_security_data(file_modified_time):
    """Load logs and run the detection engine."""

    events = detection_engine.load_events(LOG_FILE)
    alerts = detection_engine.detect_repeated_failures(events)
    cases = detection_engine.build_cases(alerts)

    return events, alerts, cases


def refresh_analysis():
    """Clear cached data and reload the log file."""
    load_security_data.clear()


# --------------------------------------------------
# DASHBOARD HEADER
# --------------------------------------------------

st.title("🛡️ SOC Detection & Incident Response")
st.caption(
    "Security monitoring dashboard | "
    "Authentication threat detection | "
    "Local demonstration environment"
)

with st.sidebar:
    st.header("Dashboard Controls")

    st.write("**Log source**")
    st.code("data/auth_events.jsonl")

    if st.button("🔄 Refresh Analysis", use_container_width=True):
        refresh_analysis()
        st.rerun()

    st.divider()

    st.subheader("Detection Rules")
    st.markdown(
        """
        **AUTH-001 — Repeated Failed Logins**

        Detects repeated login failures within five minutes.

        **AUTH-002 — Successful Login After Failures**

        Detects a successful login after repeated failures
        within the same five-minute window.
        """
    )

    st.divider()

    st.caption(
        "This lab uses fictional authentication data. "
        "Alerts indicate suspicious activity, not confirmed compromise."
    )


# --------------------------------------------------
# READ DATA
# --------------------------------------------------

if not LOG_FILE.exists():
    st.error(f"Authentication log file not found: {LOG_FILE}")
    st.stop()

try:
    events, alerts, cases = load_security_data(
        LOG_FILE.stat().st_mtime
    )
except Exception as error:
    st.error(f"Unable to analyze the log data: {error}")
    st.stop()


# Save the latest analysis reports.
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

try:
    detection_engine.save_json(REPORT_FILE, report)
    detection_engine.save_json(CASE_REPORT_FILE, cases)
except OSError as error:
    st.warning(f"Could not save the latest reports: {error}")


# --------------------------------------------------
# FILTERS
# --------------------------------------------------

st.subheader("Alert Investigation")

all_users = sorted({
    alert["username"] for alert in alerts
})

all_severities = sorted({
    alert["severity"] for alert in alerts
})

filter_col1, filter_col2, filter_col3 = st.columns(3)

with filter_col1:
    selected_severity = st.multiselect(
        "Filter by severity",
        options=all_severities,
        default=all_severities,
    )

with filter_col2:
    selected_users = st.multiselect(
        "Filter by username",
        options=all_users,
        default=all_users,
    )

with filter_col3:
    selected_rule = st.selectbox(
        "Detection rule",
        options=[
            "All rules",
            "AUTH-001",
            "AUTH-002",
        ],
    )


filtered_alerts = [
    alert for alert in alerts
    if alert["severity"] in selected_severity
    and alert["username"] in selected_users
    and (
        selected_rule == "All rules"
        or alert["rule"] == selected_rule
    )
]


# --------------------------------------------------
# TOP-LEVEL SECURITY METRICS
# --------------------------------------------------

total_events = len(events)

failed_logins = sum(
    event["event_type"] == "login_failed"
    for event in events
)

successful_logins = sum(
    event["event_type"] == "login_success"
    for event in events
)

high_alerts = sum(
    alert["severity"] == "HIGH"
    for alert in filtered_alerts
)

open_cases = sum(
    case["status"] == "OPEN"
    for case in cases
)

metric1, metric2, metric3, metric4, metric5 = st.columns(5)

metric1.metric("Events Analyzed", total_events)
metric2.metric("Failed Logins", failed_logins)
metric3.metric("Successful Logins", successful_logins)
metric4.metric("Filtered Alerts", len(filtered_alerts))
metric5.metric("Open Cases", open_cases)

st.divider()


# --------------------------------------------------
# EVENT SUMMARY CHARTS
# --------------------------------------------------

left_chart, right_chart = st.columns(2)

with left_chart:
    st.subheader("Authentication Event Breakdown")

    event_counts = pd.DataFrame({
        "Event Type": ["Failed Logins", "Successful Logins"],
        "Count": [failed_logins, successful_logins],
    })

    st.bar_chart(
        event_counts.set_index("Event Type"),
        y="Count",
    )

with right_chart:
    st.subheader("Alerts by Detection Rule")

    if filtered_alerts:
        rule_counts = pd.DataFrame([
            {
                "Rule": rule,
                "Alerts": sum(
                    alert["rule"] == rule
                    for alert in filtered_alerts
                ),
            }
            for rule in sorted({
                alert["rule"] for alert in filtered_alerts
            })
        ])

        st.bar_chart(
            rule_counts.set_index("Rule"),
            y="Alerts",
        )
    else:
        st.info("No alerts match the current filters.")


st.divider()


# --------------------------------------------------
# ALERT QUEUE
# --------------------------------------------------

st.subheader("🚨 Alert Queue")

if filtered_alerts:
    alert_rows = []

    for alert in filtered_alerts:
        alert_rows.append({
            "Severity": alert["severity"],
            "Detection Rule": alert["rule"],
            "Alert": alert["title"],
            "Username": alert["username"],
            "Source IPs": ", ".join(alert["source_ips"]),
            "Events": alert["event_count"],
        })

    alert_dataframe = pd.DataFrame(alert_rows)

    st.dataframe(
        alert_dataframe,
        use_container_width=True,
        hide_index=True,
    )

    st.caption(
        f"Showing {len(filtered_alerts)} alert(s) "
        f"matching your filters."
    )

    st.subheader("Investigate an Alert")

    alert_options = list(range(len(filtered_alerts)))

    selected_alert_index = st.selectbox(
        "Choose an alert",
        options=alert_options,
        format_func=lambda index: (
            f"{filtered_alerts[index]['severity']} | "
            f"{filtered_alerts[index]['title']} | "
            f"{filtered_alerts[index]['username']} | "
            f"{filtered_alerts[index]['rule']}"
        ),
    )

    selected_alert = filtered_alerts[selected_alert_index]

    st.markdown(
        f"### {selected_alert['title']}"
    )

    detail1, detail2, detail3 = st.columns(3)

    detail1.write("**Severity**")
    detail1.write(selected_alert["severity"])

    detail2.write("**Username**")
    detail2.write(selected_alert["username"])

    detail3.write("**Detection Rule**")
    detail3.write(selected_alert["rule"])

    st.write("**Source IP addresses**")
    st.write(", ".join(selected_alert["source_ips"]))

    st.write("**Recommended investigation action**")
    st.info(selected_alert["recommended_action"])

    st.write("**Evidence**")

    evidence_dataframe = pd.DataFrame(
        selected_alert["evidence"]
    )

    st.dataframe(
        evidence_dataframe,
        use_container_width=True,
        hide_index=True,
    )

else:
    st.success("No alerts match the current filters.")


# --------------------------------------------------
# INCIDENT CASES
# --------------------------------------------------

st.divider()
st.subheader("📁 Incident Cases")

if cases:
    case_rows = []

    for case in cases:
        case_rows.append({
            "Case ID": case["case_id"],
            "Username": case["username"],
            "Severity": case["severity"],
            "Status": case["status"],
            "Alert Count": case["alert_count"],
            "Source IPs": ", ".join(case["source_ips"]),
        })

    st.dataframe(
        pd.DataFrame(case_rows),
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("Case Details")

    selected_case_id = st.selectbox(
        "Select an incident case",
        options=[case["case_id"] for case in cases],
    )

    selected_case = next(
        case for case in cases
        if case["case_id"] == selected_case_id
    )

    st.markdown(f"### {selected_case['case_id']}")

    st.write(f"**Username:** {selected_case['username']}")
    st.write(f"**Severity:** {selected_case['severity']}")
    st.write(f"**Status:** {selected_case['status']}")
    st.write(f"**Number of alerts:** {selected_case['alert_count']}")
    st.write(
        f"**Source IPs:** {', '.join(selected_case['source_ips'])}"
    )

    for number, case_alert in enumerate(
        selected_case["alerts"],
        start=1,
    ):
        with st.expander(
            f"Alert {number}: {case_alert['title']}"
        ):
            st.write(f"Rule: {case_alert['rule']}")
            st.write(f"Severity: {case_alert['severity']}")
            st.write(case_alert["recommended_action"])
            st.dataframe(
                pd.DataFrame(case_alert["evidence"]),
                use_container_width=True,
                hide_index=True,
            )

else:
    st.success("No incident cases have been created.")


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "SOC Detection Lab | Python + Streamlit | "
    "Detection rules are for educational use and require "
    "human investigation before taking action."
)
