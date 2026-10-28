# 🛡️ SOC Detection & Incident Response Lab

<img width="948" height="438" alt="image" src="https://github.com/user-attachments/assets/33d4b0ac-84d4-4116-8405-207fb1f4ea4d" />



A Python-based Security Operations Center (SOC) training project that analyzes authentication logs, detects suspicious login activity, generates security alerts, and supports incident investigation through an interactive dashboard.

Built as a hands-on cybersecurity portfolio project to practice security monitoring, detection engineering, log analysis, and incident response workflows.

## Project Overview

Security analysts monitor authentication logs to identify potentially suspicious activity, such as repeated failed login attempts and successful logins following multiple failures.

This project simulates part of that workflow by processing structured authentication events, applying detection rules, displaying alerts, and tracking incident investigations.

### Key Features

- **Authentication log analysis:** Parses JSONL event files and validates required fields.
- **Detection engineering:** Identifies repeated failed logins within a five-minute window.
- **Suspicious login detection:** Flags successful logins that follow repeated authentication failures.
- **Alert investigation:** Displays severity, affected accounts, source IP addresses, event evidence, and recommended actions.
- **Interactive SOC dashboard:** Visualizes authentication activity and alerts with Streamlit.
- **Incident case management:** Tracks incident status and investigation notes.
- **Audit trail:** Records case status and note changes with timestamps and analyst labels.
- **Automated testing:** Includes unit tests for detection rules, time windows, incident cases, and malformed log input.
- **False-positive testing:** Uses separate fictional scenarios to verify that ordinary activity does not trigger unnecessary alerts.

## Detection Rules

| Rule ID | Detection rule | Severity | Logic |
|---|---|---|---|
| AUTH-001 | Repeated Failed Logins | HIGH | Detects at least three failed login attempts within a five-minute window. |
| AUTH-002 | Successful Login After Repeated Failures | HIGH | Detects a successful login following at least three failed attempts within the preceding five minutes. |

These rules identify activity that may warrant investigation. An alert does not, by itself, prove that an account has been compromised.

## Technology Stack

- **Python** — log processing, detection logic, and report generation
- **Streamlit** — interactive security monitoring dashboard
- **Pandas** — data analysis and dashboard visualizations
- **JSON / JSONL** — authentication events, reports, and audit records
- **unittest** — automated testing
- **PowerShell** — Windows development environment and project commands

## Project Structure

```text
soc_detection_lab/
├── data/
│   ├── auth_events.jsonl
│   ├── auth_events_backup.jsonl
│   ├── test_scenarios.jsonl
│   ├── false_alarm_test.jsonl
│   ├── time_window_test.jsonl
│   ├── case_updates.json
│   └── case_audit.jsonl
├── reports/
│   ├── security_report.json
│   └── incident_cases.json
├── tests/
│   └── test_detection.py
├── main.py
├── app.py
├── requirements.txt
└── README.md
```

The project also uses a local Python virtual environment, `.venv`, which is not required to be committed to GitHub.

## Getting Started

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd soc_detection_lab
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with the actual URL of your GitHub repository.

### 2. Create a virtual environment

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Generate the security reports

```powershell
python main.py
```

This processes the configured authentication log and generates the security report and incident case report.

### 5. Launch the dashboard

```powershell
streamlit run app.py
```

Open the local URL displayed in the terminal, typically `http://localhost:8501`.

## Authentication Event Format

The detection engine reads JSONL files, with one JSON event per line.

Example:

```json
{"timestamp":"2026-10-27T10:00:00Z","username":"admin","event_type":"login_failed","source_ip":"192.0.2.10","host":"WORKSTATION-01"}
```

Each event contains:

- `timestamp` — event time, including timezone information
- `username` — account associated with the event
- `event_type` — `login_failed` or `login_success`
- `source_ip` — source IP address
- `host` — hostname associated with the event

The example uses a documentation-only IP address and fictional data.

## Testing

Run the automated unit tests from the project root:

```powershell
python -m unittest discover -s tests -v
```

The current test suite contains 12 unit tests covering:

- Detection of repeated failed logins
- Successful logins following repeated failures
- Activity outside the detection time window
- Duplicate alert prevention within a failure burst
- Separate failure bursts
- Incident case grouping
- Investigation evidence
- Event loading and login counts
- Handling malformed log lines

Additional manual scenario tests have verified:

| Scenario | Expected result | Observed result |
|---|---|---|
| Four rapid failed logins | Generate a repeated-failure alert | PASS |
| Three failures followed by a successful login | Generate AUTH-001 and AUTH-002 alerts | PASS |
| Normal successful login | No alert | PASS |
| Two failures followed by a successful login | No alert | PASS |
| Three failures spread beyond five minutes | No alert | PASS |

The automated suite has passed all 12 tests in the current development environment. Manual scenario tests are separate from those 12 unit tests.

## Incident Response Workflow

The dashboard supports a basic incident investigation process:

1. Review alerts generated by the detection engine.
2. Select an alert to inspect its evidence and recommended investigation action.
3. Open the associated incident case.
4. Update the incident status to `OPEN`, `INVESTIGATING`, or `CLOSED`.
5. Add or revise investigation notes.
6. Review the audit records of case changes.

Case updates are stored in `data/case_updates.json`, and audit records are appended to `data/case_audit.jsonl`.

**Security limitation:** Analyst labels are self-entered and are not authenticated identities. The local JSON files are suitable for a training lab, not a tamper-resistant production audit system.

## Skills Demonstrated

- Python programming and structured log parsing
- Authentication monitoring and security event analysis
- Rule-based threat detection
- Time-window logic and false-positive testing
- Alert triage and evidence review
- Incident tracking and investigation documentation
- Audit logging and JSON data handling
- Unit testing and debugging
- Dashboard development and data visualization
- Git, GitHub, and technical documentation

## Future Improvements

Potential enhancements include:

- Ingesting authentication logs from Windows Event Logs or Linux systems
- Adding detection rules for suspicious source IP patterns
- Supporting configurable thresholds and time windows
- Exporting investigation reports to CSV or PDF
- Adding analyst authentication and role-based permissions
- Improving audit integrity and access controls
- Integrating with a SIEM or alert notification service

## Author

**Jericho Gutlay**

Computer Science graduate with a cybersecurity concentration, developing practical skills in security monitoring, detection engineering, and incident response.
