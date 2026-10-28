
import unittest
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import main


class TestSecurityDetection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.events = main.load_events(main.LOG_FILE)
        cls.alerts = main.detect_repeated_failures(cls.events)

    def make_test_event(self, seconds, event_type="login_failed"):
        timestamp = (
            datetime(2026, 10, 27, 9, 0, 0, tzinfo=timezone.utc)
            + timedelta(seconds=seconds)
        )

        return {
            "timestamp": timestamp.isoformat(),
            "_timestamp": timestamp,
            "event_type": event_type,
            "username": "testuser",
            "source_ip": "192.0.2.50",
            "host": "test-host",
        }

    def test_all_events_are_loaded(self):
        self.assertEqual(len(self.events), 10)

    def test_failed_and_successful_login_counts(self):
        failed = sum(
            event["event_type"] == "login_failed"
            for event in self.events
        )
        successful = sum(
            event["event_type"] == "login_success"
            for event in self.events
        )

        self.assertEqual(failed, 7)
        self.assertEqual(successful, 3)

    def test_repeated_failures_are_detected(self):
        alerts = [
            alert for alert in self.alerts
            if alert["rule"] == "AUTH-001"
        ]

        self.assertEqual(len(alerts), 2)
        self.assertEqual(
            {alert["username"] for alert in alerts},
            {"admin", "alex"},
        )

    def test_admin_success_after_failures_is_detected(self):
        alerts = [
            alert for alert in self.alerts
            if alert["rule"] == "AUTH-002"
        ]

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["username"], "admin")

    def test_alex_success_outside_window_is_not_flagged(self):
        alerts = [
            alert for alert in self.alerts
            if alert["rule"] == "AUTH-002"
            and alert["username"] == "alex"
        ]

        self.assertEqual(len(alerts), 0)

    def test_alerts_include_investigation_evidence(self):
        for alert in self.alerts:
            self.assertTrue(alert["evidence"])
            self.assertTrue(alert["source_ips"])
            self.assertTrue(alert["recommended_action"])

    def test_alerts_are_grouped_into_cases(self):
        cases = main.build_cases(self.alerts)

        self.assertEqual(len(cases), 2)

        cases_by_user = {
            case["username"]: case for case in cases
        }

        self.assertEqual(
            set(cases_by_user.keys()),
            {"admin", "alex"},
        )

    def test_admin_case_contains_both_alerts(self):
        cases = main.build_cases(self.alerts)

        admin_case = next(
            case for case in cases
            if case["username"] == "admin"
        )

        self.assertEqual(admin_case["alert_count"], 2)
        self.assertEqual(admin_case["status"], "OPEN")
        self.assertEqual(len(admin_case["alerts"]), 2)

    def test_failures_outside_window_do_not_trigger_alert(self):
        events = [
            self.make_test_event(0),
            self.make_test_event(360),
            self.make_test_event(720),
        ]

        alerts = main.detect_repeated_failures(events)

        self.assertEqual(len(alerts), 0)

    def test_four_rapid_failures_do_not_duplicate_threshold_alert(self):
        events = [
            self.make_test_event(0),
            self.make_test_event(15),
            self.make_test_event(30),
            self.make_test_event(45),
        ]

        alerts = main.detect_repeated_failures(events)

        repeated_failure_alerts = [
            alert for alert in alerts
            if alert["rule"] == "AUTH-001"
        ]

        self.assertEqual(len(repeated_failure_alerts), 1)

    def test_malformed_log_line_is_skipped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "test_auth.log"

            log_path.write_text(
                'this is not valid JSON\n'
                '{"timestamp":"2026-10-27T09:00:00Z",'
                '"event_type":"login_failed",'
                '"username":"testuser",'
                '"source_ip":"192.0.2.50",'
                '"host":"test-host"}\n',
                encoding="utf-8",
            )

            events = main.load_events(log_path)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["username"], "testuser")

    def test_separate_failure_bursts_generate_separate_alerts(self):
        events = [
            self.make_test_event(0),
            self.make_test_event(15),
            self.make_test_event(30),
            self.make_test_event(600),
            self.make_test_event(615),
            self.make_test_event(630),
        ]

        alerts = main.detect_repeated_failures(events)

        repeated_failure_alerts = [
            alert for alert in alerts
            if alert["rule"] == "AUTH-001"
        ]

        self.assertEqual(len(repeated_failure_alerts), 2)


if __name__ == "__main__":
    unittest.main()
