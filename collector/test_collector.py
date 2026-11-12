import json
import tempfile
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

from garudashield_collector import ApiClient, Collector, EventParser


NOW = datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc)
FAILED = "Oct 27 06:30:51 vm sshd[1234]: Failed password for admin from 198.51.100.66 port 52222 ssh2"
INVALID = "Oct 27 06:30:51 vm sshd[1234]: Invalid user admin from 198.51.100.66 port 52222"
SUCCESS = "Oct 27 06:31:01 vm sshd[1234]: Accepted password for root from 192.0.2.25 port 58944 ssh2"


class EventParserTests(unittest.TestCase):
    def setUp(self):
        self.parser = EventParser()

    def test_failed_password(self):
        event = self.parser.parse(FAILED, NOW)
        self.assertEqual(event.payload["event_type"], "ssh_login_failed")
        self.assertEqual(event.payload["source_ip"], "198.51.100.66")
        self.assertEqual(event.payload["username"], "admin")
        timestamp = datetime.fromisoformat(event.payload["timestamp"].replace("Z", "+00:00"))
        source_clock = timestamp.astimezone(timezone(timedelta(hours=7)))
        self.assertEqual((source_clock.year, source_clock.month, source_clock.day, source_clock.hour, source_clock.minute, source_clock.second), (2026, 10, 27, 6, 30, 51))
        self.assertIsNotNone(timestamp.tzinfo)

    def test_invalid_user(self):
        event = self.parser.parse(INVALID, NOW)
        self.assertEqual(event.payload["event_type"], "ssh_login_failed")
        self.assertEqual(event.payload["username"], "admin")

    def test_failed_password_for_invalid_user(self):
        line = "Oct 27 06:30:51 vm sshd[1234]: Failed password for invalid user admin from 198.51.100.66 port 52222 ssh2"
        event = self.parser.parse(line, NOW)
        self.assertEqual(event.payload["event_type"], "ssh_login_failed")
        self.assertEqual(event.payload["username"], "admin")

    def test_accepted_password(self):
        event = self.parser.parse(SUCCESS, NOW)
        self.assertEqual(event.payload["event_type"], "ssh_login_success")
        self.assertEqual(event.payload["source_ip"], "192.0.2.25")
        self.assertEqual(event.payload["username"], "root")

    def test_source_log_instant_is_normalized_to_utc_without_losing_its_wall_clock(self):
        parser = EventParser(timezone(timedelta(hours=7), name="WIB"))
        event = parser.parse(FAILED, NOW)
        self.assertEqual(event.payload["timestamp"], "2026-10-26T23:30:51Z")
        timestamp = datetime.fromisoformat(event.payload["timestamp"].replace("Z", "+00:00"))
        self.assertEqual(timestamp.astimezone(timezone(timedelta(hours=7))).strftime("%Y-%m-%d %H:%M:%S"), "2026-10-27 06:30:51")

    def test_unrelated_and_malformed_lines_are_ignored(self):
        self.assertIsNone(self.parser.parse("Oct 27 06:30:51 vm sudo: command executed", NOW))
        self.assertIsNone(self.parser.parse("sshd: Failed password for admin from nowhere port xyz", NOW))
        self.assertIsNone(self.parser.parse("", NOW))


class ApiClientTests(unittest.TestCase):
    def test_post_sends_only_schema_fields_to_the_configured_origin(self):
        class Response:
            status = 200
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

        class RecordingOpener:
            request = None
            timeout = None

            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return Response()

        opener = RecordingOpener()
        client = ApiClient("http://192.168.1.103:8000/", timeout=3, opener=opener)
        client.post_event({
            "event_type": "ssh_login_failed",
            "source_ip": "198.51.100.66",
            "username": "admin",
            "timestamp": "2026-10-27T06:30:51+00:00",
        })

        self.assertEqual(opener.request.full_url, "http://192.168.1.103:8000/api/v1/events")
        self.assertEqual(opener.request.get_method(), "POST")
        self.assertEqual(opener.timeout, 3)
        self.assertEqual(set(json.loads(opener.request.data)), {"event_type", "source_ip", "username", "timestamp"})

    def test_api_target_must_be_a_configured_origin(self):
        for invalid in ("ftp://192.168.1.103:8000", "http://user:pass@192.168.1.103:8000", "http://192.168.1.103:8000/other"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                ApiClient(invalid)


class CollectorStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.log = self.root / "secure"
        self.state = self.root / "state"
        self.log.write_text("", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def client():
        return ApiClient("http://127.0.0.1:8000")

    def collector(self, dry_run=True, start_at_end=False, client=None, clock=lambda: 1000.0):
        return Collector(self.log, self.state, client or self.client(), dry_run, start_at_end, clock, EventParser())

    def test_checkpoint_restart_does_not_duplicate_an_event(self):
        self.log.write_text(FAILED + "\n", encoding="utf-8")
        first = self.collector()
        self.assertEqual(first.read_available(), 1)
        first_state = json.loads((self.state / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(len(first_state["pending"]), 1)

        restarted = self.collector()
        self.assertEqual(restarted.read_available(), 0)
        self.assertEqual(len(restarted.store.state["pending"]), 1)

    def test_normal_start_skips_existing_log_content(self):
        self.log.write_text(FAILED + "\n", encoding="utf-8")
        collector = self.collector(start_at_end=True)
        self.assertEqual(collector.read_available(), 0)
        self.assertEqual(len(collector.store.state["pending"]), 0)
        with self.log.open("a", encoding="utf-8") as handle:
            handle.write(SUCCESS + "\n")
        self.assertEqual(collector.read_available(), 1)
        self.assertEqual(collector.store.state["pending"][0]["event"]["event_type"], "ssh_login_success")

    def test_missing_log_is_reported_as_a_read_error(self):
        self.log.unlink()
        collector = self.collector()
        self.assertEqual(collector.read_available(), 0)
        self.assertTrue(collector.last_read_error)

    def test_invalid_user_and_failed_password_pair_are_deduplicated(self):
        self.log.write_text(INVALID + "\n" + FAILED + "\n", encoding="utf-8")
        collector = self.collector()
        self.assertEqual(collector.read_available(), 1)
        self.assertEqual(len(collector.store.state["pending"]), 1)

    def test_rotation_drains_old_inode_then_reads_new_file(self):
        self.log.write_text(FAILED + "\n", encoding="utf-8")
        collector = self.collector()
        collector.read_available()
        rotated = self.root / "secure.1"
        self.log.replace(rotated)
        self.log.write_text(SUCCESS + "\n", encoding="utf-8")

        collector.read_available()  # Finds/drains the old inode, then switches cursor.
        collector.read_available()  # Reads new active file from byte zero.
        self.assertEqual(len(collector.store.state["pending"]), 2)
        self.assertEqual(collector.store.state["pending"][1]["event"]["event_type"], "ssh_login_success")

    def test_truncation_restarts_at_zero_and_reads_new_content(self):
        long_failure = "Oct 27 06:30:51 vm sshd[1234]: Failed password for " + ("a" * 80) + " from 198.51.100.66 port 52222 ssh2"
        self.log.write_text(long_failure + "\n", encoding="utf-8")
        collector = self.collector()
        collector.read_available()

        self.log.write_text(SUCCESS + "\n", encoding="utf-8")
        collector.read_available()
        self.assertEqual(len(collector.store.state["pending"]), 2)
        self.assertEqual(collector.store.state["pending"][-1]["event"]["event_type"], "ssh_login_success")

    def test_api_failure_keeps_event_and_schedules_backoff_retry(self):
        class OfflineClient:
            def post_event(self, payload):
                raise urllib.error.URLError("offline")

        self.log.write_text(FAILED + "\n", encoding="utf-8")
        current_time = [1000.0]
        collector = self.collector(dry_run=False, client=OfflineClient(), clock=lambda: current_time[0])
        collector.read_available()
        self.assertFalse(collector.deliver_one())
        item = collector.store.state["pending"][0]
        self.assertEqual(item["attempts"], 1)
        self.assertEqual(item["next_attempt"], 1001.0)
        self.assertEqual(item["event"]["username"], "admin")
        current_time[0] = 1001.0
        self.assertFalse(collector.deliver_one())
        self.assertEqual(collector.store.state["pending"][0]["attempts"], 2)
        self.assertEqual(collector.store.state["pending"][0]["next_attempt"], 1003.0)

    def test_dry_run_persists_parsed_event_without_posting(self):
        class MustNotPost:
            def post_event(self, payload):
                raise AssertionError("dry-run must never call the API")

        self.log.write_text(FAILED + "\n", encoding="utf-8")
        collector = self.collector(dry_run=True, client=MustNotPost())
        collector.run_once()
        self.assertEqual(len(collector.store.state["pending"]), 1)
        self.assertFalse(collector.deliver_one())


if __name__ == "__main__":
    unittest.main()
