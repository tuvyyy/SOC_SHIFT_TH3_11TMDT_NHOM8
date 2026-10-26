"""Kiểm thử ngưỡng, thời gian, dữ liệu lỗi, hash nhị phân và bản sửa crash."""
import csv
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from detector_starter import DATA_FILE, detect, load_events
from hash_check_starter import check_integrity, sha256_file
from traceback_exercise import parse_failed_count

ROOT = Path(__file__).resolve().parents[1]


def event(second, user="alice", kind="login_failed", ip="192.0.2.10"):
    return {"timestamp": f"2026-10-16T08:00:{second:02}", "user": user,
            "src_ip": ip, "event": kind, "asset": "vpn", "details": "test"}


class DetectorTests(unittest.TestCase):
    def test_supplied_dataset(self):
        events = load_events(DATA_FILE)
        self.assertEqual(len(events), 15)
        findings = detect(events)
        self.assertEqual(len(findings), 2)
        self.assertEqual((findings[0]["src_ip"], findings[0]["priority"], findings[0]["failed_count"]),
                         ("203.0.113.77", "HIGH", 5))
        self.assertEqual(findings[0]["success_after_failures"][0]["failures_before_success"], 5)
        self.assertEqual(findings[1]["rules"], ["POSSIBLE_PASSWORD_SPRAY"])
        self.assertEqual(findings[1]["unique_failed_users"], 3)

    def test_exact_failure_threshold_and_below(self):
        self.assertEqual(detect([event(i) for i in range(3)]), [])
        self.assertEqual(detect([event(i) for i in range(4)])[0]["rules"], ["REPEATED_FAILURES"])

    def test_spray_is_independent_of_four_failures(self):
        finding = detect([event(i, user) for i, user in enumerate(["a", "b", "c"])])[0]
        self.assertEqual(finding["failed_count"], 3)
        self.assertEqual(finding["priority"], "MEDIUM")
        self.assertEqual(finding["rules"], ["POSSIBLE_PASSWORD_SPRAY"])

    def test_repeated_user_is_not_spray(self):
        self.assertEqual(detect([event(i) for i in range(4)])[0]["unique_failed_users"], 1)

    def test_unsorted_input_and_success_after_failures(self):
        rows = [event(i) for i in range(4)] + [event(5, kind="login_success")]
        self.assertEqual(detect(reversed(rows))[0]["priority"], "HIGH")

    def test_success_before_failures_does_not_raise_priority(self):
        rows = [event(0, kind="login_success")] + [event(i) for i in range(1, 5)]
        finding = detect(rows)[0]
        self.assertEqual(finding["priority"], "MEDIUM")
        self.assertEqual(finding["success_after_failures"], [])

    def test_success_before_threshold_does_not_raise_priority(self):
        rows = [event(0), event(1, kind="login_success"), event(2), event(3), event(4)]
        finding = detect(rows)[0]
        self.assertEqual(finding["priority"], "MEDIUM")
        self.assertEqual(finding["success_after_failures"][0]["failures_before_success"], 1)

    def test_equal_timestamp_does_not_prove_after(self):
        rows = [event(0) for _ in range(4)] + [event(0, kind="login_success")]
        self.assertEqual(detect(rows)[0]["success_after_failures"], [])

    def test_ips_do_not_share_counters(self):
        self.assertEqual(detect([event(i, ip=f"192.0.2.{i}") for i in range(4)]), [])

    def test_success_for_other_user_is_explicit(self):
        rows = [event(i) for i in range(4)] + [event(5, "bob", "login_success")]
        self.assertFalse(detect(rows)[0]["success_after_failures"][0]["same_user_failed_before"])

    def test_empty_and_success_only(self):
        self.assertEqual(detect([]), [])
        self.assertEqual(detect([event(0, kind="login_success")]), [])

    def test_mixed_timezone_is_rejected(self):
        rows = [event(0), event(1)]
        rows[0]["timestamp"] += "+07:00"
        with self.assertRaisesRegex(ValueError, "offset"):
            detect(rows)

    def test_missing_columns_and_bad_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.csv"
            path.write_text("user\nalice\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_events(path)
            for key, invalid in [("timestamp", "bad-date"), ("src_ip", "bad-ip"),
                                 ("user", ""), ("event", "unknown")]:
                row = event(0)
                row[key] = invalid
                with path.open("w", encoding="utf-8-sig", newline="") as stream:
                    writer = csv.DictWriter(stream, fieldnames=list(row))
                    writer.writeheader()
                    writer.writerow(row)
                with self.subTest(key=key), self.assertRaises(ValueError):
                    load_events(path)


class HashTests(unittest.TestCase):
    def test_known_sha256_vectors_and_binary_chunks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.txt"
            for payload, expected in [(b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                                      (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                                      (bytes(range(256)) * 1000, None)]:
                path.write_bytes(payload)
                self.assertEqual(sha256_file(path), expected or hashlib.sha256(payload).hexdigest())

    def test_match_mismatch_and_invalid_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.txt"
            baseline = Path(directory) / "baseline.txt"
            path.write_bytes(b"abc")
            baseline.write_text(f"SHA256 artifact.txt {sha256_file(path).upper()}\n", encoding="utf-8")
            self.assertEqual(check_integrity(path, baseline)["status"], "MATCH")
            path.write_bytes(b"changed\r\n")
            self.assertEqual(check_integrity(path, baseline)["status"], "MISMATCH")
            for invalid in ["", "SHA256 artifact.txt invalid", "SHA256 wrong.txt " + "0" * 64]:
                baseline.write_text(invalid, encoding="utf-8")
                with self.assertRaises(ValueError):
                    check_integrity(path, baseline)

    def test_original_data_bytes_unchanged(self):
        manifest = json.loads((ROOT / "evidence/source_manifest.json").read_text(encoding="utf-8"))
        for relative, expected in manifest["sha256"].items():
            self.assertEqual(sha256_file(ROOT / relative), expected, relative)
        self.assertEqual(check_integrity()["status"], "MISMATCH")


class TracebackTests(unittest.TestCase):
    def test_valid_counts(self):
        for value, expected in [("5", 5), (" 0 ", 0), (3, 3)]:
            self.assertEqual(parse_failed_count(value), expected)

    def test_invalid_counts_fail_explicitly(self):
        for value in [None, "", "-1", "3.5", "abc", True, -1, 4.0, "²"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_failed_count(value)


class CliTests(unittest.TestCase):
    def run_script(self, name, *arguments):
        return subprocess.run([sys.executable, str(ROOT / name), *arguments],
                              cwd=tempfile.gettempdir(), capture_output=True, text=True,
                              encoding="utf-8", env=dict(os.environ, PYTHONIOENCODING="utf-8"))

    def test_default_paths_work_outside_project(self):
        for name in ["detector_starter.py", "hash_check_starter.py", "traceback_exercise.py"]:
            result = self.run_script(name)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_input_and_strict_mismatch_exit_codes(self):
        self.assertEqual(self.run_script("detector_starter.py", "--input", "no-such-soc-file.csv").returncode, 2)
        self.assertEqual(self.run_script("hash_check_starter.py", "--strict").returncode, 1)

    def test_json_is_valid_and_contains_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.json"
            result = self.run_script("detector_starter.py", "--json", str(path))
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["event_count"], 15)
            self.assertEqual(len(payload["findings"][0]["evidence"]), 6)


if __name__ == "__main__":
    unittest.main()
