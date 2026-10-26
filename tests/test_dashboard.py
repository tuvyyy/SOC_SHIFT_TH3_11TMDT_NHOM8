"""Exercise the actual local HTTP API and existing Python analysis together."""
import base64
import hashlib
import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from app import DashboardHandler


class QuietHandler(DashboardHandler):
    def log_message(self, *args):
        pass


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def request(self, path, body=None, origin=None):
        headers = {"Content-Type": "application/json"}
        if origin:
            headers["Origin"] = origin
        request = urllib.request.Request(self.url + path,
                                         data=None if body is None else json.dumps(body).encode(),
                                         headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), exc.headers

    def test_dashboard_uses_real_sample_analysis(self):
        status, body, _ = self.request("/api/dashboard")
        result = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(result["analysis"]["stats"]["total"], 15)
        self.assertEqual(result["analysis"]["stats"]["high"], 1)
        self.assertEqual(result["hash"]["status"], "MISMATCH")

    def test_uploaded_csv_is_analyzed_without_hardcoded_ips(self):
        content = "timestamp,user,src_ip,event,asset,details\n"
        content += "".join(f"2026-10-16T09:00:0{i},tester,192.0.2.123,login_failed,vpn,test\n" for i in range(4))
        status, body, _ = self.request("/api/analyze", {"csv": content, "filename": "new.csv"})
        result = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(result["findings"][0]["src_ip"], "192.0.2.123")
        self.assertEqual(result["source"], "new.csv")
        self.assertEqual(json.loads(self.request("/api/dashboard")[1])["analysis"]["stats"]["total"], 15)

    def test_empty_csv_with_header_has_zero_findings(self):
        status, body, _ = self.request("/api/analyze", {"csv": "timestamp,user,src_ip,event,asset,details\n"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["findings"], [])

    def test_bad_csv_returns_readable_error(self):
        status, body, _ = self.request("/api/analyze", {"csv": "bad,data\n"})
        self.assertEqual(status, 400)
        self.assertIn("error", json.loads(body))

    def test_uploaded_binary_hash_match_and_mismatch(self):
        payload = bytes(range(256))
        body = {"filename": "binary.dat", "file_base64": base64.b64encode(payload).decode(),
                "baseline": f"SHA256 binary.dat {hashlib.sha256(payload).hexdigest()}"}
        status, result, _ = self.request("/api/hash", body)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(result)["status"], "MATCH")
        body["baseline"] = "SHA256 binary.dat " + "0" * 64
        self.assertEqual(json.loads(self.request("/api/hash", body)[1])["status"], "MISMATCH")

    def test_hash_rejects_path_traversal_and_bad_base64(self):
        for filename, encoded in [("../artifact.txt", "YQ=="), ("artifact.txt", "!bad!")]:
            status, _, _ = self.request("/api/hash", {"filename": filename,
                "file_base64": encoded, "baseline": "SHA256 artifact.txt " + "0" * 64})
            self.assertEqual(status, 400)

    def test_traceback_runs_both_versions(self):
        status, body, _ = self.request("/api/traceback", {})
        result = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(result["before"]["exit_code"], 1)
        self.assertIn("TypeError", result["before"]["output"])
        self.assertEqual(result["after"]["exit_code"], 0)
        self.assertIn("ALERT 203.0.113.77 5", result["after"]["output"])

    def test_traceback_can_run_each_step_separately(self):
        for version, expected_code in [("before", 1), ("after", 0)]:
            status, body, _ = self.request("/api/traceback", {"version": version})
            result = json.loads(body)
            self.assertEqual(status, 200)
            self.assertEqual(list(result), [version])
            self.assertEqual(result[version]["exit_code"], expected_code)
        for invalid in ["unknown", [], 7]:
            self.assertEqual(self.request("/api/traceback", {"version": invalid})[0], 400)

    def test_sample_hash_runs_as_independent_action(self):
        status, body, _ = self.request("/api/sample-hash")
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertEqual(result["status"], "MISMATCH")
        self.assertNotEqual(result["expected"], result["actual"])

    def test_documents_and_assets_are_available(self):
        for path in ["/", "/styles.css", "/app.js", "/styles.css?v=2", "/app.js?v=2", "/api/document?name=report",
                     "/api/document?name=research", "/api/document?name=assignment"]:
            status, body, headers = self.request(path)
            self.assertEqual(status, 200, path)
            self.assertTrue(body)
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(self.request("/api/document?name=../app.py")[0], 404)
        self.assertEqual(self.request("/../app.py")[0], 404)

    def test_cross_origin_request_is_rejected(self):
        self.assertEqual(self.request("/api/traceback", {}, origin="https://example.com")[0], 403)


if __name__ == "__main__":
    unittest.main()
