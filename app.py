"""SOC SHIFT browser dashboard. Run: python app.py (Python standard library)."""
import argparse
import base64
import binascii
import csv
import json
import os
import subprocess
import sys
import tempfile
import threading
import webbrowser
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from console_utils import configure_console
from detector_starter import (DATA_FILE, FAILURE_THRESHOLD, SPRAY_UNIQUE_USERS_THRESHOLD,
                              detect, load_events, parse_timestamp)
from hash_check_starter import check_integrity

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
MAX_REQUEST_BYTES = 4 * 1024 * 1024
DOCUMENTS = {
    "report": "BAO_CAO_SU_CO.md",
    "research": "PHIEU_RESEARCH.md",
    "assignment": "BAI_LAM_SOC_SHIFT.md",
    "guide": "HUONG_DAN_CHAY.md",
}


def summarize(events, source):
    findings = detect(events)
    ordered = sorted(events, key=lambda row: parse_timestamp(row["timestamp"]))
    failures = Counter(row["src_ip"] for row in events if row["event"] == "login_failed")
    return {
        "source": source,
        "events": ordered,
        "findings": findings,
        "stats": {
            "total": len(events),
            "failed": sum(row["event"] == "login_failed" for row in events),
            "success": sum(row["event"] == "login_success" for row in events),
            "unique_ips": len({row["src_ip"] for row in events}),
            "high": sum(item["priority"] == "HIGH" for item in findings),
            "medium": sum(item["priority"] == "MEDIUM" for item in findings),
            "first": ordered[0]["timestamp"] if ordered else None,
            "last": ordered[-1]["timestamp"] if ordered else None,
        },
        "failures_by_ip": dict(failures.most_common()),
        "scope": "entire_file",
        "failure_threshold": FAILURE_THRESHOLD,
        "spray_unique_users_threshold": SPRAY_UNIQUE_USERS_THRESHOLD,
    }


def analyze_csv(content, filename):
    if not isinstance(content, str) or not isinstance(filename, str):
        raise ValueError("CSV và tên tệp phải là chuỗi")
    with tempfile.TemporaryDirectory(prefix="soc_upload_") as directory:
        path = Path(directory) / "uploaded.csv"
        path.write_text(content, encoding="utf-8")
        return summarize(load_events(path), filename[:240])


def uploaded_hash(encoded, baseline, filename):
    if not all(isinstance(value, str) for value in (encoded, baseline, filename)):
        raise ValueError("Dữ liệu tệp không hợp lệ")
    if (not filename or filename in {".", ".."} or len(filename) > 200
            or any(char in filename for char in '\\/:*?"<>|\x00')):
        raise ValueError("Tên tệp không hợp lệ")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Nội dung tệp không phải base64 hợp lệ") from exc
    with tempfile.TemporaryDirectory(prefix="soc_hash_") as directory:
        folder = Path(directory)
        (folder / "artifact").mkdir()
        path = folder / "artifact" / filename
        path.write_bytes(payload)
        baseline_path = folder / "expected.sha256"
        baseline_path.write_text(baseline, encoding="utf-8")
        result = check_integrity(path, baseline_path)
    result.update(file=filename, baseline="Baseline đã chọn")
    return result


def run_traceback(version=None):
    if version is not None and (not isinstance(version, str) or version not in {"before", "after"}):
        raise ValueError("Phiên bản phải là before hoặc after")
    results = {}
    for name, script in [("before", ROOT / "evidence/original/traceback_exercise.py"),
                         ("after", ROOT / "traceback_exercise.py")]:
        if version is not None and name != version:
            continue
        result = subprocess.run([sys.executable, str(script)], cwd=ROOT,
                                env=dict(os.environ, PYTHONIOENCODING="utf-8"),
                                capture_output=True, text=True, encoding="utf-8", timeout=5)
        results[name] = {"output": result.stdout + result.stderr, "exit_code": result.returncode}
    return results


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "SOCShift/1.0"

    def send_data(self, data, content_type, status=200, filename=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, payload, status=200):
        self.send_data(json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8", status)

    def do_GET(self):
        route = urlsplit(self.path)
        try:
            if route.path == "/api/dashboard":
                self.send_json({"analysis": summarize(load_events(DATA_FILE), DATA_FILE.name),
                                "hash": check_integrity(), "dataset": "sample"})
            elif route.path == "/api/sample-hash":
                self.send_json(check_integrity())
            elif route.path == "/api/document":
                key = parse_qs(route.query).get("name", ["report"])[0]
                if key not in DOCUMENTS:
                    self.send_json({"error": "Không tìm thấy tài liệu"}, 404)
                    return
                self.send_json({"filename": DOCUMENTS[key],
                                "content": (ROOT / DOCUMENTS[key]).read_text(encoding="utf-8")})
            elif route.path in {"/", "/styles.css", "/app.js"}:
                name, kind = {"/": ("index.html", "text/html"),
                              "/styles.css": ("styles.css", "text/css"),
                              "/app.js": ("app.js", "application/javascript")}[route.path]
                self.send_data((WEB / name).read_bytes(), kind + "; charset=utf-8")
            elif route.path == "/favicon.ico":
                self.send_data(b"", "image/x-icon", 204)
            else:
                self.send_json({"error": "Không tìm thấy đường dẫn"}, 404)
        except (OSError, ValueError, csv.Error) as exc:
            self.send_json({"error": str(exc)}, 400)

    def do_POST(self):
        # Local compute endpoints: no uploads are retained or written to the source dataset.
        origin = self.headers.get("Origin")
        if origin and origin != f"http://{self.headers.get('Host')}":
            self.send_json({"error": "Nguồn yêu cầu không hợp lệ"}, 403)
            return
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            self.send_json({"error": "Yêu cầu application/json"}, 415)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > MAX_REQUEST_BYTES:
                self.send_json({"error": "Tệp quá lớn hoặc rỗng (giới hạn yêu cầu 4 MiB)"}, 413)
                return
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(body, dict):
                raise ValueError("Nội dung yêu cầu phải là JSON object")
            if self.path == "/api/analyze":
                self.send_json(analyze_csv(body["csv"], body.get("filename", "uploaded.csv")))
            elif self.path == "/api/hash":
                self.send_json(uploaded_hash(body["file_base64"], body["baseline"], body["filename"]))
            elif self.path == "/api/traceback":
                self.send_json(run_traceback(body.get("version")))
            else:
                self.send_json({"error": "Không tìm thấy đường dẫn"}, 404)
        except (OSError, ValueError, KeyError, csv.Error, subprocess.TimeoutExpired) as exc:
            self.send_json({"error": str(exc)}, 400)


def main():
    configure_console()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), DashboardHandler)
    except OSError as exc:
        parser.exit(1, f"Không mở được cổng {args.port}: {exc}\nThử: python app.py --port 8766\n")
    url = f"http://127.0.0.1:{server.server_port}"
    print(f"SOC SHIFT Dashboard: {url}\nNhấn Ctrl+C để dừng. Dữ liệu chỉ xử lý trên máy này.")
    if not args.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nĐã dừng dashboard.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
