"""Chạy ba ticket và lưu đầu ra thật vào evidence/ bằng một lệnh."""
import json
import os
import subprocess
import sys
from pathlib import Path
from console_utils import configure_console
from hash_check_starter import sha256_file

ROOT = Path(__file__).resolve().parent


def main():
    configure_console()
    evidence = ROOT / "evidence"
    evidence.mkdir(exist_ok=True)
    manifest = json.loads((evidence / "source_manifest.json").read_text(encoding="utf-8"))
    for relative_path, expected in manifest["sha256"].items():
        if sha256_file(ROOT / relative_path) != expected:
            raise ValueError(f"Dữ liệu gốc đã thay đổi: {relative_path}; dừng để bảo toàn bằng chứng")
    jobs = [
        ("detector_output.txt", ["detector_starter.py", "--json", "evidence/findings.json"]),
        ("hash_output.txt", ["hash_check_starter.py", "--json", "evidence/hash_result.json"]),
        ("traceback_after.txt", ["traceback_exercise.py"]),
    ]
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    failed = False
    for output_name, arguments in jobs:
        result = subprocess.run([sys.executable, *arguments], cwd=ROOT, env=env,
                                capture_output=True, text=True, encoding="utf-8")
        content = result.stdout + result.stderr
        (evidence / output_name).write_text(content, encoding="utf-8")
        print(f"\n>>> python {' '.join(arguments)} (exit={result.returncode})")
        print(content, end="")
        failed = failed or result.returncode != 0
    print("\nĐã lưu kết quả tại evidence/. MISMATCH là phát hiện của bài hash.")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
