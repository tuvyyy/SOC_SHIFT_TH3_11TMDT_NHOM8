"""Tính SHA-256 ở chế độ nhị phân và so với baseline, không sửa tệp mẫu."""
import argparse
import hashlib
import json
import re
from pathlib import Path
from console_utils import configure_console

BASE_DIR = Path(__file__).resolve().parent / "data"
FILE_TO_CHECK = BASE_DIR / "artifact.txt"
BASELINE_FILE = BASE_DIR / "hash_baseline.txt"
CHUNK_SIZE = 64 * 1024


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_integrity(file_path=FILE_TO_CHECK, baseline_path=BASELINE_FILE):
    fields = Path(baseline_path).read_text(encoding="utf-8-sig").strip().split()
    if len(fields) != 3 or fields[0].upper() != "SHA256":
        raise ValueError("Baseline phải có dạng: SHA256  tên_tệp  64_ký_tự_hex")
    if fields[1] != Path(file_path).name:
        raise ValueError("Tên tệp trong baseline không trùng tên tệp được kiểm tra")
    expected = fields[2].lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Baseline SHA-256 không hợp lệ")
    actual = sha256_file(file_path)
    return {"file": str(file_path), "baseline": str(baseline_path),
            "expected": expected, "actual": actual,
            "status": "MATCH" if actual == expected else "MISMATCH"}


def main(argv=None):
    configure_console()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, default=FILE_TO_CHECK)
    parser.add_argument("--baseline", type=Path, default=BASELINE_FILE)
    parser.add_argument("--json", type=Path, dest="json_path")
    parser.add_argument("--strict", action="store_true", help="Trả mã 1 nếu MISMATCH")
    args = parser.parse_args(argv)
    try:
        result = check_integrity(args.file, args.baseline)
        if args.json_path:
            args.json_path.parent.mkdir(parents=True, exist_ok=True)
            args.json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Lỗi: {exc}\n")
    print("Expected:", result["expected"])
    print("Actual:  ", result["actual"])
    print(result["status"])
    if result["status"] == "MISMATCH":
        print("Nội dung khác baseline; cần xác minh nguồn baseline và lịch sử thay đổi.")
        print("Hash mismatch không tự chứng minh mã độc hoặc người đã sửa tệp.")
    return 1 if args.strict and result["status"] == "MISMATCH" else 0


if __name__ == "__main__":
    raise SystemExit(main())
