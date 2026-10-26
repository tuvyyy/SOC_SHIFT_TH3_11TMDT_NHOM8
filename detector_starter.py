"""Phát hiện bất thường xác thực trên CSV mô phỏng; chỉ dùng thư viện chuẩn."""
import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from console_utils import configure_console

DATA_FILE = Path(__file__).resolve().parent / "data" / "auth_events.csv"
FAILURE_THRESHOLD = 4
SPRAY_UNIQUE_USERS_THRESHOLD = 3
REQUIRED_COLUMNS = {"timestamp", "user", "src_ip", "event", "asset", "details"}


def parse_timestamp(value):
    """Giữ giờ nguồn; không tự gán múi giờ cho timestamp thiếu offset."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_events(path):
    events = []
    with Path(path).open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        if not REQUIRED_COLUMNS.issubset(reader.fieldnames or []):
            raise ValueError("CSV thiếu cột bắt buộc: " + ", ".join(sorted(REQUIRED_COLUMNS)))
        for record_number, row in enumerate(reader, start=1):
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"Bản ghi {record_number}: số cột không hợp lệ")
            row = {key: value.strip() for key, value in row.items()}
            try:
                parse_timestamp(row["timestamp"])
                ip_address(row["src_ip"])
                if not row["user"] or not row["asset"]:
                    raise ValueError("user/asset không được rỗng")
                if row["event"] not in {"login_failed", "login_success"}:
                    raise ValueError("event phải là login_failed hoặc login_success")
            except ValueError as exc:
                raise ValueError(f"Bản ghi {record_number}: {exc}") from exc
            row["record_number"] = record_number
            events.append(row)
    return events


def detect(events):
    """Gom toàn file theo IP; hai ngưỡng độc lập; đối chiếu đúng thứ tự thời gian.

    HIGH khi ngưỡng fail hoặc spray đã đạt trước một success từ cùng IP.
    """
    events = list(events)
    awareness = {parse_timestamp(row["timestamp"]).utcoffset() is not None for row in events}
    if len(awareness) > 1:
        raise ValueError("Không trộn timestamp có offset và thiếu offset trong cùng file")
    ordered = sorted(events, key=lambda row: parse_timestamp(row["timestamp"]))
    failures_by_ip = Counter()
    failed_users_by_ip = defaultdict(set)
    failures = defaultdict(list)
    successful_by_ip = defaultdict(list)
    for row in ordered:
        ip = row["src_ip"]
        if row["event"] == "login_failed":
            failures_by_ip[ip] += 1
            failed_users_by_ip[ip].add(row["user"])
            failures[ip].append(row)
        elif row["event"] == "login_success":
            successful_by_ip[ip].append(row)

    findings = []
    for ip, count in failures_by_ip.items():
        users = sorted(failed_users_by_ip[ip])
        reasons = []
        rules = []
        if count >= FAILURE_THRESHOLD:
            rules.append("REPEATED_FAILURES")
            reasons.append(f"{count} lần login_failed (ngưỡng {FAILURE_THRESHOLD})")
        if len(users) >= SPRAY_UNIQUE_USERS_THRESHOLD:
            rules.append("POSSIBLE_PASSWORD_SPRAY")
            reasons.append(f"{len(users)} tài khoản bị thử (ngưỡng {SPRAY_UNIQUE_USERS_THRESHOLD}); giả thuyết password spraying")
        if not rules:
            continue
        success_after = []
        for success in successful_by_ip[ip]:
            before = [failure for failure in failures[ip]
                      if parse_timestamp(failure["timestamp"]) < parse_timestamp(success["timestamp"])]
            if not before:
                continue
            before_users = {row["user"] for row in before}
            success_after.append({
                **success,
                "failures_before_success": len(before),
                "same_user_failed_before": success["user"] in before_users,
                "threshold_reached_before_success": (
                    len(before) >= FAILURE_THRESHOLD
                    or len(before_users) >= SPRAY_UNIQUE_USERS_THRESHOLD
                ),
            })
        priority = "HIGH" if any(row["threshold_reached_before_success"] for row in success_after) else "MEDIUM"
        if success_after:
            reasons.append("Có login_success sau login_failed: cần đối chiếu thời gian / phiên / MFA; chưa đủ kết luận tài khoản bị chiếm")
        elif successful_by_ip[ip]:
            reasons.append("Có login_success nhưng không có success muộn hơn fail; cần đối chiếu thời gian / phiên / MFA")
        findings.append({
            "src_ip": ip, "priority": priority, "rules": rules,
            "failed_count": count, "unique_failed_users": len(users), "users": users,
            "assets": sorted({row["asset"] for row in failures[ip]}),
            "first_failure": failures[ip][0]["timestamp"],
            "last_failure": failures[ip][-1]["timestamp"],
            "reasons": reasons, "success_after_failures": success_after,
            "evidence": failures[ip] + successful_by_ip[ip],
        })
    return sorted(findings, key=lambda item: (item["priority"] != "HIGH", item["src_ip"]))


def main(argv=None):
    configure_console()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DATA_FILE, help="CSV đầu vào")
    parser.add_argument("--json", type=Path, dest="json_path", help="Xuất cảnh báo và bằng chứng JSON")
    args = parser.parse_args(argv)
    try:
        events = load_events(args.input)
        findings = detect(events)
        if args.json_path:
            args.json_path.parent.mkdir(parents=True, exist_ok=True)
            args.json_path.write_text(json.dumps({
                "input": str(args.input), "event_count": len(events),
                "scope": "entire_file", "failure_threshold": FAILURE_THRESHOLD,
                "spray_unique_users_threshold": SPRAY_UNIQUE_USERS_THRESHOLD,
                "findings": findings,
            }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, csv.Error) as exc:
        parser.exit(2, f"Lỗi: {exc}\n")
    print(f"Đã đọc {len(events)} sự kiện; {len(findings)} IP cần kiểm tra (toàn bộ file).")
    for item in findings:
        print(f"\n[{item['priority']}] IP={item['src_ip']} | failed={item['failed_count']} | users={', '.join(item['users'])}")
        for reason in item["reasons"]:
            print(f"  - {reason}")
        for row in item["evidence"]:
            print(f"    {row['timestamp']} | {row['user']} | {row['event']} | {row['asset']} | {row['details']}")
    if not findings:
        print("Không có IP đạt ngưỡng; kết quả này không chứng minh hệ thống an toàn.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
