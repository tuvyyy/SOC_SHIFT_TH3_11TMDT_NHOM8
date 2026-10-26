"""Bản sửa lỗi str >= int; traceback và bản lỗi gốc nằm trong evidence/."""
FAILURE_THRESHOLD = 4
records = [
    {"src_ip": "203.0.113.77", "failed_count": "5"},
    {"src_ip": "10.20.0.11", "failed_count": "1"},
    {"src_ip": "198.51.100.24", "failed_count": "3"},
]

def parse_failed_count(value):
    """Chỉ chấp nhận số nguyên không âm hoặc chuỗi chữ số ASCII không rỗng."""
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str):
        text = value.strip()
        if text and text.isascii() and text.isdecimal():
            return int(text)
    raise ValueError(f"failed_count phải là số nguyên không âm, nhận {value!r}")


def main():
    for record in records:
        failed_count = parse_failed_count(record["failed_count"])
        if failed_count >= FAILURE_THRESHOLD:
            print("ALERT", record["src_ip"], failed_count)


if __name__ == "__main__":
    main()
