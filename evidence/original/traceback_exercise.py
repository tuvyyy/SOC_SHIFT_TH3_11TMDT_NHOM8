"""Chạy file này để xem traceback có chủ đích. Đây là lỗi kiểu dữ liệu, không phải mã độc."""
records = [
    {"src_ip": "203.0.113.77", "failed_count": "5"},
    {"src_ip": "10.20.0.11", "failed_count": "1"},
    {"src_ip": "198.51.100.24", "failed_count": "3"},
]

for record in records:
    # Bug có chủ đích: failed_count là chuỗi, nhưng lại so sánh với số nguyên.
    if record["failed_count"] >= 4:
        print("ALERT", record["src_ip"], record["failed_count"])
