# SOC SHIFT - TH3 - 11TMDT - Nhóm 8

Dashboard trình duyệt và bài làm đã hoàn thiện, gồm code, bằng chứng chạy, research và báo cáo sự cố.

## Mở giao diện

```powershell
python app.py
```

Trình duyệt tự mở tại **http://127.0.0.1:8765**. Hoặc nhấp đúp `MO_DASHBOARD.cmd`. Giữ cửa sổ chạy Python để sử dụng dashboard; nhấn Ctrl+C để dừng.

Giao diện đi theo thứ tự **Log → Kiểm tra tệp → Sửa lỗi Python → Báo cáo**. Hai nhóm log có nút chọn sẵn; kiểm tra hash mẫu bằng một nút; chạy bản gốc và bản sửa riêng từng bước. Chỉ dùng thư viện chuẩn Python, xử lý cục bộ trên máy.

Phân công: **Anh Khôi** — điều tra và research; **Tú Vy** — lập trình phát hiện; **Phước Thịnh** — lập trình kiểm chứng. Chi tiết vai trò kiêm nhiệm và công việc chung nằm trong báo cáo và bài làm.

Sau khi cập nhật code: dừng server bằng Ctrl+C, chạy lại `python app.py` rồi nhấn Ctrl+F5 trong trình duyệt.

## Chạy dòng lệnh và kiểm thử

Yêu cầu Python 3.10+; không cần cài thư viện bên ngoài.

```powershell
python run_all.py
python -m unittest discover -s tests -v
```

32 kiểm thử Python đều đạt (21 core và 11 API); thêm 10 tình huống tương tác DOM với server thật đã đạt. Bản traceback hiện tại đã sửa; bản lỗi gốc và traceback trước/sau được giữ tại `evidence/`.

## Tài liệu nộp bài

- [Flow demo: bấm nút nào và nói gì](FLOW_DEMO.md)
- [Hướng dẫn chạy, đầu ra và giới hạn](HUONG_DAN_CHAY.md)
- [Bài làm đầy đủ và FLAG 1–4](BAI_LAM_SOC_SHIFT.md)
- [Phiếu research](PHIEU_RESEARCH.md)
- [Báo cáo sự cố ngắn](BAO_CAO_SU_CO.md)
- [Cảnh báo JSON](evidence/findings.json)
- [Kết quả hash](evidence/hash_result.json)

Dữ liệu giữ nguyên từng byte so với ZIP đã cung cấp. `MISMATCH` là kết quả cần ghi nhận của bài hash.

## An toàn
Đây là dữ liệu mô phỏng. Các địa chỉ IP trong log thuộc dải dành cho tài liệu minh họa,
không phải IOC thật. Không chạy tấn công lên hệ thống thật, không thực thi mã lạ lấy từ mạng,
không đăng tải log có dữ liệu cá nhân lên dịch vụ bên ngoài. Chỉ nghiên cứu thông tin công khai.
