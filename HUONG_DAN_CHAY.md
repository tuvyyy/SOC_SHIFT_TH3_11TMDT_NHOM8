# SOC SHIFT - Hướng dẫn chạy

Python 3.10 trở lên, chỉ dùng thư viện chuẩn, không cần `pip install`.

Demo theo [FLOW_DEMO.md](FLOW_DEMO.md): thao tác và lời nói ngắn cho từng màn hình.

## Giao diện trình duyệt

```powershell
cd C:\SOC_SHIFT_TH3_11TMDT_NHOM8
python app.py
```

Trình duyệt tự mở `http://127.0.0.1:8765`. Có thể nhấp đúp `MO_DASHBOARD.cmd` thay cho nhập lệnh. Giữ cửa sổ Python đang chạy; Ctrl+C để dừng. Nếu cổng bị dùng, chạy `python app.py --port 8766`. `--no-browser` chạy server mà không tự mở trình duyệt.

Sau khi cập nhật code, Ctrl+C dừng server cũ, chạy lại `python app.py` rồi nhấn Ctrl+F5 trong trình duyệt.

1. **Tổng quan:** bấm “Xem 6 dòng log” hoặc “Xem 3 dòng log” để mở bằng chứng của từng phát hiện. Biểu đồ và ngưỡng được thu gọn trong “Biểu đồ và quy tắc phát hiện”.
2. **Log đăng nhập:** chọn “Fail rồi thành công” để xem 5 fail và 1 success (dòng xanh). Chọn “Nhiều tài khoản” để xem mai, binh, chi. Không cần gõ IP. “Tất cả log” bỏ lọc nhóm; vẫn có tìm kiếm, lọc kết quả, sắp xếp và xuất CSV. Bật “Log gốc” để xem event/details đúng nguyên văn.
3. **Kiểm tra tệp:** giữ “Dữ liệu bài tập”, bấm “So sánh SHA-256”. Kết quả hiện hai hash và MISMATCH. Muốn thử tệp riêng, chọn “Chọn tệp khác”, tải artifact và baseline lên rồi bấm cùng nút. Khi đổi đầu vào, kết quả cũ được xóa để tránh nhầm.
4. **Sửa lỗi Python:** bấm “1. Chạy bản gốc” để thấy TypeError. Sau đó nút “2. Chạy bản sửa” được bật; bấm để thấy kết quả ALERT và mã thoát 0. Traceback dài được thu gọn trong “Xem traceback đầy đủ”.
5. **Báo cáo:** đọc báo cáo, nguồn tham khảo hoặc bài làm/FLAG. Tài liệu được soạn cho dataset mẫu, không tự viết lại khi tải CSV khác.

Mỗi màn hình có nút “Tiếp” ở cuối để đi theo thứ tự bài. “Đổi CSV” chỉ xuất hiện ở tổng quan/log; chọn tệp khác không ghi đè dữ liệu mẫu. “Dùng lại mẫu” quay về dữ liệu gốc.

Dashboard giới hạn tệp tải lên 2 MiB, baseline 16 KiB. Tệp chọn chỉ được xử lý tạm trên máy, không lưu vào dữ liệu gốc. Bảng log hiển thị tối đa 1.000 kết quả; xuất CSV vẫn lấy tất cả kết quả lọc. Biểu đồ tự gộp nếu có trên 24 nhóm. Server chỉ lắng nghe `127.0.0.1`; không cần tài khoản hoặc kết nối dịch vụ bên ngoài.

## Chạy bằng dòng lệnh

```powershell
cd C:\SOC_SHIFT_TH3_11TMDT_NHOM8
python run_all.py
python -m unittest discover -s tests -v
```

`run_all.py` chạy detector, kiểm tra hash, bản sửa traceback và lưu đầu ra thật vào `evidence/`. Runner đối chiếu dữ liệu với manifest gốc trước khi chạy; nếu chủ động thay log, hãy chạy detector trực tiếp với `--input`.

Chạy riêng từng ticket:

```powershell
python detector_starter.py
python detector_starter.py --input data/auth_events.csv --json evidence/findings.json
python hash_check_starter.py --json evidence/hash_result.json
python traceback_exercise.py
```

`hash_check_starter.py --strict` trả mã thoát 1 khi mismatch; mặc định trả 0 khi đã kiểm tra xong, kể cả mismatch. Lỗi đọc dữ liệu/sai định dạng trả 2. Detector trả 0 khi xử lý xong, kể cả có cảnh báo.

## Kết quả dữ liệu mẫu

| Phần | Kết quả |
| --- | --- |
| Detector | 15 sự kiện, 2 IP đạt ngưỡng |
| HIGH | `203.0.113.77`: 5 fail; admin success sau đó, MFA chưa rõ |
| MEDIUM | `198.51.100.24`: 3 fail trên 3 tài khoản, nghi spraying |
| Hash | `MISMATCH`, không thay đổi artifact/baseline |
| Traceback đã sửa | `ALERT 203.0.113.77 5`, exit 0 |
| Kiểm thử | 32 test Python (21 core + 11 API), 10 tình huống DOM/API |

## Cấu trúc bài

- `BAI_LAM_SOC_SHIFT.md`: phân công Anh Khôi, Tú Vy, Phước Thịnh; giả thuyết, triage, timeline, FLAG 1–4, giải thích code/hash/traceback và debrief.
- `PHIEU_RESEARCH.md`: truy vấn thật, bài LinkedIn, tác giả/ngày đăng, nguồn kiểm chứng và đánh giá.
- `BAO_CAO_SU_CO.md`: báo cáo ngắn theo 5 mục của đề.
- Ba script `detector_starter.py`, `hash_check_starter.py`, `traceback_exercise.py` và `console_utils.py`: mã đã hoàn thiện.
- `evidence/`: đầu ra chạy thật, JSON cảnh báo/hash, traceback trước/sau, manifest gốc và kết quả test.
- `tests/test_soc_shift.py`: kiểm thử quy tắc và tình huống biên.
- `app.py`, `web/`, `MO_DASHBOARD.cmd`: server cục bộ, giao diện HTML/CSS/JavaScript và tệp khởi động.
- `tests/test_dashboard.py`: kiểm thử HTTP thật với CSV/hash tải lên, lỗi đầu vào, traceback và tài liệu.
- `tools/check_dashboard_ui.cjs`: kiểm tra 10 tình huống thao tác qua DOM và server Python thật, không phải kiểm tra hiển thị trực quan. Chỉ chạy khi phát triển: `npm install --prefix tmp/ui-dom --no-save linkedom`, rồi `node tools/check_dashboard_ui.cjs`. Không cần Node hoặc package này để mở dashboard.

## Quy tắc và giới hạn

Detector đếm trên **toàn bộ file**, không dùng cửa sổ trượt 10 phút. Đã làm phần mở rộng xuất JSON. Ngưỡng ở hằng số: ít nhất 4 fail **hoặc** ít nhất 3 user thất bại khác nhau. MEDIUM khi đạt một trong hai ngưỡng; HIGH khi success xuất hiện sau khi đã đạt ngưỡng trên cùng IP. Đây là mức ưu tiên điều tra, không phải kết luận xâm nhập.

Detector sắp xếp timestamp, không phụ thuộc thứ tự dòng CSV; timestamp bằng nhau không chứng minh trước/sau. CSV thiếu cột, IP/thời gian sai hoặc event ngoài hai loại đăng nhập sẽ bị báo lỗi. Không trộn timestamp có offset và thiếu offset. Gom theo IP có thể tạo cảnh báo nhầm với NAT/VPN dùng chung; cần đối chiếu user/asset/session/MFA.

Timestamp mẫu không có múi giờ; báo cáo giữ nguyên giờ nguồn. IP public là địa chỉ minh họa, `10.20.0.x` là IP private mô phỏng. Không gửi log lên web hoặc chạy mã từ nguồn research. Phân công theo danh sách nhóm cung cấp: Anh Khôi phụ trách điều tra/research; Tú Vy lập trình phát hiện; Phước Thịnh lập trình kiểm chứng.
