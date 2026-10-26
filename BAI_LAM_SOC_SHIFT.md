# Bài thực hành SOC SHIFT

**Nhóm 8 - TH3 - 11TMDT | Ngày: 16/10/2026 | SOC-0815 / PY-LOG / FILE-HASH / PY-CRASH / RESEARCH**

## 1. Phân công Nhóm 8 và giả thuyết ban đầu

| Thành viên | Vai trò kiêm nhiệm | Công việc phụ trách |
| --- | --- | --- |
| **Anh Khôi** | Incident Commander + Log Hunter + OSINT Researcher | Phân tích log CSV, tìm IP bất thường, lập timeline, nghiên cứu MITRE và nguồn tham khảo, viết nhận định sự cố và đề xuất ứng phó. |
| **Tú Vy** | Python Analyst + Detection Developer | Hoàn thiện Python Detector, xử lý điều kiện cảnh báo, kiểm thử với dữ liệu log, xây dựng phần hiển thị kết quả phát hiện. |
| **Phước Thịnh** | Python Analyst + Technical Reporter | Xử lý SHA-256, sửa lỗi traceback, xây dựng phần hiển thị kiểm tra tệp và sửa lỗi, tích hợp kết quả kỹ thuật vào báo cáo. |

### Sản phẩm của từng thành viên

- **Anh Khôi — phân tích và điều tra:** log, timeline, OSINT, đánh giá và đề xuất ứng phó; không phụ trách lập trình.
- **Tú Vy — lập trình phát hiện:** Detector Python, logic cảnh báo, kiểm thử log và giao diện kết quả; phụ trách code chính của nhóm chức năng phát hiện.
- **Phước Thịnh — lập trình kiểm chứng:** hash checker, traceback repair, giao diện kỹ thuật và tích hợp báo cáo; phụ trách code chính của nhóm chức năng kiểm chứng.

### Phần cả nhóm làm chung

- **Báo cáo cuối:** Anh Khôi tổng hợp nội dung; Tú Vy và Phước Thịnh cung cấp bằng chứng kỹ thuật.
- **Kiểm thử ứng dụng:** Tú Vy và Phước Thịnh kiểm tra chức năng; Anh Khôi đối chiếu kết quả với yêu cầu bài thực hành.
- **Demo:** cả ba cùng chuẩn bị; có thể phân phần trình bày hoặc chọn một người đại diện.

### Giả thuyết ban đầu

Giả thuyết ban đầu: có hoạt động đoán mật khẩu; một nguồn có thể thử nhiều tài khoản; success sau fail có thể là người dùng hợp lệ hoặc truy cập trái phép. Hash khác có thể do thay đổi được phép, sai phiên bản/baseline, khác byte xuống dòng hoặc thay đổi không được phép. Crash có thể do lỗi dữ liệu/kiểu dữ liệu. Chưa có bằng chứng nối việc sửa file với phiên VPN.

## 2. Triage log và FLAG 1

Nguồn: `data/auth_events.csv`, 15 bản ghi: **10 fail, 5 success**. Bảng dùng toàn bộ file. Timestamp giữ nguyên giờ nguồn, chưa xác định múi giờ. Số thứ tự bản ghi không tính header/dòng trống.

| IP | Fail | User thất bại | Success | Đánh giá |
| --- | ---: | --- | ---: | --- |
| `203.0.113.77` | 5 | admin, root | 1 | HIGH: chuỗi fail và admin success sau đó |
| `198.51.100.24` | 3 | mai, binh, chi | 0 | MEDIUM: 3 user khác nhau, nghi spraying |
| `10.20.0.11` | 1 | linh | 2 | Chưa đạt ngưỡng; reason=typo, success sau có MFA=passed |
| `192.0.2.44` | 1 | guest | 0 | Chưa đạt ngưỡng; tiếp tục theo dõi |
| `10.20.0.12` | 0 | Không có | 1 | Không đạt quy tắc cảnh báo |
| `10.20.0.15` | 0 | Không có | 1 | Không đạt quy tắc cảnh báo |

`203.0.113.77` có 4 fail của admin và 1 fail của root; root có `reason=unknown_user`, không suy ra root tồn tại. `198.51.100.24` thử 3 user trong 35 giây, là giả thuyết spraying; log không ghi mật khẩu nên không chứng minh cùng mật khẩu được dùng trên các user.

**FLAG 1:** ưu tiên kiểm tra `203.0.113.77`, đặc biệt phiên admin. Hai bản ghi gốc làm bằng chứng tối thiểu (bản ghi 3 và 8):

```text
2026-10-16T08:10:01,admin,203.0.113.77,login_failed,vpn-gateway,reason=bad_password
2026-10-16T08:11:12,admin,203.0.113.77,login_success,vpn-gateway,MFA=unknown; session_created=true
```

Toàn bộ 6 sự kiện của IP này có trong `evidence/detector_output.txt` và `evidence/findings.json`. `MFA=unknown` không đồng nghĩa MFA thất bại hoặc bị vượt qua.

### Timeline 5 sự kiện quan trọng

Tất cả ngày 16/10/2026, asset `vpn-gateway`.

| Timestamp | User | IP | Event | Lý do chọn |
| --- | --- | --- | --- | --- |
| 08:10:01 | admin | 203.0.113.77 | login_failed | Bắt đầu chuỗi sai mật khẩu |
| 08:10:39 | admin | 203.0.113.77 | login_failed | Fail thứ 4 từ IP, chạm ngưỡng |
| 08:11:12 | admin | 203.0.113.77 | login_success | Success sau 5 fail; phiên được tạo, MFA chưa rõ |
| 08:14:05 | mai | 198.51.100.24 | login_failed | Bắt đầu cụm nhiều user |
| 08:14:40 | chi | 198.51.100.24 | login_failed | User thứ 3 sau mai/binh, chạm ngưỡng spray |

Năm sự kiện trên đều trước mốc ticket 08:15. File còn log sau 08:15; chúng chỉ dùng trong rà soát toàn file, không được coi là đã biết khi nhận ticket.

## 3. Detector Python

`detector_starter.py` dùng `csv.DictReader`, `Counter` và tập user theo IP. Hằng số `FAILURE_THRESHOLD = 4`, `SPRAY_UNIQUE_USERS_THRESHOLD = 3`. Hai quy tắc độc lập nên không bỏ sót IP có 3 fail trên 3 user.

Sắp xếp timestamp trước khi đối chiếu. Success phải muộn hơn fail; để nâng HIGH, ngưỡng fail hoặc user phải đạt trước success đó. Mỗi success kèm số fail trước đó và việc user có từng fail. MEDIUM/HIGH là ưu tiên cục bộ của bài, không khẳng định tài khoản bị chiếm.

Đầu ra có IP, ưu tiên, số fail, user, lý do, thời gian và bằng chứng. Mở rộng: `--input`, `--json`. Không hard-code IP/kết quả dataset. Đếm toàn file; chưa triển khai cửa sổ trượt 10 phút.

```powershell
python detector_starter.py --json evidence/findings.json
```

### Giao diện thao tác

Chạy `python app.py` để mở dashboard tại `http://127.0.0.1:8765`, hoặc nhấp đúp `MO_DASHBOARD.cmd`. Giao diện gọi trực tiếp detector/hash checker Python, có biểu đồ, lọc log, xem bằng chứng, tải CSV, kiểm tra tệp, đối chiếu traceback và đọc báo cáo. Chỉ dùng thư viện chuẩn Python; không cần cài thêm package. Tệp tải lên xử lý tạm và không ghi đè dữ liệu gốc.

## 4. SHA-256 và FLAG 2

`sha256_file()` mở `rb`, đọc khối 64 KiB, cập nhật `hashlib.sha256()` rồi trả `hexdigest()`.

```text
Expected: bada325b6efa645b6272c257ee01add7c061dffba9e3c233621ed832d320994c
Actual:   adf82e65e0c245e5a86d868fcf5869c77da573171e36b6f1730059bf4324f138
Result:   MISMATCH
```

**FLAG 2:** hash thực tế khác hash ticket cung cấp: file hiện tại không khớp dấu vân tay baseline. Chưa chứng minh mã độc, người sửa, thời điểm sửa hoặc quan hệ với VPN. Tệp mẫu và baseline giữ nguyên.

Hai bước tiếp theo:

1. Giữ bản sao bằng chứng, ghi SHA-256, thời điểm/người thu thập và quyền truy cập; lấy bản chuẩn, xác thực nguồn và phiên bản baseline từ chủ hệ thống.
2. So sánh với bản chuẩn, đối chiếu ticket thay đổi, lịch sử phiên bản, audit chỉnh sửa và quyền truy cập; chỉ khôi phục sau khi xác minh theo quy trình.

File có `backup_enabled=false`; chưa có nội dung bản chuẩn nên không khẳng định đây là dòng bị sửa. `evidence/source_manifest.json` ghi hash của byte mẫu trong ZIP để kiểm tra việc giữ nguyên dữ liệu khi làm bài; **khác** baseline tin cậy của ticket.

## 5. Traceback repair và FLAG 3

Đã chạy bản gốc, giữ tại `evidence/original/traceback_exercise.py`; traceback thật tại `evidence/traceback_before.txt`, exit 1.

```text
File "...\evidence\original\traceback_exercise.py", line 10
    if record["failed_count"] >= 4:
TypeError: '>=' not supported between instances of 'str' and 'int'
```

**FLAG 3:** `failed_count` có kiểu `str` (ví dụ `"5"`) nhưng so sánh với `int` (`4`). Python không định nghĩa so sánh thứ tự `str >= int` và không tự ép kiểu ở đây.

Dòng sửa trong bản hiện tại:

```python
failed_count = parse_failed_count(record["failed_count"])
if failed_count >= FAILURE_THRESHOLD:
    print("ALERT", record["src_ip"], failed_count)
```

Hàm kiểm tra số nguyên không âm hoặc chuỗi chữ số ASCII sau khi bỏ khoảng trắng, rồi gọi `int(text)`. Giá trị rỗng, âm, boolean, số thực hoặc không phải số gây `ValueError`, không dùng `except: pass`. Bản sửa in `ALERT 203.0.113.77 5`, exit 0; bằng chứng ở `evidence/traceback_after.txt`.

## 6. Research và FLAG 4

Truy vấn, bài công khai, tác giả/ngày đăng, claim và bảng kiểm chứng ở [PHIEU_RESEARCH.md](PHIEU_RESEARCH.md). Nội dung mạng xã hội không phải bằng chứng của sự cố mô phỏng.

**FLAG 4:** [MITRE ATT&CK T1110.003 - Password Spraying](https://attack.mitre.org/techniques/T1110/003/) là ánh xạ giả thuyết cho `198.51.100.24` vì nguồn này fail trên 3 user trong 35 giây; chưa xác nhận do thiếu thông tin mật khẩu và ngữ cảnh. Với `203.0.113.77`, nghi brute force ở mức [T1110](https://attack.mitre.org/techniques/T1110/), chưa đủ xác định kỹ thuật con hoặc truy cập trái phép.

## 7. Bàn giao và debrief

[Báo cáo ngắn](BAO_CAO_SU_CO.md) ưu tiên xác minh phiên admin, MFA và hoạt động sau success; sau đó kiểm tra cụm nhiều tài khoản và file. Đây là đề xuất; chưa thực hiện thu hồi phiên, reset mật khẩu, chặn IP hay sửa cấu hình trên hệ thống thật.

Bài học: phân biệt tổng fail với số user; kiểm tra thời gian thay vì vị trí dòng CSV; hash không giải thích nguyên nhân thay đổi; traceback cho thấy lỗi kiểu dữ liệu, không phải malware. Thiếu session ID, user-agent, thiết bị, vị trí, audit file và múi giờ nên chưa xác nhận chuỗi tấn công thống nhất.

Nhắc ergonomics: sau mỗi 2 ticket, đứng lên/đổi tư thế, giãn vai và cổ tay 30–60 giây. Đây là nhắc thực hành, không xác nhận nhóm đã thực hiện.

## 8. Kiểm tra hoàn thành

Ba script chạy thành công qua `python run_all.py`; **32 kiểm thử Python đạt**: 21 core và 11 API dashboard. Kiểm tra dataset, ngưỡng biên, spray độc lập, thời gian, dữ liệu sai, hash nhị phân, bảo toàn dữ liệu, CLI, CSV/hash tải lên và chạy từng bản traceback. Thêm **10 tình huống tương tác DOM/API đạt**, gồm nút lọc nhóm, hash mẫu/tệp riêng, chuỗi thao tác bản gốc → bản sửa, tài liệu và dữ liệu lỗi. Cú pháp JavaScript đã được kiểm tra. Chưa kiểm tra trực quan bằng trình duyệt tự động vì không có trình duyệt được kết nối. Kết quả ở `evidence/test_results.txt` và `evidence/ui_flow_results.txt`.
