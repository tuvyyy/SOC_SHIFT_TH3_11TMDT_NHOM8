# Báo cáo sự cố mini - SOC-0815

**Nhóm 8 - TH3 - 11TMDT | Ngày 16/10/2026 | Trạng thái: cần xác minh | Dữ liệu mô phỏng**

## Thành viên phụ trách

| Thành viên | Vai trò kiêm nhiệm | Công việc phụ trách |
| --- | --- | --- |
| **Anh Khôi** | Incident Commander + Log Hunter + OSINT Researcher | Phân tích log, tìm IP bất thường, lập timeline, research MITRE và nguồn tham khảo, đánh giá và đề xuất ứng phó; tổng hợp nội dung báo cáo. |
| **Tú Vy** | Python Analyst + Detection Developer | Detector Python, logic cảnh báo, kiểm thử log và giao diện kết quả phát hiện. |
| **Phước Thịnh** | Python Analyst + Technical Reporter | SHA-256, sửa traceback, giao diện kiểm tra tệp/sửa lỗi và tích hợp bằng chứng kỹ thuật vào báo cáo. |

## Báo cáo sự cố

### 1. Phát hiện

| Hạng mục | Bằng chứng chính |
| --- | --- |
| `203.0.113.77` | 5 lần thất bại lúc 08:10:01–08:10:52; admin đăng nhập thành công lúc **08:11:12**, MFA chưa rõ. |
| `198.51.100.24` | 3 lần thất bại trên **mai, binh, chi** lúc 08:14:05–08:14:40. |
| `artifact.txt` | **MISMATCH** — SHA-256 khác baseline của ticket. |
| Công cụ Python | **Đã sửa TypeError** — kiểm tra giá trị và chuyển chuỗi sang int trước khi so sánh. |

### 2. Đánh giá

- **Cao:** phiên admin từ `203.0.113.77`.
- **Vừa:** nghi password spraying từ `198.51.100.24`.
- Tin cậy cao với log/hash; vừa với giả thuyết tấn công. **Chưa xác nhận xâm nhập** hoặc liên hệ giữa phiên VPN và thay đổi file.

### 3. Ứng phó trước mắt

- Giữ log, tệp gốc và bản sao có hash.
- Xác minh chủ tài khoản, phiên admin và MFA.
- Nếu xác nhận phiên trái phép, đề xuất thu hồi phiên/reset thông tin xác thực theo quy trình được duyệt.

### 4. Xác minh tiếp

- Kiểm tra session ID, thiết bị và hoạt động sau **08:11:12**; đối chiếu NAT/VPN dùng chung.
- Xác thực nguồn baseline, lịch sử thay đổi và quyền sửa file. Mismatch chưa cho biết ai sửa hoặc vì sao.

### 5. Nguồn tham khảo

- [Microsoft Learn](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray): điều tra đăng nhập và MFA.
- [MITRE T1110.003](https://attack.mitre.org/techniques/T1110/003/): đối chiếu giả thuyết password spraying.
- [LinkedIn — Daniel von Büren](https://www.linkedin.com/posts/dvonbueren_threat-actors-misuse-oauth-applications-to-activity-7141698485967343616-yutK): bài công khai, đã kiểm chứng trong phiếu research.

<details>
<summary>Xem bằng chứng kỹ thuật và giới hạn</summary>

**SHA-256 của artifact.txt**

```text
Expected: bada325b6efa645b6272c257ee01add7c061dffba9e3c233621ed832d320994c
Actual:   adf82e65e0c245e5a86d868fcf5869c77da573171e36b6f1730059bf4324f138
Kết quả:  MISMATCH
```

**Traceback:** bản gốc lỗi tại dòng 10 do `str >= int`; bản sửa chạy thành công, mã thoát 0.

**Giới hạn:** timestamp chưa có múi giờ. Thiếu mật khẩu, thông tin phiên và audit để xác nhận kỹ thuật hoặc tác nhân. Chưa thực hiện chặn IP hay thay đổi hệ thống; IP mẫu không phải IOC thật.

Bằng chứng đầy đủ và FLAG 1–4 nằm trong [bài làm](BAI_LAM_SOC_SHIFT.md).

</details>
