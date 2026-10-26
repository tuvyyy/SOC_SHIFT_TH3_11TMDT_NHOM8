# Phiếu research - Ticket RESEARCH

**Ngày truy cập: 16/10/2026 | Câu hỏi:** Khi có nhiều login thất bại rồi một login thành công, SOC nên kiểm tra và xử lý thế nào?

## 1. Truy vấn đã dùng

```text
site.linkedin.com/posts password spraying successful login Microsoft security
site.microsoft.com security blog password spray successful sign ins investigation
```

Tìm bằng công cụ tìm kiếm công khai, mở bài LinkedIn và đối chiếu nguồn kỹ thuật. Không đăng nhập, không liên hệ tác giả, không gửi log ra ngoài, không tải/chạy mã đính kèm. Tìm kiếm và đọc nguồn được thực hiện trong giới hạn research 15 phút của bài.

## 2. Bài đăng công khai

- **Nền tảng:** LinkedIn.
- **Tác giả:** Daniel von Büren; đây là người chia sẻ, không phải tác giả nghiên cứu gốc.
- **Bài:** [Threat actors misuse OAuth applications to automate financially driven attacks](https://www.linkedin.com/posts/dvonbueren_threat-actors-misuse-oauth-applications-to-activity-7141698485967343616-yutK).
- **Ngày đăng:** 16/12/2023, lúc 08:00:05.369 UTC (15:00:05.369 giờ Việt Nam). Trang công khai hiển thị tương đối `2y`; mốc tuyệt đối lấy từ trường JSON-LD `datePublished` trong HTML, không suy đoán từ chữ `2y`.
- **Ngữ cảnh:** chia sẻ nghiên cứu Microsoft Threat Intelligence về lạm dụng ứng dụng OAuth sau khi chiếm tài khoản.
- **Claim được diễn giải:** một số chiến dịch dùng phishing hoặc password spraying đối với tài khoản bảo vệ yếu, rồi lạm dụng quyền ứng dụng OAuth.
- **Giới hạn:** bài này không mô tả log VPN mẫu; không dùng nó để gán nhóm tấn công hay kết luận phiên admin đã bị chiếm. Không dùng số lượt tương tác làm thước đo độ đúng.

Metadata nguồn được ghi tại `evidence/research_sources.json`.

## 3. Kiểm chứng bằng nguồn kỹ thuật

| Nguồn đã đọc | Điều kiểm chứng | Kết quả và giới hạn |
| --- | --- | --- |
| [Microsoft Threat Intelligence, 12/12/2023 - nghiên cứu OAuth gốc](https://www.microsoft.com/en-us/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/) | Claim của người chia sẻ | Nghiên cứu xác nhận các chiến dịch dùng spraying/phishing và lạm dụng OAuth; hỗ trợ kiểm tra quyền ứng dụng khi môi trường có OAuth. Là nguồn sơ cấp của bài chia sẻ, không phải chứng thực độc lập chiến dịch. |
| [MITRE ATT&CK T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Bản chất password spraying, nguồn độc lập với người đăng và Microsoft | Một hoặc vài mật khẩu được thử trên nhiều tài khoản. Nhiều user từ cùng IP phù hợp giả thuyết; không đủ xác nhận nếu không có ngữ cảnh. |
| [Microsoft Learn - Password spray investigation](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray) | Quy trình điều tra | Đối chiếu IP/thời gian, đăng nhập thành công và MFA; kiểm tra bất thường thiết bị/tài khoản. Áp dụng nguyên tắc cho VPN, không giả định bài lab đang dùng Entra/AD FS. |

## 4. Đề xuất cho dữ liệu mẫu và độ tin cậy

Đây là suy luận của bài làm từ log và nguồn, chưa phải hành động đã thực hiện:

1. Bảo toàn log gốc/bản sao, ghi hash và phạm vi thời gian; xác minh múi giờ và đồng bộ đồng hồ.
2. Ưu tiên `203.0.113.77`: xác minh ai dùng admin lúc 08:11:12; lấy session ID, kết quả MFA chi tiết, thiết bị/user-agent, tài nguyên được truy cập và hoạt động sau đăng nhập. Success đơn lẻ chưa xác nhận xâm nhập.
3. Với `198.51.100.24`, mở rộng tìm trên các tài khoản/nguồn liên quan; kiểm tra NAT hoặc nguồn dùng chung và dấu hiệu tự động hóa. Không cần thu thập mật khẩu thật để kiểm tra giả thuyết.
4. Nếu xác minh phiên trái phép hoặc rủi ro đủ cao, đề xuất thu hồi phiên/reset thông tin xác thực theo quy trình phê duyệt. Không tự động chặn chỉ dựa vào IP trong bộ mẫu. Nếu hệ thống dùng OAuth, kiểm tra consent/quyền ứng dụng bất thường.

**Độ tin cậy:** cao với số lần fail/success và mismatch quan sát được; vừa với giả thuyết đoán mật khẩu/spraying; chưa đủ bằng chứng để xác nhận chiếm tài khoản, MFA bị vượt qua hoặc liên hệ với file thay đổi. Nguồn kỹ thuật đáng tin cậy về cơ chế và quy trình, nhưng không xác minh sự cố cụ thể trong lab.

## 5. FLAG 4

Ánh xạ **nghi vấn T1110.003** cho `198.51.100.24` vì fail trên `mai`, `binh`, `chi` trong 35 giây. Cần thêm log xác thực và ngữ cảnh để xác nhận mẫu thử mật khẩu ít trên nhiều tài khoản. Không suy ra credential stuffing vì không có bằng chứng dùng danh sách credential bị lộ.
