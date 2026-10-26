# Flow demo SOC SHIFT

Mở `python app.py`. Nếu server đang chạy bản cũ: Ctrl+C, chạy lại, rồi Ctrl+F5 trên trình duyệt.

Nếu cả ba cùng trình bày, có thể chia: **Anh Khôi** mở đầu, phân tích log và research/nhận định; **Tú Vy** giới thiệu Detector, ngưỡng cảnh báo, giao diện kết quả và kiểm thử log; **Phước Thịnh** demo SHA-256, traceback và bằng chứng kỹ thuật. Cả nhóm chuẩn bị chung; cũng có thể chọn một người đại diện thực hiện toàn bộ flow bên dưới.

## 1. Tổng quan

Chỉ ba số **15 sự kiện / 10 lần thất bại / 2 IP cần kiểm tra**.

Nói: “Nhóm phân tích log xác thực và phát hiện hai nguồn đăng nhập cần điều tra.”

## 2. Fail rồi thành công

Ở ô **Thất bại rồi đăng nhập được**, bấm **Xem 6 dòng log**.

Chỉ năm dòng thất bại rồi dòng xanh lúc **08:11:12**.

Nói: “IP 203.0.113.77 có năm lần thất bại rồi admin đăng nhập thành công. MFA chưa rõ, nên cần xác minh phiên; chưa đủ kết luận bị chiếm tài khoản.”

## 3. Nhiều tài khoản

Ngay trên bảng, bấm **Nhiều tài khoản**. Chỉ các tên **mai, binh, chi** và ba dòng log.

Nói: “Cùng IP 198.51.100.24 thử ba tài khoản khác nhau. Đây là nghi vấn password spraying, chưa phải kết luận.”

## 4. Kiểm tra tệp

Bấm **Tiếp: Kiểm tra tệp →** ở cuối trang. Giữ **Dữ liệu bài tập**, bấm **So sánh SHA-256**. Không cần chọn file.

Chỉ hai hash và nhãn **MISMATCH**.

Nói: “Hash tính từ tệp khác baseline của ticket. Cần kiểm tra nguồn baseline và lịch sử sửa file; hash không cho biết ai sửa hoặc vì sao.”

## 5. Sửa lỗi Python

Bấm **Tiếp: Sửa lỗi Python →**. Bấm **1. Chạy bản gốc**, chỉ kết quả **TypeError**.

Nói: “Giá trị 5 đang ở dạng chuỗi, nhưng được so sánh với số nguyên 4.”

Bấm **2. Chạy bản sửa**, chỉ **Chạy thành công** và **ALERT 203.0.113.77 5**.

Nói: “Bản sửa kiểm tra dữ liệu rồi chuyển sang int trước khi so sánh.”

## 6. Báo cáo

Bấm **Tiếp: Báo cáo →**. Show báo cáo; chọn **Nguồn tham khảo** để chỉ nguồn LinkedIn, Microsoft và MITRE. Chọn **Bài làm & FLAG** nếu cần show kết quả từng ticket.

Đầu báo cáo có bảng **Thành viên phụ trách** gồm Anh Khôi, Tú Vy, Phước Thịnh cùng vai trò kiêm nhiệm và công việc. Khi giới thiệu: “Khôi phụ trách điều tra và research; Vy lập trình phát hiện; Thịnh lập trình kiểm chứng. Khôi tổng hợp nội dung báo cáo, Vy và Thịnh cung cấp bằng chứng kỹ thuật.”

Kết: “Nhóm đề xuất giữ bằng chứng, xác minh phiên admin và MFA, kiểm tra hoạt động sau đăng nhập cùng lịch sử thay đổi file.”

Không cần tải CSV khác, chọn tệp khác, xuất JSON hoặc chạy kiểm thử trong demo chính. Các chức năng đó dùng khi được yêu cầu xem thêm.
