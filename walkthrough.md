# Hoàn tất Nâng cấp Sản phẩm (Production-Ready)

Hệ thống Chữ ký số của bạn đã được lột xác hoàn toàn từ một "Công cụ Demo chạy script" thành một **Ứng dụng Web hoàn chỉnh (Production-Ready)**.

## Các tính năng mới được cập nhật

### 1. Hệ thống Quản lý Người Dùng (Authentication)
- Tích hợp `Flask-Login` và Mã hóa mật khẩu bảo mật `Werkzeug Security`.
- Người dùng giờ đây phải **Đăng nhập** để có thể tạo khóa và ký tài liệu.
- Việc này giúp cô lập dữ liệu: Tài liệu và Khóa của ai thì chỉ người đó quản lý.

### 2. Lưu trữ Cơ sở dữ liệu (SQLite) thay vì File tĩnh
- Toàn bộ Private Key và Public Key không còn lưu "lộ thiên" dưới dạng file text trong thư mục `keys/` nữa.
- Chúng đã được chuyển vào lưu trong CSDL SQLite (`app.db`).
- Kiến trúc này mô phỏng sát nhất cách hoạt động của một **Certificate Authority (CA)** trong thực tế.

### 3. Hệ thống Giám sát & Kiểm toán (Audit Logs)
- Thêm Bảng điều khiển (Dashboard) cá nhân.
- Mọi thao tác: Tạo khóa, Ký file, Xác minh file, và đặc biệt là **Phát hiện Giả mạo** đều được ghi chú lại chi tiết cùng với thời gian thực.
- Giúp quản trị viên theo dõi được lịch sử an toàn thông tin của hệ thống.

## Hướng dẫn trải nghiệm bản nâng cấp
1. Mở trình duyệt và truy cập `http://127.0.0.1:5000`.
2. Bạn sẽ thấy trên thanh menu có thêm nút **Login**. Hãy bấm vào đó, sau đó chọn **Register** để tạo một tài khoản mới (ví dụ: `admin` / `123456`).
3. Sau khi đăng nhập thành công, bạn sẽ được đưa tới **Dashboard**.
4. Lúc này, hãy thử vào mục **Sender** để tạo khóa và ký 1 file. Bạn sẽ thấy mọi hoạt động của bạn vừa rồi đều đã được hệ thống "Camera thu nhỏ" (Audit Logs) trong Dashboard ghi lại một cách chuyên nghiệp.

> [!TIP]
> Bạn có thể khoe với giảng viên: *"Bọn em đã thiết kế lại kiến trúc lưu trữ. Thay vì lưu file cấu hình tĩnh, hệ thống đóng vai trò như một **KMS (Key Management System)** quản lý khóa tập trung bằng CSDL và có Audit Trail (Lưu dấu vết kiểm toán) đầy đủ cho mọi hành vi thao tác trên hệ thống!"*
