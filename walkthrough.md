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

### Cách 1: Chạy trực tuyến trên Railway (Production)
Dự án đã được deploy thành công lên đám mây **Railway** với cấu hình chuẩn doanh nghiệp:
1. **Cơ sở dữ liệu đám mây (PostgreSQL)**: Thay vì SQLite lưu file tạm, chúng ta đã chuyển sang sử dụng **PostgreSQL** của Railway để lưu trữ khóa và nhật ký kiểm toán vĩnh viễn, chống mất mát dữ liệu khi server restart.
2. **Quản lý Cổng (Port Binding)**: Tích hợp `Procfile` để hệ thống tự động nhận cổng mạng của Railway, chạy dịch vụ qua web server `gunicorn` bảo mật.
3. **Mã nguồn tinh gọn**: Tối ưu hóa `requirements.txt` loại bỏ các thư viện không tương thích (như `metatrader5` vốn chỉ chạy trên Windows), giúp máy chủ Linux của Railway cài đặt nhanh gọn và mượt mà.

👉 **Link trải nghiệm trực tuyến của bạn**: (Hãy dán link Railway của bạn vào đây)

---

### Cách 2: Chạy dưới Local (Máy cá nhân)
1. Mở trình duyệt và truy cập `http://127.0.0.1:5000`.
2. Bạn sẽ thấy trên thanh menu có thêm nút **Login**. Hãy bấm vào đó, sau đó chọn **Register** để tạo một tài khoản mới (ví dụ: `admin` / `MậtKhẩuCủaBạn123@`).
3. Sau khi đăng nhập thành công, bạn sẽ được đưa tới **Dashboard**.
4. Lúc này, hãy thử vào mục **Sender** để tạo khóa và ký 1 file. Bạn sẽ thấy mọi hoạt động của bạn vừa rồi đều đã được hệ thống "Camera thu nhỏ" (Audit Logs) trong Dashboard ghi lại một cách chuyên nghiệp.

> [!TIP]
> **Điểm cộng cực lớn để thuyết trình:** 
> *"Bọn em đã xây dựng một kiến trúc hybrid linh hoạt. Khi chạy **Local**, ứng dụng sử dụng CSDL gọn nhẹ **SQLite**. Nhưng khi deploy lên **Cloud (Railway)**, hệ thống tự động phát hiện biến môi trường và chuyển sang CSDL chuẩn doanh nghiệp **PostgreSQL**. Toàn bộ cấu hình hệ thống, quản lý cổng thông qua `Procfile` và web server `gunicorn` đều đã được tối ưu hóa để sẵn sàng đưa vào vận hành thực tế (Production-Ready)!"*
