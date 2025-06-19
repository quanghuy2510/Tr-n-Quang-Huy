# Tran-Quang-Huy
1. Ký số thật ở Client bằng Private Key (Web Crypto hoặc WASM)
Hiện tại bạn mới dùng SHA-256 trên client làm “giả” chữ ký số. Nên:

Dùng thư viện như Forge hoặc WebAssembly + Python để ký bằng private.pem ngay từ trình duyệt (khó hơn, nhưng chuẩn hơn).

Hoặc xây 1 ứng dụng client desktop nhỏ bằng Python để ký số trước khi upload.

2. Lưu file + kết quả xác minh vào CSDL
Hiện tại bạn in kết quả ra terminal. Có thể lưu vào SQLite:

Tên file

Mã hash

Kết quả xác minh

Thời gian

IP người gửi (nếu có)

=> Giúp quản lý lịch sử xác thực file.

3. Mã hóa nội dung file bằng AES trước khi ký
Bảo vệ bí mật file truyền (hiện tại chỉ bảo vệ tính toàn vẹn):

Tạo key AES ngẫu nhiên

Mã hóa file

Ký chữ ký số trên bản mã

Gửi key AES đã được mã hóa bằng public key người nhận (RSA envelope)

4. Tạo giao diện đẹp hơn với Bootstrap
Ví dụ:

Hiển thị tên file, hash SHA-256

Trạng thái gửi file

Kết quả xác minh 

Thanh tiến trình gửi file

5. Triển khai trên mạng LAN hoặc Internet
Dùng socketio.run(app, host="0.0.0.0", port=5000) để cho máy khác truy cập.

Hoặc deploy lên nền tảng như Render, Heroku, Railway.

6. Tạo ứng dụng di động mini
Dùng React Native hoặc Flutter để tạo giao diện chọn file và gửi lên server qua WebSocket hoặc API.
