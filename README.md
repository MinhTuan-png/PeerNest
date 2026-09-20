# PeerNest

## 1. Chạy backend

Mở terminal tại thư mục `PeerNest-backend`:

```bash
npm install
npm start
```

Backend chạy tại:

http://localhost:3000

Kiểm tra:

http://localhost:3000/api/health

## 2. Chạy frontend

Mở file `PeerNest-frontend.html` bằng Live Server trong VS Code.

Frontend gọi:

- POST /api/auth/register
- POST /api/auth/login

Database SQLite `peernest.db` sẽ tự được tạo trong thư mục backend.

## 3. Dữ liệu được lưu

Bảng `users` lưu:

- id
- name
- email
- password đã hash bằng bcrypt
- created_at

Không lưu mật khẩu dạng plaintext.
