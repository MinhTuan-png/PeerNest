const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_only";

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('./peernest.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

app.get('/api/health', (req, res) => {
  res.json({ message: 'PeerNest backend đang chạy.' });
});

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Vui lòng nhập đầy đủ thông tin.' });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: 'Mật khẩu phải có ít nhất 6 ký tự.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name.trim(), email.trim().toLowerCase(), hashedPassword],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(409).json({ message: 'Email này đã được đăng ký.' });
          }
          return res.status(500).json({ message: 'Không thể tạo tài khoản.' });
        }

        res.status(201).json({
          message: 'Đăng ký thành công.',
          user: {
            id: this.lastID,
            name: name.trim(),
            email: email.trim().toLowerCase()
          }
        });
      }
    );
  } catch (error) {
    res.status(500).json({ message: 'Lỗi server.' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Vui lòng nhập email và mật khẩu.' });
  }

  db.get(
    'SELECT * FROM users WHERE email = ?',
    [email.trim().toLowerCase()],
    async (err, user) => {
      if (err) return res.status(500).json({ message: 'Lỗi server.' });

      if (!user) {
        return res.status(401).json({ message: 'Email hoặc mật khẩu không đúng.' });
      }

      const valid = await bcrypt.compare(password, user.password);

      if (!valid) {
        return res.status(401).json({ message: 'Email hoặc mật khẩu không đúng.' });
      }

      const token = jwt.sign(
        { id: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        message: 'Đăng nhập thành công.',
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email
        }
      });
    }
  );
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`PeerNest backend đang chạy tại cổng ${PORT}`);
});
