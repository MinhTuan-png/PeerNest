const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_only";

app.use(cors());
app.use(express.json({ limit: '5mb' }));

const db = new sqlite3.Database('./peernest.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      anon_id TEXT NOT NULL UNIQUE,
      avatar TEXT NOT NULL,
      is_listener INTEGER NOT NULL DEFAULT 0,
      listener_keywords TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS conversations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      requester_id INTEGER NOT NULL,
      responder_id INTEGER NOT NULL,
      topic_keywords TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (requester_id) REFERENCES users(id),
      FOREIGN KEY (responder_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      conversation_id INTEGER NOT NULL,
      sender_id INTEGER NOT NULL,
      type TEXT NOT NULL DEFAULT 'text',
      content TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (conversation_id) REFERENCES conversations(id),
      FOREIGN KEY (sender_id) REFERENCES users(id)
    )
  `);
});

const AVATAR_POOL = ['🦊', '🐢', '🐧', '🦉', '🐝', '🐨', '🐬', '🦔', '🐿️', '🦋', '🐙', '🐼'];

function generateAnonId() {
  const num = Math.floor(1000 + Math.random() * 9000);
  return 'Nest' + num;
}

function pickAvatar(seedText) {
  let sum = 0;
  for (let i = 0; i < seedText.length; i++) sum += seedText.charCodeAt(i);
  return AVATAR_POOL[sum % AVATAR_POOL.length];
}

function parseKeywords(raw) {
  return (raw || '')
    .toLowerCase()
    .split(/[,\n]/)
    .map(function(k) { return k.trim(); })
    .filter(Boolean);
}

function checkAnonAvailable(name, callback) {
  db.get('SELECT id FROM users WHERE anon_id = ?', [name], function(err, row) {
    if (err) return callback(err);
    callback(null, !row);
  });
}

function generateUniqueAnonId(callback) {
  const candidate = generateAnonId();
  checkAnonAvailable(candidate, function(err, available) {
    if (err) return callback(err);
    if (available) return callback(null, candidate);
    generateUniqueAnonId(callback);
  });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ message: 'Bạn cần đăng nhập để thực hiện thao tác này.' });
  }

  jwt.verify(token, JWT_SECRET, function(err, payload) {
    if (err) {
      return res.status(401).json({ message: 'Phiên đăng nhập đã hết hạn, vui lòng đăng nhập lại.' });
    }
    req.userId = payload.id;
    next();
  });
}

app.get('/api/health', (req, res) => {
  res.json({ message: 'PeerNest backend đang chạy.' });
});

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, anonName, isListener, listenerKeywords } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Vui lòng nhập đầy đủ thông tin.' });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: 'Mật khẩu phải có ít nhất 6 ký tự.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    function insertUser(anonId) {
      const avatar = pickAvatar(anonId);
      const listenerFlag = isListener ? 1 : 0;
      const keywords = listenerFlag ? parseKeywords(listenerKeywords).join(',') : '';

      db.run(
        'INSERT INTO users (name, email, password, anon_id, avatar, is_listener, listener_keywords) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [name.trim(), email.trim().toLowerCase(), hashedPassword, anonId, avatar, listenerFlag, keywords],
        function(err) {
          if (err) {
            if (err.message.includes('UNIQUE') && err.message.includes('users.email')) {
              return res.status(409).json({ message: 'Email này đã được đăng ký.' });
            }
            if (err.message.includes('UNIQUE')) {
              return res.status(409).json({ message: 'Tên/ID ẩn danh này đã có người dùng, vui lòng chọn tên khác.' });
            }
            return res.status(500).json({ message: 'Không thể tạo tài khoản.' });
          }

          res.status(201).json({
            message: 'Đăng ký thành công.',
            user: {
              id: this.lastID,
              name: name.trim(),
              email: email.trim().toLowerCase(),
              anonId: anonId,
              avatar: avatar
            }
          });
        }
      );
    }

    if (anonName && anonName.trim()) {
      const wanted = anonName.trim();

      checkAnonAvailable(wanted, function(err, available) {
        if (err) return res.status(500).json({ message: 'Lỗi server.' });
        if (!available) {
          return res.status(409).json({ message: 'Tên ẩn danh này đã có người dùng, vui lòng chọn tên khác.' });
        }
        insertUser(wanted);
      });
    } else {
      generateUniqueAnonId(function(err, anonId) {
        if (err) return res.status(500).json({ message: 'Lỗi server.' });
        insertUser(anonId);
      });
    }
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
          email: user.email,
          anonId: user.anon_id,
          avatar: user.avatar,
          isListener: !!user.is_listener
        }
      });
    }
  );
});

function loadConversationIfMember(conversationId, userId, callback) {
  db.get('SELECT * FROM conversations WHERE id = ?', [conversationId], (err, convo) => {
    if (err) return callback(err);
    if (!convo) return callback(null, null);
    if (convo.requester_id !== userId && convo.responder_id !== userId) {
      return callback(null, false);
    }
    callback(null, convo);
  });
}

app.post('/api/safe-space/match', authMiddleware, (req, res) => {
  const keywords = parseKeywords(req.body.keywords);

  if (keywords.length === 0) {
    return res.status(400).json({ message: 'Vui lòng nhập ít nhất một từ khóa về vấn đề bạn đang gặp.' });
  }

  db.all(
    'SELECT id, anon_id, avatar, listener_keywords FROM users WHERE is_listener = 1 AND id != ?',
    [req.userId],
    (err, listeners) => {
      if (err) return res.status(500).json({ message: 'Lỗi server.' });

      if (!listeners.length) {
        return res.status(404).json({ message: 'Hiện chưa có người đồng hành phù hợp, vui lòng thử lại sau.' });
      }

      let best = null;
      let bestScore = -1;

      listeners.forEach((listener) => {
        const listenerKeywords = parseKeywords(listener.listener_keywords);
        const score = keywords.filter((k) => listenerKeywords.includes(k)).length;

        if (score > bestScore) {
          bestScore = score;
          best = listener;
        }
      });

      if (bestScore <= 0) {
        best = listeners[Math.floor(Math.random() * listeners.length)];
      }

      db.run(
        'INSERT INTO conversations (requester_id, responder_id, topic_keywords, status) VALUES (?, ?, ?, ?)',
        [req.userId, best.id, keywords.join(','), 'active'],
        function(err) {
          if (err) return res.status(500).json({ message: 'Không thể tạo cuộc trò chuyện.' });

          res.status(201).json({
            conversationId: this.lastID,
            partner: { anonId: best.anon_id, avatar: best.avatar },
            matchedByKeyword: bestScore > 0
          });
        }
      );
    }
  );
});

app.get('/api/safe-space/active', authMiddleware, (req, res) => {
  db.get(
    `SELECT c.*,
      ru.anon_id AS requester_anon, ru.avatar AS requester_avatar,
      su.anon_id AS responder_anon, su.avatar AS responder_avatar
     FROM conversations c
     JOIN users ru ON ru.id = c.requester_id
     JOIN users su ON su.id = c.responder_id
     WHERE (c.requester_id = ? OR c.responder_id = ?) AND c.status = 'active'
     ORDER BY c.id DESC LIMIT 1`,
    [req.userId, req.userId],
    (err, convo) => {
      if (err) return res.status(500).json({ message: 'Lỗi server.' });
      if (!convo) return res.json({ conversation: null });

      const isRequester = convo.requester_id === req.userId;

      res.json({
        conversation: {
          id: convo.id,
          topicKeywords: convo.topic_keywords,
          partner: {
            anonId: isRequester ? convo.responder_anon : convo.requester_anon,
            avatar: isRequester ? convo.responder_avatar : convo.requester_avatar
          }
        }
      });
    }
  );
});

app.get('/api/safe-space/conversations/:id/messages', authMiddleware, (req, res) => {
  const conversationId = req.params.id;
  const afterId = parseInt(req.query.after || '0', 10);

  loadConversationIfMember(conversationId, req.userId, (err, convo) => {
    if (err) return res.status(500).json({ message: 'Lỗi server.' });
    if (convo === null) return res.status(404).json({ message: 'Không tìm thấy cuộc trò chuyện.' });
    if (convo === false) return res.status(403).json({ message: 'Bạn không có quyền xem cuộc trò chuyện này.' });

    db.all(
      'SELECT id, sender_id, type, content, created_at FROM messages WHERE conversation_id = ? AND id > ? ORDER BY id ASC',
      [conversationId, afterId],
      (err, rows) => {
        if (err) return res.status(500).json({ message: 'Lỗi server.' });

        const messages = rows.map((m) => ({
          id: m.id,
          type: m.type,
          content: m.content,
          isMine: m.sender_id === req.userId,
          createdAt: m.created_at
        }));

        res.json({ messages });
      }
    );
  });
});

app.post('/api/safe-space/conversations/:id/messages', authMiddleware, (req, res) => {
  const conversationId = req.params.id;
  const { type, content } = req.body;

  if (!content || !['text', 'image', 'icon'].includes(type)) {
    return res.status(400).json({ message: 'Tin nhắn không hợp lệ.' });
  }

  if (type === 'image' && content.length > 4500000) {
    return res.status(413).json({ message: 'Ảnh quá lớn, vui lòng chọn ảnh nhỏ hơn.' });
  }

  loadConversationIfMember(conversationId, req.userId, (err, convo) => {
    if (err) return res.status(500).json({ message: 'Lỗi server.' });
    if (convo === null) return res.status(404).json({ message: 'Không tìm thấy cuộc trò chuyện.' });
    if (convo === false) return res.status(403).json({ message: 'Bạn không có quyền gửi tin nhắn trong cuộc trò chuyện này.' });

    db.run(
      'INSERT INTO messages (conversation_id, sender_id, type, content) VALUES (?, ?, ?, ?)',
      [conversationId, req.userId, type, content],
      function(err) {
        if (err) return res.status(500).json({ message: 'Không thể gửi tin nhắn.' });

        res.status(201).json({
          message: { id: this.lastID, type, content, isMine: true }
        });
      }
    );
  });
});
app.listen(PORT, "0.0.0.0", () => {
  console.log(`PeerNest backend đang chạy tại cổng ${PORT}`);
});
