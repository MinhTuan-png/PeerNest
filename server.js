const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_only";

app.use(cors());
app.use(express.json({ limit: '5mb' }));

// Kết nối PostgreSQL qua biến môi trường DATABASE_URL (lấy từ Render Postgres)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : false
});

async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        anon_id TEXT NOT NULL UNIQUE,
        avatar TEXT NOT NULL,
        is_listener BOOLEAN NOT NULL DEFAULT FALSE,
        listener_keywords TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS conversations (
        id SERIAL PRIMARY KEY,
        requester_id INTEGER NOT NULL REFERENCES users(id),
        responder_id INTEGER NOT NULL REFERENCES users(id),
        topic_keywords TEXT,
        status TEXT NOT NULL DEFAULT 'active',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        conversation_id INTEGER NOT NULL REFERENCES conversations(id),
        sender_id INTEGER NOT NULL REFERENCES users(id),
        type TEXT NOT NULL DEFAULT 'text',
        content TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    console.log('Đã kết nối và khởi tạo bảng PostgreSQL thành công.');
  } catch (error) {
    console.error('Lỗi khởi tạo database PostgreSQL:', error);
  }
}

initDb();

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

async function isAnonAvailable(name) {
  const result = await pool.query('SELECT id FROM users WHERE anon_id = $1', [name]);
  return result.rows.length === 0;
}

async function generateUniqueAnonId() {
  const candidate = generateAnonId();
  const available = await isAnonAvailable(candidate);
  if (available) return candidate;
  return generateUniqueAnonId();
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ message: 'Bạn cần đăng nhập để thực hiện thao tác này.' });
  }

  jwt.verify(token, JWT_SECRET, function(err, payload) {
    if (err) {
      console.error('Lỗi xác thực JWT:', err);
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

    let anonId;
    if (anonName && anonName.trim()) {
      const wanted = anonName.trim();
      const available = await isAnonAvailable(wanted);
      if (!available) {
        return res.status(409).json({ message: 'Tên ẩn danh này đã có người dùng, vui lòng chọn tên khác.' });
      }
      anonId = wanted;
    } else {
      anonId = await generateUniqueAnonId();
    }

    const avatar = pickAvatar(anonId);
    const listenerFlag = !!isListener;
    const keywords = listenerFlag ? parseKeywords(listenerKeywords).join(',') : '';

    const result = await pool.query(
      `INSERT INTO users (name, email, password, anon_id, avatar, is_listener, listener_keywords)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [name.trim(), email.trim().toLowerCase(), hashedPassword, anonId, avatar, listenerFlag, keywords]
    );

    res.status(201).json({
      message: 'Đăng ký thành công.',
      user: {
        id: result.rows[0].id,
        name: name.trim(),
        email: email.trim().toLowerCase(),
        anonId: anonId,
        avatar: avatar
      }
    });
  } catch (error) {
    console.error('Lỗi trong register:', error);

    if (error.code === '23505') { // unique_violation của Postgres
      if (error.constraint && error.constraint.includes('email')) {
        return res.status(409).json({ message: 'Email này đã được đăng ký.' });
      }
      return res.status(409).json({ message: 'Tên/ID ẩn danh này đã có người dùng, vui lòng chọn tên khác.' });
    }

    res.status(500).json({ message: 'Lỗi server.', detail: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Vui lòng nhập email và mật khẩu.' });
  }

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email.trim().toLowerCase()]
    );

    const user = result.rows[0];

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
  } catch (error) {
    console.error('Lỗi trong login:', error);
    res.status(500).json({ message: 'Lỗi server.', detail: error.message });
  }
});

async function loadConversationIfMember(conversationId, userId) {
  const result = await pool.query('SELECT * FROM conversations WHERE id = $1', [conversationId]);
  const convo = result.rows[0];

  if (!convo) return null;
  if (convo.requester_id !== userId && convo.responder_id !== userId) return false;
  return convo;
}

app.post('/api/safe-space/match', authMiddleware, async (req, res) => {
  const keywords = parseKeywords(req.body.keywords);

  if (keywords.length === 0) {
    return res.status(400).json({ message: 'Vui lòng nhập ít nhất một từ khóa về vấn đề bạn đang gặp.' });
  }

  try {
    const result = await pool.query(
      'SELECT id, anon_id, avatar, listener_keywords FROM users WHERE is_listener = TRUE AND id != $1',
      [req.userId]
    );

    const listeners = result.rows;

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

    const insertResult = await pool.query(
      `INSERT INTO conversations (requester_id, responder_id, topic_keywords, status)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [req.userId, best.id, keywords.join(','), 'active']
    );

    res.status(201).json({
      conversationId: insertResult.rows[0].id,
      partner: { anonId: best.anon_id, avatar: best.avatar },
      matchedByKeyword: bestScore > 0
    });
  } catch (error) {
    console.error('Lỗi trong match:', error);
    res.status(500).json({ message: 'Lỗi server.', detail: error.message });
  }
});

app.get('/api/safe-space/active', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.*,
        ru.anon_id AS requester_anon, ru.avatar AS requester_avatar,
        su.anon_id AS responder_anon, su.avatar AS responder_avatar
       FROM conversations c
       JOIN users ru ON ru.id = c.requester_id
       JOIN users su ON su.id = c.responder_id
       WHERE (c.requester_id = $1 OR c.responder_id = $1) AND c.status = 'active'
       ORDER BY c.id DESC LIMIT 1`,
      [req.userId]
    );

    const convo = result.rows[0];

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
  } catch (error) {
    console.error('Lỗi trong active conversation:', error);
    res.status(500).json({ message: 'Lỗi server.', detail: error.message });
  }
});

app.get('/api/safe-space/conversations/:id/messages', authMiddleware, async (req, res) => {
  const conversationId = req.params.id;
  const afterId = parseInt(req.query.after || '0', 10);

  try {
    const convo = await loadConversationIfMember(conversationId, req.userId);

    if (convo === null) return res.status(404).json({ message: 'Không tìm thấy cuộc trò chuyện.' });
    if (convo === false) return res.status(403).json({ message: 'Bạn không có quyền xem cuộc trò chuyện này.' });

    const result = await pool.query(
      'SELECT id, sender_id, type, content, created_at FROM messages WHERE conversation_id = $1 AND id > $2 ORDER BY id ASC',
      [conversationId, afterId]
    );

    const messages = result.rows.map((m) => ({
      id: m.id,
      type: m.type,
      content: m.content,
      isMine: m.sender_id === req.userId,
      createdAt: m.created_at
    }));

    res.json({ messages });
  } catch (error) {
    console.error('Lỗi trong get messages:', error);
    res.status(500).json({ message: 'Lỗi server.', detail: error.message });
  }
});

app.post('/api/safe-space/conversations/:id/messages', authMiddleware, async (req, res) => {
  const conversationId = req.params.id;
  const { type, content } = req.body;

  if (!content || !['text', 'image', 'icon'].includes(type)) {
    return res.status(400).json({ message: 'Tin nhắn không hợp lệ.' });
  }

  if (type === 'image' && content.length > 4500000) {
    return res.status(413).json({ message: 'Ảnh quá lớn, vui lòng chọn ảnh nhỏ hơn.' });
  }

  try {
    const convo = await loadConversationIfMember(conversationId, req.userId);

    if (convo === null) return res.status(404).json({ message: 'Không tìm thấy cuộc trò chuyện.' });
    if (convo === false) return res.status(403).json({ message: 'Bạn không có quyền gửi tin nhắn trong cuộc trò chuyện này.' });

    const result = await pool.query(
      'INSERT INTO messages (conversation_id, sender_id, type, content) VALUES ($1, $2, $3, $4) RETURNING id',
      [conversationId, req.userId, type, content]
    );

    res.status(201).json({
      message: { id: result.rows[0].id, type, content, isMine: true }
    });
  } catch (error) {
    console.error('Lỗi trong post message:', error);
    res.status(500).json({ message: 'Không thể gửi tin nhắn.', detail: error.message });
  }
});

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Promise Rejection:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`PeerNest backend đang chạy tại cổng ${PORT}`);
});
