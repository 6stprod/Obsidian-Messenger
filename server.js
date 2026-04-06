const express = require('express');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// 🔑 СЕКРЕТ 
const SECRET = 'e2e_messenger_secret_key_2024';
const DB_FILE = 'messenger.db';
let db;

async function initDB() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_FILE)) {
    db = new SQL.Database(fs.readFileSync(DB_FILE));
  } else {
    db = new SQL.Database();
    db.run(`
      CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, nickname TEXT UNIQUE, password_hash TEXT, public_key TEXT);
      CREATE TABLE contact_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, from_id INTEGER, to_id INTEGER, status TEXT DEFAULT 'pending');
      CREATE TABLE dialogs (id INTEGER PRIMARY KEY AUTOINCREMENT, user1_id INTEGER, user2_id INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
      CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, dialog_id INTEGER, sender_id INTEGER, content_base64 TEXT, iv_base64 TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
      CREATE UNIQUE INDEX idx_dialog_users ON dialogs(user1_id, user2_id);
    `);
    saveDB();
  }
  console.log('✅ DB initialized');
}

function saveDB() {
  if (db) {
    const data = db.export();
    fs.writeFileSync(DB_FILE, Buffer.from(data));
  }
}

function run(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.run(params);
  stmt.free();
  saveDB();
}

function get(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (!stmt.step()) { stmt.free(); return null; }
  const row = stmt.getAsObject();
  stmt.free();
  return row;
}

function all(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results = [];
  while (stmt.step()) results.push(stmt.getAsObject());
  stmt.free();
  return results;
}

// 🔐 Middleware с отладкой
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  // console.log('🔍 Auth header:', authHeader); // Раскомментировать для отладки
  
  if (!authHeader) return res.status(401).json({ error: 'No authorization header' });
  
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ error: 'Invalid auth format' });
  }
  
  const token = parts[1];
  try {
    req.user = jwt.verify(token, SECRET);
    // console.log('✅ Token verified:', req.user);
    next();
  } catch (err) {
    console.error('❌ Token verify error:', err.message);
    res.status(403).json({ error: 'Invalid token' });
  }
};

// === API ===

app.post('/api/auth', async (req, res) => {
  const { nickname, password } = req.body;
  if (!nickname || !password) return res.status(400).json({ error: 'Missing fields' });

  try {
    let user = get('SELECT * FROM users WHERE nickname = ?', [nickname]);

    if (user) {
      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) return res.status(401).json({ error: 'Invalid password' });
    } else {
      const hash = await bcrypt.hash(password, 10);
      run('INSERT INTO users (nickname, password_hash) VALUES (?, ?)', [nickname, hash]);
      user = get('SELECT * FROM users WHERE nickname = ?', [nickname]);
    }

    const token = jwt.sign({ id: user.id, nickname: user.nickname }, SECRET, { expiresIn: '24h' });
    res.json({ token, nickname: user.nickname, id: user.id });
  } catch (e) {
    console.error('Auth error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/key', authMiddleware, (req, res) => {
  const { public_key } = req.body;
  // public_key уже строка, не делаем JSON.stringify ещё раз
  run('UPDATE users SET public_key = ? WHERE id = ?', [public_key, req.user.id]);
  res.json({ message: 'Key saved' });
});

app.get('/api/users/search', authMiddleware, (req, res) => {
  const q = req.query.q || '';
  // ✅ public_key должен быть в SELECT
  const users = all('SELECT id, nickname, public_key FROM users WHERE nickname LIKE ? AND id != ?', [`%${q}%`, req.user.id]);
  res.json(users);
});

app.post('/api/contact/request', authMiddleware, (req, res) => {
  const { to_nickname } = req.body;
  const target = get('SELECT id FROM users WHERE nickname = ?', [to_nickname]);
  if (!target) return res.status(404).json({ error: 'User not found' });
  try {
    run('INSERT INTO contact_requests (from_id, to_id) VALUES (?, ?)', [req.user.id, target.id]);
    res.json({ message: 'Request sent' });
  } catch { res.status(409).json({ error: 'Already requested' }); }
});

app.post('/api/contact/confirm', authMiddleware, (req, res) => {
  const { from_id } = req.body;
  run('UPDATE contact_requests SET status = ? WHERE from_id = ? AND to_id = ?', ['accepted', from_id, req.user.id]);
  const existing = get('SELECT id FROM dialogs WHERE (user1_id=? AND user2_id=?) OR (user1_id=? AND user2_id=?)', [req.user.id, from_id, from_id, req.user.id]);
  if (!existing) run('INSERT INTO dialogs (user1_id, user2_id) VALUES (?, ?)', [from_id, req.user.id]);
  res.json({ message: 'Contact confirmed' });
});

app.get('/api/contacts/pending', authMiddleware, (req, res) => {
  const pending = all('SELECT cr.from_id, u.nickname FROM contact_requests cr JOIN users u ON cr.from_id = u.id WHERE cr.to_id = ? AND cr.status = ?', [req.user.id, 'pending']);
  res.json(pending);
});

app.get('/api/dialogs', authMiddleware, (req, res) => {
  const dialogs = all('SELECT d.id, u.id as other_id, u.nickname FROM dialogs d JOIN users u ON (u.id = d.user1_id OR u.id = d.user2_id) AND u.id != ? WHERE d.user1_id = ? OR d.user2_id = ?', [req.user.id, req.user.id, req.user.id]);
  res.json(dialogs);
});

app.get('/api/messages/:dialogId', authMiddleware, (req, res) => {
  res.json(all('SELECT id, sender_id, content_base64, iv_base64, created_at FROM messages WHERE dialog_id = ? ORDER BY created_at ASC', [req.params.dialogId]));
});

app.post('/api/messages', authMiddleware, (req, res) => {
  const { dialog_id, content_base64, iv_base64 } = req.body;
  const dialog = get('SELECT id FROM dialogs WHERE id = ? AND (user1_id = ? OR user2_id = ?)', [dialog_id, req.user.id, req.user.id]);
  if (!dialog) return res.status(403).json({ error: 'Not in dialog' });
  run('INSERT INTO messages (dialog_id, sender_id, content_base64, iv_base64) VALUES (?, ?, ?, ?)', [dialog_id, req.user.id, content_base64, iv_base64]);
  res.json({ message: 'Sent' });
});

// Удаление диалога и всех сообщений
app.delete('/api/dialogs/:dialogId', authMiddleware, (req, res) => {
  const dialogId = req.params.dialogId;
  
  // Проверяем, что пользователь состоит в диалоге
  const dialog = get('SELECT * FROM dialogs WHERE id = ? AND (user1_id = ? OR user2_id = ?)', 
    [dialogId, req.user.id, req.user.id]);
  
  if (!dialog) {
    return res.status(403).json({ error: 'Dialog not found' });
  }
  
  // ✅ Удаляем ТОЛЬКО сообщения, диалог НЕ трогаем!
  run('DELETE FROM messages WHERE dialog_id = ?', [dialogId]);
  
  res.json({ message: 'Messages deleted' });
});

// Сохранение публичного ключа
app.post('/api/key', authMiddleware, (req, res) => {
  const { public_key } = req.body;
  if (!public_key) return res.status(400).json({ error: 'No public key' });
  
  run('UPDATE users SET public_key = ? WHERE id = ?', [public_key, req.user.id]);
  res.json({ message: 'Key saved' });
});

// 🚫 Удаление из друзей (удаляет диалог, сообщения и запросы)
// ✅ УДАЛЕНИЕ ИЗ ДРУЗЕЙ (ДЛЯ ОБОИХ ПОЛЬЗОВАТЕЛЕЙ)
app.delete('/api/contacts/:friendId', authMiddleware, (req, res) => {
  const friendId = parseInt(req.params.friendId);
  const userId = req.user.id;
  
  if (!friendId || friendId === userId) {
    return res.status(400).json({ error: 'Invalid friend ID' });
  }

  // Находим диалог
  const dialog = get(`
    SELECT id FROM dialogs 
    WHERE (user1_id=? AND user2_id=?) OR (user1_id=? AND user2_id=?)
  `, [userId, friendId, friendId, userId]);
  
  if (dialog) {
    // ✅ Удаляем ВСЕ сообщения
    run('DELETE FROM messages WHERE dialog_id = ?', [dialog.id]);
    // ✅ Удаляем САМ диалог
    run('DELETE FROM dialogs WHERE id = ?', [dialog.id]);
  }

  // ✅ Удаляем запросы на дружбу в ОБЕИХ направлениях
  run('DELETE FROM contact_requests WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)', 
    [userId, friendId, friendId, userId]);

  res.json({ message: 'Friend and dialog deleted for both users' });
});



initDB().then(() => {
  const PORT = 63000;
  app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
});
setInterval(saveDB, 30000);