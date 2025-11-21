// app.js placeholder
// app.js
const express = require('express');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const db = require('./db'); // our db.js
const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
// Default route → redirect to login
app.get("/", (req, res) => {
  res.redirect("/login.html");
});


// session (for simplicity, not production-hardened)
app.use(session({
  secret: 'change_this_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 } // 1 hour
}));

// uploads folder
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

// multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + '-' + file.originalname.replace(/\s+/g, '_'));
  }
});
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024 } }); // 20MB limit

// --- AUTH HELPERS & MIDDLEWARE ---
function requireLogin(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Unauthorized' });
}
function requireRole(role) {
  return (req, res, next) => {
    if (req.session && req.session.user && req.session.user.role === role) return next();
    return res.status(403).json({ error: 'Forbidden' });
  };
}

// --- AUTH ROUTES ---
// Register (both teacher & student)
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password || !role) return res.status(400).json({ error: 'Missing fields' });
    if (!['teacher', 'student'].includes(role)) return res.status(400).json({ error: 'Invalid role' });

    const [exists] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
    if (exists.length) return res.status(400).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 10);
    await db.query('INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)', [name, email, hash, role]);
    res.json({ ok: true, message: 'User registered' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = rows[0];
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });

    // store minimal session info
    req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
    res.json({ ok: true, user: req.session.user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// Whoami
app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

// --- DEPARTMENTS & TOPICS (manageable by teacher via API or done via DB) ---
// create department (teacher or admin). We'll allow teachers to add dept/topic for flexibility.
app.post('/api/departments', requireLogin, requireRole('teacher'), async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Missing name' });
    await db.query('INSERT IGNORE INTO departments (name) VALUES (?)', [name]);
    const [rows] = await db.query('SELECT * FROM departments');
    res.json({ ok: true, departments: rows });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/departments', async (req, res) => {
  const [rows] = await db.query('SELECT * FROM departments ORDER BY name');
  res.json(rows);
});

// create topic
app.post('/api/topics', requireLogin, requireRole('teacher'), async (req, res) => {
  try {
    const { name, department_id } = req.body;
    if (!name) return res.status(400).json({ error: 'Missing name' });
    await db.query('INSERT INTO topics (name, department_id) VALUES (?, ?)', [name, department_id || null]);
    const [rows] = await db.query('SELECT * FROM topics');
    res.json({ ok: true, topics: rows });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/topics', async (req, res) => {
  const [rows] = await db.query('SELECT t.*, d.name as department_name FROM topics t LEFT JOIN departments d ON t.department_id = d.id ORDER BY t.name');
  res.json(rows);
});

// --- MATERIALS CRUD ---
// Create / Upload material (teacher only)
app.post('/api/materials', requireLogin, requireRole('teacher'), upload.single('file'), async (req, res) => {
  try {
    const teacherId = req.session.user.id;
    const { title, description, subject, class: className, topic_id, department_id } = req.body;
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'No file uploaded' });
    const sql = `INSERT INTO materials 
      (title, description, subject, class, orig_filename, stored_filename, file_size, mime_type, teacher_id, topic_id, department_id)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)`;
    await db.query(sql, [
      title || '',
      description || '',
      subject || '',
      className || '',
      file.originalname,
      file.filename,
      file.size,
      file.mimetype,
      teacherId,
      topic_id || null,
      department_id || null
    ]);
    res.json({ ok: true, message: 'Uploaded' });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// Edit material (teacher only, and only owner)
app.put('/api/materials/:id', requireLogin, requireRole('teacher'), async (req, res) => {
  try {
    const tid = req.session.user.id;
    const id = Number(req.params.id);
    const { title, description, subject, class: className, topic_id, department_id } = req.body;
    // check owner
    const [rows] = await db.query('SELECT teacher_id FROM materials WHERE id = ?', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    if (rows[0].teacher_id !== tid) return res.status(403).json({ error: 'Forbidden' });

    await db.query(`UPDATE materials SET title=?, description=?, subject=?, class=?, topic_id=?, department_id=? WHERE id=?`, [
      title, description, subject, className, topic_id || null, department_id || null, id
    ]);
    res.json({ ok: true, message: 'Updated' });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// Delete material (teacher only, owner)
app.delete('/api/materials/:id', requireLogin, requireRole('teacher'), async (req, res) => {
  try {
    const tid = req.session.user.id;
    const id = Number(req.params.id);
    const [rows] = await db.query('SELECT stored_filename, teacher_id FROM materials WHERE id = ?', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    if (rows[0].teacher_id !== tid) return res.status(403).json({ error: 'Forbidden' });

    // delete file
    const filePath = path.join(UPLOAD_DIR, rows[0].stored_filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    await db.query('DELETE FROM materials WHERE id = ?', [id]);
    res.json({ ok: true, message: 'Deleted' });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// Download material (any logged in user: student or teacher). Public download if you want to allow unauthenticated downloads, remove requireLogin.
app.get('/api/materials/download/:id', requireLogin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const [rows] = await db.query('SELECT orig_filename, stored_filename FROM materials WHERE id = ?', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const filePath = path.join(UPLOAD_DIR, rows[0].stored_filename);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File missing' });
    return res.download(filePath, rows[0].orig_filename);
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// Get materials list (with search + filters) — open to logged-in users
app.get('/api/materials', requireLogin, async (req, res) => {
  try {
    // filters from query string
    const { q, subject, topic_id, department_id, teacher_id, limit = 100 } = req.query;
    // build query dynamically (simple and safe)
    let sql = `SELECT m.*, u.name as teacher_name, t.name as topic_name, d.name as department_name
               FROM materials m
               LEFT JOIN users u ON m.teacher_id = u.id
               LEFT JOIN topics t ON m.topic_id = t.id
               LEFT JOIN departments d ON m.department_id = d.id
               WHERE 1=1`;
    const params = [];
    if (q) {
      sql += ` AND (m.title LIKE ? OR m.description LIKE ? OR m.subject LIKE ?)`;
      const like = `%${q}%`;
      params.push(like, like, like);
    }
    if (subject) { sql += ` AND m.subject = ?`; params.push(subject); }
    if (topic_id) { sql += ` AND m.topic_id = ?`; params.push(topic_id); }
    if (department_id) { sql += ` AND m.department_id = ?`; params.push(department_id); }
    if (teacher_id) { sql += ` AND m.teacher_id = ?`; params.push(teacher_id); }

    sql += ` ORDER BY m.uploaded_at DESC LIMIT ?`;
    params.push(Number(limit));
    const [rows] = await db.query(sql, params);
    res.json(rows);
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// single material info
app.get('/api/materials/:id', requireLogin, async (req, res) => {
  const id = Number(req.params.id);
  const [rows] = await db.query('SELECT m.*, u.name as teacher_name, t.name as topic_name, d.name as department_name FROM materials m LEFT JOIN users u ON m.teacher_id=u.id LEFT JOIN topics t ON m.topic_id=t.id LEFT JOIN departments d ON m.department_id=d.id WHERE m.id = ?', [id]);
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  res.json(rows[0]);
});

// --- Simple helper endpoints to get teachers for filter dropdown ---
app.get('/api/teachers', requireLogin, async (req, res) => {
  const [rows] = await db.query("SELECT id, name FROM users WHERE role='teacher' ORDER BY name");
  res.json(rows);
});

// --- Start server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
