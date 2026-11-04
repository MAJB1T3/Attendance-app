const express = require('express');
const { DatabaseSync } = require('node:sqlite'); // built into Node 22.5+, nothing to compile
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const PDFDocument = require('pdfkit');
const ExcelJS = require('exceljs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-before-deploying';
const LECTURER_CODE = process.env.LECTURER_CODE || 'LECT-2026'; // needed to create a lecturer account
const APP_TZ = process.env.APP_TZ || 'Africa/Lagos';
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'attendance.db');

// ---------------------------------------------------------------- database
const db = new DatabaseSync(DB_FILE);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');

db.exec(`
CREATE TABLE IF NOT EXISTS students (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  matric_no TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS lecturers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS courses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL,
  title TEXT NOT NULL,
  lecturer_id INTEGER NOT NULL REFERENCES lecturers(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (lecturer_id, code)
);
CREATE TABLE IF NOT EXISTS attendance_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  course_id INTEGER NOT NULL REFERENCES courses(id),
  lecturer_id INTEGER NOT NULL REFERENCES lecturers(id),
  session_date TEXT NOT NULL,
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  ended_early INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS attendance_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL REFERENCES attendance_sessions(id),
  student_id INTEGER NOT NULL REFERENCES students(id),
  session_date TEXT NOT NULL,
  time_marked TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'present',
  device_id TEXT NOT NULL,
  device_info TEXT,
  ip_address TEXT,
  UNIQUE (session_id, student_id),   -- one mark per student per session
  UNIQUE (session_id, device_id)     -- one device cannot mark for two students
);
`);

// ---------------------------------------------------------------- helpers
const app = express();
app.set('trust proxy', true);
app.use(express.json({ limit: '50kb' }));

// CORS so the packaged Android app (served from its own origin) can call the API
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const wrap = (fn) => (req, res) => {
  try { fn(req, res); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
};

const clean = (v) => String(v ?? '').trim();
const normMatric = (v) => clean(v).toUpperCase().replace(/\s+/g, '');

function sign(role, id) {
  return jwt.sign({ role, id }, JWT_SECRET, { expiresIn: '12h' });
}

// Accepts "Authorization: Bearer <token>" or ?token= (used by PDF/Excel download links)
function auth(role) {
  return (req, res, next) => {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : req.query.token;
    try {
      const p = jwt.verify(token, JWT_SECRET);
      if (p.role !== role) return res.status(403).json({ error: 'Not allowed' });
      req.user = p;
      next();
    } catch {
      res.status(401).json({ error: 'Please log in again' });
    }
  };
}

function sessionStatus(s, now = Date.now()) {
  if (s.ended_early) return 'closed';
  if (now < Date.parse(s.start_time)) return 'pending';
  if (now >= Date.parse(s.end_time)) return 'closed';
  return 'open';
}

const fmt = (iso) =>
  new Date(iso).toLocaleString('en-GB', { timeZone: APP_TZ, dateStyle: 'medium', timeStyle: 'short' });
const fmtTime = (iso) =>
  new Date(iso).toLocaleTimeString('en-GB', { timeZone: APP_TZ, hour: '2-digit', minute: '2-digit', second: '2-digit' });

function clientIp(req) {
  return String(req.ip || req.socket.remoteAddress || '').replace('::ffff:', '');
}

// ---------------------------------------------------------------- auth routes
app.post('/api/student/register', wrap((req, res) => {
  const matric = normMatric(req.body.matric);
  const name = clean(req.body.name);
  const password = String(req.body.password || '');
  if (!matric || !name) return res.status(400).json({ error: 'Name and matric number are required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (db.prepare('SELECT 1 FROM students WHERE matric_no = ?').get(matric))
    return res.status(409).json({ error: 'That matric number is already registered' });
  const info = db.prepare('INSERT INTO students (matric_no, name, password_hash) VALUES (?,?,?)')
    .run(matric, name, bcrypt.hashSync(password, 10));
  res.json({ token: sign('student', info.lastInsertRowid), user: { id: info.lastInsertRowid, name, matric_no: matric } });
}));

app.post('/api/student/login', wrap((req, res) => {
  const matric = normMatric(req.body.matric);
  const s = db.prepare('SELECT * FROM students WHERE matric_no = ?').get(matric);
  if (!s || !bcrypt.compareSync(String(req.body.password || ''), s.password_hash))
    return res.status(401).json({ error: 'Wrong matric number or password' });
  res.json({ token: sign('student', s.id), user: { id: s.id, name: s.name, matric_no: s.matric_no } });
}));

app.post('/api/lecturer/register', wrap((req, res) => {
  const name = clean(req.body.name);
  const email = clean(req.body.email).toLowerCase();
  const password = String(req.body.password || '');
  if (clean(req.body.invite_code) !== LECTURER_CODE)
    return res.status(403).json({ error: 'Invalid lecturer invite code' });
  if (!name || !email.includes('@')) return res.status(400).json({ error: 'Name and a valid email are required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (db.prepare('SELECT 1 FROM lecturers WHERE email = ?').get(email))
    return res.status(409).json({ error: 'That email is already registered' });
  const info = db.prepare('INSERT INTO lecturers (name, email, password_hash) VALUES (?,?,?)')
    .run(name, email, bcrypt.hashSync(password, 10));
  res.json({ token: sign('lecturer', info.lastInsertRowid), user: { id: info.lastInsertRowid, name, email } });
}));

app.post('/api/lecturer/login', wrap((req, res) => {
  const email = clean(req.body.email).toLowerCase();
  const l = db.prepare('SELECT * FROM lecturers WHERE email = ?').get(email);
  if (!l || !bcrypt.compareSync(String(req.body.password || ''), l.password_hash))
    return res.status(401).json({ error: 'Wrong email or password' });
  res.json({ token: sign('lecturer', l.id), user: { id: l.id, name: l.name, email: l.email } });
}));

// ---------------------------------------------------------------- lecturer routes
app.get('/api/courses', auth('lecturer'), wrap((req, res) => {
  res.json(db.prepare('SELECT id, code, title FROM courses WHERE lecturer_id = ? ORDER BY code').all(req.user.id));
}));

app.post('/api/courses', auth('lecturer'), wrap((req, res) => {
  const code = clean(req.body.code).toUpperCase();
  const title = clean(req.body.title);
  if (!code || !title) return res.status(400).json({ error: 'Course code and title are required' });
  try {
    const info = db.prepare('INSERT INTO courses (code, title, lecturer_id) VALUES (?,?,?)').run(code, title, req.user.id);
    res.json({ id: info.lastInsertRowid, code, title });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'You already have a course with that code' });
    throw e;
  }
}));

app.post('/api/sessions', auth('lecturer'), wrap((req, res) => {
  const course = db.prepare('SELECT * FROM courses WHERE id = ? AND lecturer_id = ?').get(req.body.course_id, req.user.id);
  if (!course) return res.status(404).json({ error: 'Course not found' });
  const minutes = Math.round(Number(req.body.duration_minutes));
  if (!(minutes >= 1 && minutes <= 720)) return res.status(400).json({ error: 'Duration must be between 1 and 720 minutes' });
  const now = Date.now();
  const open = db.prepare('SELECT * FROM attendance_sessions WHERE course_id = ? AND ended_early = 0').all(course.id)
    .find((s) => sessionStatus(s, now) === 'open');
  if (open) return res.status(409).json({ error: 'This course already has an open session. End it first.' });
  const start = new Date(now).toISOString();
  const end = new Date(now + minutes * 60000).toISOString();
  const info = db.prepare(
    'INSERT INTO attendance_sessions (course_id, lecturer_id, session_date, start_time, end_time) VALUES (?,?,?,?,?)'
  ).run(course.id, req.user.id, start.slice(0, 10), start, end);
  res.json({ id: info.lastInsertRowid, start_time: start, end_time: end });
}));

app.get('/api/sessions', auth('lecturer'), wrap((req, res) => {
  const rows = db.prepare(`
    SELECT s.*, c.code AS course_code, c.title AS course_title,
           (SELECT COUNT(*) FROM attendance_records r WHERE r.session_id = s.id) AS present_count
    FROM attendance_sessions s JOIN courses c ON c.id = s.course_id
    WHERE s.lecturer_id = ? ORDER BY s.id DESC LIMIT 100`).all(req.user.id);
  const now = Date.now();
  res.json({ server_time: new Date(now).toISOString(), sessions: rows.map((s) => ({ ...s, status: sessionStatus(s, now) })) });
}));

function ownedSession(req, res) {
  const s = db.prepare(`
    SELECT s.*, c.code AS course_code, c.title AS course_title, l.name AS lecturer_name
    FROM attendance_sessions s JOIN courses c ON c.id = s.course_id JOIN lecturers l ON l.id = s.lecturer_id
    WHERE s.id = ? AND s.lecturer_id = ?`).get(req.params.id, req.user.id);
  if (!s) res.status(404).json({ error: 'Session not found' });
  return s;
}

function recordsFor(sessionId) {
  return db.prepare(`
    SELECT st.name, st.matric_no, r.time_marked, r.status, r.device_info, r.ip_address
    FROM attendance_records r JOIN students st ON st.id = r.student_id
    WHERE r.session_id = ? ORDER BY r.time_marked`).all(sessionId);
}

app.get('/api/sessions/:id', auth('lecturer'), wrap((req, res) => {
  const s = ownedSession(req, res); if (!s) return;
  const now = Date.now();
  res.json({ server_time: new Date(now).toISOString(), session: { ...s, status: sessionStatus(s, now) }, records: recordsFor(s.id) });
}));

app.post('/api/sessions/:id/end', auth('lecturer'), wrap((req, res) => {
  const s = ownedSession(req, res); if (!s) return;
  db.prepare('UPDATE attendance_sessions SET ended_early = 1 WHERE id = ?').run(s.id);
  res.json({ ok: true });
}));

app.get('/api/sessions/:id/export.pdf', auth('lecturer'), wrap((req, res) => {
  const s = ownedSession(req, res); if (!s) return;
  const rows = recordsFor(s.id);
  const doc = new PDFDocument({ size: 'A4', margin: 40 });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="attendance-${s.course_code}-${s.session_date}.pdf"`);
  doc.pipe(res);

  doc.fontSize(18).text('Attendance List', { align: 'center' });
  doc.moveDown(0.5).fontSize(11)
    .text(`Course: ${s.course_code} - ${s.course_title}`)
    .text(`Lecturer: ${s.lecturer_name}`)
    .text(`Session: ${fmt(s.start_time)} to ${fmtTime(s.end_time)}`)
    .text(`Total present: ${rows.length}`);
  doc.moveDown();

  const cols = [
    { label: 'S/N', x: 40, w: 30 },
    { label: 'Name', x: 70, w: 190 },
    { label: 'Matric No', x: 260, w: 110 },
    { label: 'Time Marked', x: 370, w: 90 },
    { label: 'Status', x: 460, w: 90 },
  ];
  const header = () => {
    const y = doc.y;
    doc.font('Helvetica-Bold').fontSize(10);
    cols.forEach((c) => doc.text(c.label, c.x, y, { width: c.w }));
    doc.moveTo(40, y + 14).lineTo(555, y + 14).stroke();
    doc.y = y + 20;
    doc.font('Helvetica');
  };
  header();
  rows.forEach((r, i) => {
    if (doc.y > 770) { doc.addPage(); header(); }
    const y = doc.y;
    const cells = [String(i + 1), r.name, r.matric_no, fmtTime(r.time_marked), r.status];
    cols.forEach((c, k) => doc.fontSize(10).text(cells[k], c.x, y, { width: c.w, lineBreak: false, ellipsis: true }));
    doc.y = y + 16;
  });
  if (!rows.length) doc.text('No students marked attendance for this session.', 40);
  doc.end();
}));

app.get('/api/sessions/:id/export.xlsx', auth('lecturer'), wrap(async (req, res) => {
  const s = ownedSession(req, res); if (!s) return;
  const rows = recordsFor(s.id);
  const wb = new ExcelJS.Workbook();
  const ws = wb.addWorksheet('Attendance');
  ws.addRow([`${s.course_code} - ${s.course_title}`]).font = { bold: true, size: 14 };
  ws.addRow([`Session: ${fmt(s.start_time)} to ${fmtTime(s.end_time)}`]);
  ws.addRow([]);
  ws.addRow(['S/N', 'Name', 'Matric No', 'Time Marked', 'Course', 'Status']).font = { bold: true };
  rows.forEach((r, i) => ws.addRow([i + 1, r.name, r.matric_no, fmt(r.time_marked), s.course_code, r.status]));
  [6, 30, 18, 24, 12, 10].forEach((w, i) => (ws.getColumn(i + 1).width = w));
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', `attachment; filename="attendance-${s.course_code}-${s.session_date}.xlsx"`);
  await wb.xlsx.write(res);
  res.end();
}));

// ---------------------------------------------------------------- student routes
app.get('/api/student/sessions/active', auth('student'), wrap((req, res) => {
  const now = Date.now();
  const rows = db.prepare(`
    SELECT s.id, s.start_time, s.end_time, s.ended_early, c.code AS course_code, c.title AS course_title,
           l.name AS lecturer_name,
           EXISTS (SELECT 1 FROM attendance_records r WHERE r.session_id = s.id AND r.student_id = ?) AS marked
    FROM attendance_sessions s JOIN courses c ON c.id = s.course_id JOIN lecturers l ON l.id = s.lecturer_id
    WHERE s.ended_early = 0 AND s.end_time > ? ORDER BY s.end_time`).all(req.user.id, new Date(now).toISOString());
  res.json({
    server_time: new Date(now).toISOString(),
    sessions: rows.filter((s) => sessionStatus(s, now) === 'open').map((s) => ({ ...s, marked: !!s.marked })),
  });
}));

app.post('/api/student/mark', auth('student'), wrap((req, res) => {
  const sessionId = Number(req.body.session_id);
  const deviceId = clean(req.body.device_id);
  if (deviceId.length < 8) return res.status(400).json({ error: 'Device could not be identified' });
  const s = db.prepare('SELECT * FROM attendance_sessions WHERE id = ?').get(sessionId);
  if (!s) return res.status(404).json({ error: 'Session not found' });
  const now = Date.now();
  const status = sessionStatus(s, now);
  if (status !== 'open') return res.status(403).json({ error: 'This attendance session is closed' });

  const info = clean(req.body.device_info).slice(0, 300) || String(req.headers['user-agent'] || '').slice(0, 300);
  try {
    db.prepare(`INSERT INTO attendance_records
      (session_id, student_id, session_date, time_marked, status, device_id, device_info, ip_address)
      VALUES (?,?,?,?, 'present', ?,?,?)`)
      .run(s.id, req.user.id, s.session_date, new Date(now).toISOString(), deviceId, info, clientIp(req));
    res.json({ ok: true, time_marked: new Date(now).toISOString() });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) {
      if (String(e.message).includes('device_id'))
        return res.status(409).json({ error: 'This device has already been used to mark attendance for this session' });
      return res.status(409).json({ error: 'You have already marked attendance for this session' });
    }
    throw e;
  }
}));

app.get('/api/student/history', auth('student'), wrap((req, res) => {
  res.json(db.prepare(`
    SELECT r.time_marked, r.status, c.code AS course_code, c.title AS course_title
    FROM attendance_records r
    JOIN attendance_sessions s ON s.id = r.session_id
    JOIN courses c ON c.id = s.course_id
    WHERE r.student_id = ? ORDER BY r.time_marked DESC LIMIT 200`).all(req.user.id));
}));

// ---------------------------------------------------------------- static front end
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

app.listen(PORT, () => console.log(`Attendance server running on http://localhost:${PORT}`));
