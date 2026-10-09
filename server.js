const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const UPLOAD_DIR = path.join(ROOT, 'uploads');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

if (!process.env.SESSION_SECRET && process.env.NODE_ENV === 'production') {
  throw new Error('SESSION_SECRET must be set in production. Copy .env.example to .env.');
}
const sessionSecret = process.env.SESSION_SECRET || 'development-only-secret-change-me';

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(session({
  name: 'daneshjuyan.sid',
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
const db = new Database(path.join(DATA_DIR, 'daneshjuyan.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'student' CHECK(role IN ('student','admin')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS universities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name_fa TEXT NOT NULL, name_ps TEXT NOT NULL, name_en TEXT NOT NULL,
  city TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS programs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  university_id INTEGER NOT NULL REFERENCES universities(id) ON DELETE CASCADE,
  name_fa TEXT NOT NULL, name_ps TEXT NOT NULL, name_en TEXT NOT NULL,
  faculty_fa TEXT DEFAULT '', faculty_ps TEXT DEFAULT '', faculty_en TEXT DEFAULT '',
  semesters INTEGER NOT NULL DEFAULT 8
);
CREATE TABLE IF NOT EXISTS courses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  program_id INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
  semester INTEGER NOT NULL,
  title_fa TEXT NOT NULL, title_ps TEXT NOT NULL, title_en TEXT NOT NULL,
  description TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS resources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  kind TEXT NOT NULL DEFAULT 'notes',
  original_name TEXT NOT NULL,
  stored_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS profiles (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  university TEXT DEFAULT '',
  program TEXT DEFAULT '',
  semester INTEGER DEFAULT 1,
  bio TEXT DEFAULT ''
);
`);

const count = db.prepare('SELECT COUNT(*) AS n FROM universities').get().n;
if (!count) {
  const uni = db.prepare('INSERT INTO universities (name_fa,name_ps,name_en,city) VALUES (?,?,?,?)');
  const uni1 = uni.run('دانشگاه کابل', 'د کابل پوهنتون', 'Kabul University', 'کابل').lastInsertRowid;
  const uni2 = uni.run('دانشگاه هرات', 'هرات پوهنتون', 'Herat University', 'هرات').lastInsertRowid;
  const uni3 = uni.run('دانشگاه بلخ', 'بلخ پوهنتون', 'Balkh University', 'مزار شریف').lastInsertRowid;
  const prog = db.prepare(`INSERT INTO programs
    (university_id,name_fa,name_ps,name_en,faculty_fa,faculty_ps,faculty_en,semesters)
    VALUES (?,?,?,?,?,?,?,?)`);
  const cs = prog.run(uni1,'کمپیوتر ساینس','کمپیوټر ساینس','Computer Science','پوهنځی کمپیوتر ساینس','د کمپیوټر ساینس پوهنځی','Faculty of Computer Science',8).lastInsertRowid;
  prog.run(uni1,'حقوق','حقوق','Law','دانشکده حقوق','د حقوقو پوهنځی','Faculty of Law',8);
  prog.run(uni2,'اقتصاد','اقتصاد','Economics','دانشکده اقتصاد','د اقتصاد پوهنځی','Faculty of Economics',8);
  const course = db.prepare('INSERT INTO courses (program_id,semester,title_fa,title_ps,title_en,description) VALUES (?,?,?,?,?,?)');
  [
    [1,'مبانی کمپیوتر','د کمپیوټر بنسټونه','Computer Fundamentals'],
    [1,'ریاضیات','ریاضي','Mathematics'],
    [1,'انگلیسی','انګلیسي','English'],
    [2,'برنامه‌نویسی مقدماتی','لومړنۍ پروګرام‌لیکنه','Introduction to Programming'],
    [2,'ساختمان داده‌ها','د معلوماتو جوړښتونه','Data Structures'],
    [3,'سیستم‌های اطلاعاتی','د معلوماتو سیستمونه','Information Systems']
  ].forEach(([sem,fa,ps,en]) => course.run(cs,sem,fa,ps,en,'نمونه اولیه؛ برنامه واقعی را با اطلاعات تأییدشده جایگزین کنید.'));
}

const adminEmail = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const adminPassword = String(process.env.ADMIN_PASSWORD || '');
if (adminEmail && adminPassword && !db.prepare('SELECT id FROM users WHERE email=?').get(adminEmail)) {
  const hash = bcrypt.hashSync(adminPassword, 12);
  db.prepare("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,'admin')")
    .run('مدیر سایت', adminEmail, hash);
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => cb(null, crypto.randomBytes(18).toString('hex') + path.extname(file.originalname).toLowerCase())
});
const upload = multer({
  storage,
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowed = ['.pdf', '.doc', '.docx', '.ppt', '.pptx', '.txt', '.png', '.jpg', '.jpeg'];
    if (!allowed.includes(ext)) return cb(new Error('نوع فایل مجاز نیست. فقط PDF، اسناد، ارائه‌ها، متن و تصویر پذیرفته می‌شود.'));
    cb(null, true);
  }
});

function currentUser(req) {
  if (!req.session.userId) return null;
  return db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(req.session.userId) || null;
}
function requireAuth(req, res, next) {
  if (!currentUser(req)) return res.status(401).json({ error: 'برای ادامه وارد حساب خود شوید.' });
  next();
}
function requireAdmin(req, res, next) {
  const user = currentUser(req);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'این بخش فقط برای مدیر سایت است.' });
  next();
}
function cleanText(value, max = 200) {
  return String(value || '').trim().slice(0, max);
}

app.get('/api/config', (_req, res) => res.json({ appName: 'دانشجویان', languages: ['fa','ps','en'] }));
app.get('/api/me', (req, res) => res.json({ user: currentUser(req) }));

app.post('/api/register', authLimiter, async (req, res) => {
  const name = cleanText(req.body.name, 80);
  const email = cleanText(req.body.email, 160).toLowerCase();
  const password = String(req.body.password || '');
  if (name.length < 2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8) {
    return res.status(400).json({ error: 'نام، ایمیل معتبر و رمز عبور حداقل ۸ حرفی وارد کنید.' });
  }
  if (db.prepare('SELECT id FROM users WHERE email=?').get(email)) return res.status(409).json({ error: 'این ایمیل قبلاً ثبت شده است.' });
  const hash = await bcrypt.hash(password, 12);
  const result = db.prepare('INSERT INTO users (name,email,password_hash) VALUES (?,?,?)').run(name,email,hash);
  db.prepare('INSERT INTO profiles (user_id) VALUES (?)').run(result.lastInsertRowid);
  req.session.userId = result.lastInsertRowid;
  res.status(201).json({ user: currentUser(req) });
});
app.post('/api/login', authLimiter, async (req, res) => {
  const email = cleanText(req.body.email, 160).toLowerCase();
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'ایمیل یا رمز عبور درست نیست.' });
  req.session.userId = user.id;
  res.json({ user: currentUser(req) });
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get('/api/catalog', (_req, res) => {
  const universities = db.prepare('SELECT * FROM universities ORDER BY name_en').all();
  const programs = db.prepare(`SELECT p.*, u.name_fa AS university_fa, u.name_ps AS university_ps, u.name_en AS university_en
    FROM programs p JOIN universities u ON u.id=p.university_id ORDER BY p.name_en`).all();
  const courses = db.prepare('SELECT * FROM courses ORDER BY program_id, semester, title_en').all();
  res.json({ universities, programs, courses });
});
app.get('/api/resources', (req, res) => {
  const courseId = Number(req.query.courseId || 0);
  const status = currentUser(req)?.role === 'admin' && req.query.status === 'pending' ? 'pending' : 'approved';
  const rows = db.prepare(`SELECT r.id,r.title,r.description,r.kind,r.original_name,r.status,r.created_at,
    u.name AS author,c.title_fa AS course_fa,c.title_ps AS course_ps,c.title_en AS course_en
    FROM resources r JOIN users u ON u.id=r.user_id JOIN courses c ON c.id=r.course_id
    WHERE r.status=? AND (?=0 OR r.course_id=?) ORDER BY r.created_at DESC`).all(status, courseId, courseId);
  res.json({ resources: rows });
});
app.get('/api/resources/:id/download', (req, res) => {
  const row = db.prepare('SELECT * FROM resources WHERE id=?').get(Number(req.params.id));
  if (!row) return res.status(404).send('فایل پیدا نشد.');
  const user = currentUser(req);
  if (row.status !== 'approved' && (!user || (user.role !== 'admin' && user.id !== row.user_id))) return res.status(403).send('این فایل هنوز تأیید نشده است.');
  const filePath = path.join(UPLOAD_DIR, path.basename(row.stored_name));
  if (!fs.existsSync(filePath)) return res.status(404).send('فایل در دسترس نیست.');
  res.download(filePath, row.original_name);
});
app.post('/api/resources', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'یک فایل انتخاب کنید.' });
  const courseId = Number(req.body.courseId);
  const course = db.prepare('SELECT id FROM courses WHERE id=?').get(courseId);
  if (!course) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'مضمون انتخاب‌شده معتبر نیست.' });
  }
  const title = cleanText(req.body.title, 120);
  if (title.length < 2) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'عنوان فایل را وارد کنید.' });
  }
  const result = db.prepare(`INSERT INTO resources (course_id,user_id,title,description,kind,original_name,stored_name)
    VALUES (?,?,?,?,?,?,?)`).run(courseId, currentUser(req).id, title, cleanText(req.body.description, 500),
    cleanText(req.body.kind, 30) || 'notes', path.basename(req.file.originalname).slice(0,180), req.file.filename);
  res.status(201).json({ id: result.lastInsertRowid, message: 'فایل ثبت شد و پس از تأیید مدیر در کتابخانه نمایش داده می‌شود.' });
});
app.get('/api/profile', requireAuth, (req, res) => {
  res.json({ profile: db.prepare('SELECT * FROM profiles WHERE user_id=?').get(currentUser(req).id) });
});
app.put('/api/profile', requireAuth, (req, res) => {
  db.prepare('UPDATE profiles SET university=?,program=?,semester=?,bio=? WHERE user_id=?').run(
    cleanText(req.body.university,120), cleanText(req.body.program,120),
    Math.max(1, Math.min(16, Number(req.body.semester) || 1)), cleanText(req.body.bio,500), currentUser(req).id
  );
  res.json({ ok: true });
});
app.get('/api/admin/resources', requireAdmin, (_req, res) => {
  res.json({ resources: db.prepare(`SELECT r.*,u.name AS author,c.title_en AS course_en FROM resources r
    JOIN users u ON u.id=r.user_id JOIN courses c ON c.id=r.course_id
    WHERE r.status='pending' ORDER BY r.created_at`).all() });
});
app.post('/api/admin/resources/:id/:action', requireAdmin, (req, res) => {
  const action = req.params.action;
  if (!['approve','reject'].includes(action)) return res.status(400).json({ error: 'عملیات نامعتبر است.' });
  const status = action === 'approve' ? 'approved' : 'rejected';
  const result = db.prepare("UPDATE resources SET status=? WHERE id=? AND status='pending'").run(status, Number(req.params.id));
  if (!result.changes) return res.status(404).json({ error: 'محتوای در انتظار پیدا نشد.' });
  res.json({ ok: true });
});

app.use('/uploads', express.static(UPLOAD_DIR, { dotfiles: 'deny', index: false }));
app.use(express.static(path.join(ROOT, 'public')));
app.get('*', (_req, res) => res.sendFile(path.join(ROOT, 'public', 'index.html')));
app.use((err, _req, res, _next) => {
  console.error(err.message);
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'حداکثر حجم فایل ۱۵ مگابایت است.' });
  res.status(400).json({ error: err.message || 'خطای غیرمنتظره رخ داد.' });
});

app.listen(PORT, () => console.log(`Daneshjuyan is running at http://localhost:${PORT}`));
