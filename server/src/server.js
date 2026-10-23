import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import db from './db.js';
import { issueToken, verifyToken, comparePassword, createUser, findUserByUsername, findUserByEmail, getUserById, hashPassword } from './auth.js';

dotenv.config();
const app = express();
const PORT = Number(process.env.PORT || 4000);
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:5173';

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(helmet({ crossOriginResourcePolicy: false }));

const allowedOrigins = new Set(
  [process.env.CLIENT_URL, process.env.ALLOWED_ORIGINS]
    .filter(Boolean)
    .flatMap((value) => String(value).split(','))
    .map((value) => value.trim())
    .filter(Boolean)
);

const isLocalOrigin = (origin) => /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.has(origin) || isLocalOrigin(origin)) return callback(null, true);
    return callback(null, false);
  },
  credentials: true
}));
app.use(express.json({ limit: '1mb' }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'طلبات كثيرة، حاول بعد قليل.' }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'محاولات دخول كثيرة، حاول بعد 15 دقيقة.' }
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'تم إنشاء عدة حسابات من هذا الجهاز، حاول لاحقاً.' }
});

const failedLogins = new Map();
const MAX_ATTEMPTS = 5;
const LOCK_MS = 15 * 60 * 1000;

function isLocked(username) {
  const entry = failedLogins.get(username);
  if (!entry) return false;
  if (Date.now() > entry.until) {
    failedLogins.delete(username);
    return false;
  }
  return entry.count >= MAX_ATTEMPTS;
}

function registerFailure(username) {
  if (failedLogins.size > 5000) failedLogins.clear();
  const entry = failedLogins.get(username) || { count: 0, until: 0 };
  entry.count += 1;
  entry.until = Date.now() + LOCK_MS;
  failedLogins.set(username, entry);
}

function validatePassword(password) {
  if (typeof password !== 'string') return 'كلمة المرور غير صالحة';
  if (password.length < 8) return 'كلمة المرور يجب أن تكون 8 أحرف على الأقل';
  if (password.length > 128) return 'كلمة المرور طويلة جداً';
  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
    return 'كلمة المرور يجب أن تحتوي حرفاً ورقماً على الأقل';
  }
  return null;
}

function dbAll(sql, params = []) {
  return db.prepare(sql).all(...params);
}

const PHOTO_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp']);

function normalizePhoto(photo) {
  if (typeof photo !== 'string') return '';
  const match = /^data:([a-z/+.-]+);base64,/i.exec(photo.slice(0, 60));
  if (!match || !PHOTO_TYPES.has(match[1].toLowerCase())) return '';
  if (photo.length > 800000) return '';
  return photo;
}

function getAuthUser(req) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.replace('Bearer ', '');
  try {
    const payload = verifyToken(token);
    return getUserById(payload.id);
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const user = getAuthUser(req);
  if (!user) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  req.user = user;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    next();
  };
}

app.get('/api/health', (req, res) => {
  res.json({ success: true, message: 'Server is running' });
});

app.post('/api/auth/register', registerLimiter, (req, res) => {
  const {
    name,
    username,
    email,
    password,
    grade_level,
    mother_name,
    birth_date,
    gender,
    national_id,
    id_issue_country,
    id_issue_authority,
    id_issue_date,
    nationality,
    mother_tongue,
    blood_type,
    religion,
    phone,
    study_language,
    section,
    photo,
    special_needs,
    city,
    district,
    neighborhood,
    alley,
    landmark,
    living_standard,
    social_welfare,
    notes
  } = req.body || {};
  const cleanName = String(name || '').trim();
  const cleanUsername = String(username || '').trim();
  const cleanEmail = String(email || '').trim().toLowerCase();

  if (!cleanName || !cleanUsername || !cleanEmail || !password) {
    return res.status(400).json({ success: false, message: 'الاسم واسم المستخدم والبريد وكلمة المرور مطلوبة' });
  }
  if (!/^[\p{L}\p{N}_.-]{3,32}$/u.test(cleanUsername)) {
    return res.status(400).json({ success: false, message: 'اسم المستخدم يجب أن يكون بين 3 و32 حرفاً بدون مسافات' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(cleanEmail)) {
    return res.status(400).json({ success: false, message: 'البريد الإلكتروني غير صالح' });
  }
  const passwordError = validatePassword(password);
  if (passwordError) {
    return res.status(400).json({ success: false, message: passwordError });
  }
  if (findUserByUsername(cleanUsername) || findUserByEmail(cleanEmail)) {
    return res.status(409).json({ success: false, message: 'اسم المستخدم أو البريد الإلكتروني مستخدم مسبقاً' });
  }
  if (national_id && db.prepare('SELECT id FROM students WHERE national_id = ?').get(national_id)) {
    return res.status(409).json({ success: false, message: 'رقم البطاقة الوطنية الموحدة مسجل مسبقاً' });
  }

  const user = createUser({ name: cleanName, username: cleanUsername, email: cleanEmail, password, role: 'student' });
  db.prepare(`
    INSERT INTO students (
      name, grade_level, guardian_name, guardian_phone, status, user_id,
      mother_name, birth_date, gender, national_id, id_issue_country, id_issue_authority, id_issue_date,
      nationality, mother_tongue, blood_type, religion, phone, study_language, section, photo,
      special_needs, city, district, neighborhood, alley, landmark, living_standard, social_welfare, notes
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    cleanName,
    grade_level || 'غير محدد',
    '',
    '',
    'pending',
    user.id,
    mother_name || '',
    birth_date || '',
    gender || '',
    national_id || '',
    id_issue_country || '',
    id_issue_authority || '',
    id_issue_date || '',
    nationality || '',
    mother_tongue || '',
    blood_type || '',
    religion || '',
    phone || '',
    study_language || '',
    section || '',
    normalizePhoto(photo),
    special_needs || '',
    city || '',
    district || '',
    neighborhood || '',
    alley || '',
    landmark || '',
    living_standard || '',
    social_welfare || '',
    notes || ''
  );
  db.save();
  const token = issueToken(user);
  return res.status(201).json({ success: true, token, user });
});

app.post('/api/auth/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const identifier = String(username || '').trim();
  if (!identifier || !password) {
    return res.status(400).json({ success: false, message: 'اسم المستخدم وكلمة المرور مطلوبان' });
  }

  const attemptKey = identifier.toLowerCase();
  if (isLocked(attemptKey)) {
    return res.status(429).json({ success: false, message: 'الحساب مقفل مؤقتاً بعد محاولات فاشلة. حاول بعد 15 دقيقة.' });
  }

  let user = findUserByUsername(identifier);
  if (!user && identifier.includes('@')) {
    user = findUserByEmail(identifier);
  }

  if (!user || !user.password_hash || !comparePassword(password, user.password_hash)) {
    registerFailure(attemptKey);
    return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة' });
  }

  failedLogins.delete(attemptKey);

  const token = issueToken(user);
  return res.json({ success: true, token, user: { id: user.id, name: user.name, username: user.username, email: user.email, role: user.role } });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ success: true, user: req.user });
});

app.get('/api/dashboard/overview', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const studentCount = db.prepare('SELECT COUNT(*) AS total FROM students').get().total;
  const staffCount = db.prepare('SELECT COUNT(*) AS total FROM staff').get().total;
  const examCount = db.prepare('SELECT COUNT(*) AS total FROM exams').get().total;
  const attendanceSnapshot = dbAll('SELECT status, COUNT(*) AS total FROM attendance GROUP BY status');
  const gradeRows = dbAll('SELECT score, max_score FROM grades');
  const avgGrade = gradeRows.length
    ? gradeRows.reduce((sum, row) => sum + (Number(row.score) / Number(row.max_score || 1)) * 100, 0) / gradeRows.length
    : 0;

  const overview = {
    studentCount,
    staffCount,
    examCount,
    attendanceSnapshot,
    avgGrade: Number(avgGrade.toFixed(1)),
    presentCount: (attendanceSnapshot.find(row => row.status === 'present') || { total: 0 }).total,
    absentCount: (attendanceSnapshot.find(row => row.status === 'absent') || { total: 0 }).total,
    lateCount: (attendanceSnapshot.find(row => row.status === 'late') || { total: 0 }).total,
    latestStudents: dbAll('SELECT * FROM students ORDER BY created_at DESC LIMIT 5'),
    upcomingExams: dbAll('SELECT * FROM exams ORDER BY exam_date DESC LIMIT 5')
  };

  res.json({ success: true, overview });
});

app.get('/api/students', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const rows = dbAll('SELECT * FROM students ORDER BY created_at DESC');
  res.json({ success: true, students: rows });
});

app.post('/api/students', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const {
    name,
    grade_level,
    guardian_name,
    guardian_phone,
    status = 'active',
    mother_name,
    birth_date,
    gender,
    national_id,
    id_issue_country,
    id_issue_authority,
    id_issue_date,
    nationality,
    mother_tongue,
    blood_type,
    religion,
    phone,
    study_language,
    section,
    photo,
    special_needs,
    city,
    district,
    neighborhood,
    alley,
    landmark,
    living_standard,
    social_welfare,
    notes
  } = req.body || {};
  if (!name) {
    return res.status(400).json({ success: false, message: 'اسم الطالب مطلوب' });
  }

  const result = db.prepare(`
    INSERT INTO students (
      name, grade_level, guardian_name, guardian_phone, status,
      mother_name, birth_date, gender, national_id, id_issue_country, id_issue_authority, id_issue_date,
      nationality, mother_tongue, blood_type, religion, phone, study_language, section, photo,
      special_needs, city, district, neighborhood, alley, landmark, living_standard, social_welfare, notes
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    name,
    grade_level || 'غير محدد',
    guardian_name || '',
    guardian_phone || '',
    status,
    mother_name || '',
    birth_date || '',
    gender || '',
    national_id || '',
    id_issue_country || '',
    id_issue_authority || '',
    id_issue_date || '',
    nationality || '',
    mother_tongue || '',
    blood_type || '',
    religion || '',
    phone || '',
    study_language || '',
    section || '',
    normalizePhoto(photo),
    special_needs || '',
    city || '',
    district || '',
    neighborhood || '',
    alley || '',
    landmark || '',
    living_standard || '',
    social_welfare || '',
    notes || ''
  );

  db.save();
  const student = db.prepare('SELECT * FROM students WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json({ success: true, student });
});

app.post('/api/students/import', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const rows = req.body?.students;
  if (!Array.isArray(rows) || rows.length === 0) {
    return res.status(400).json({ success: false, message: 'لم يتم العثور على أسماء صالحة للاستيراد' });
  }
  if (rows.length > 500) {
    return res.status(413).json({ success: false, message: 'الحد الأقصى للاستيراد هو 500 طالب في المرة الواحدة' });
  }

  const studentsToImport = rows.map((row) => ({
    name: typeof row?.name === 'string' ? row.name.trim() : '',
    gradeLevel: typeof row?.grade_level === 'string' ? row.grade_level.trim() : '',
    guardianName: typeof row?.guardian_name === 'string' ? row.guardian_name.trim() : '',
    guardianPhone: typeof row?.guardian_phone === 'string' ? row.guardian_phone.trim() : ''
  })).filter((student) => student.name && student.name.length <= 160);

  const skipped = rows.length - studentsToImport.length;
  if (!studentsToImport.length) {
    return res.status(400).json({ success: false, message: 'تأكد من وجود عمود اسم الطالب في الملف' });
  }

  try {
    db.exec('BEGIN TRANSACTION');
    for (const student of studentsToImport) {
      db.prepare(`
        INSERT INTO students (name, grade_level, guardian_name, guardian_phone, status)
        VALUES (?, ?, ?, ?, 'active')
      `).run(student.name, student.gradeLevel || 'غير محدد', student.guardianName, student.guardianPhone);
    }
    db.exec('COMMIT');
    db.save();
  } catch (error) {
    db.exec('ROLLBACK');
    console.error('Student import failed:', error);
    return res.status(500).json({ success: false, message: 'تعذر استيراد الأسماء، لم يتم حفظ أي سجل' });
  }

  return res.status(201).json({
    success: true,
    imported: studentsToImport.length,
    skipped,
    message: `تم استيراد ${studentsToImport.length} طالب${skipped ? ` وتجاوز ${skipped} صفوف غير صالحة` : ''}`
  });
});

app.put('/api/students/:id', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const { name, grade_level, guardian_name, guardian_phone, status } = req.body || {};
  if (!name || !grade_level) {
    return res.status(400).json({ success: false, message: 'Name and grade level are required' });
  }

  db.prepare(`
    UPDATE students
    SET name = ?, grade_level = ?, guardian_name = ?, guardian_phone = ?, status = ?
    WHERE id = ?
  `).run(name, grade_level, guardian_name || '', guardian_phone || '', status || 'active', req.params.id);

  db.save();
  res.json({ success: true, student: db.prepare('SELECT * FROM students WHERE id = ?').get(req.params.id) });
});

app.delete('/api/students/:id', requireAuth, requireRole('admin'), (req, res) => {
  const student = db.prepare('SELECT id, user_id FROM students WHERE id = ?').get(req.params.id);
  if (!student) {
    return res.status(404).json({ success: false, message: 'الطالب غير موجود' });
  }

  db.prepare('DELETE FROM attendance WHERE student_id = ?').run(student.id);
  db.prepare('DELETE FROM grades WHERE student_id = ?').run(student.id);
  db.prepare('DELETE FROM students WHERE id = ?').run(student.id);
  if (student.user_id) {
    db.prepare("DELETE FROM users WHERE id = ? AND role = 'student'").run(student.user_id);
  }

  db.save();
  res.json({ success: true, message: 'تم حذف الطالب وحسابه' });
});

app.get('/api/attendance', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const rows = dbAll(`
    SELECT a.*, s.name AS student_name, s.grade_level
    FROM attendance a
    JOIN students s ON s.id = a.student_id
    ORDER BY a.date DESC, a.id DESC
  `);
  res.json({ success: true, attendance: rows });
});

app.post('/api/attendance', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const { student_id, date, status, notes } = req.body || {};
  if (!student_id || !date || !status) {
    return res.status(400).json({ success: false, message: 'Student, date and status are required' });
  }

  const existing = db.prepare('SELECT * FROM attendance WHERE student_id = ? AND date = ?').get(student_id, date);
  if (existing) {
    db.prepare(`
      UPDATE attendance
      SET status = ?, notes = ?, recorded_by = ?
      WHERE id = ?
    `).run(status, notes || '', req.user.name || req.user.username, existing.id);
  } else {
    db.prepare(`
      INSERT INTO attendance (student_id, date, status, notes, recorded_by)
      VALUES (?, ?, ?, ?, ?)
    `).run(student_id, date, status, notes || '', req.user.name || req.user.username);
  }

  db.save();
  res.status(201).json({ success: true, message: 'Attendance recorded' });
});

app.get('/api/grades', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const rows = dbAll(`
    SELECT g.*, s.name AS student_name, s.grade_level
    FROM grades g
    JOIN students s ON s.id = g.student_id
    ORDER BY g.created_at DESC
  `);
  res.json({ success: true, grades: rows });
});

app.post('/api/grades', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const { student_id, subject, exam_name, score, max_score } = req.body || {};
  if (!student_id || !subject || !exam_name || !score || !max_score) {
    return res.status(400).json({ success: false, message: 'Student, subject, exam, score and max score are required' });
  }

  const result = db.prepare(`
    INSERT INTO grades (student_id, subject, exam_name, score, max_score, teacher_name)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(student_id, subject, exam_name, Number(score), Number(max_score), req.user.name || req.user.username);

  db.save();
  const grade = db.prepare('SELECT * FROM grades WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json({ success: true, grade });
});

app.get('/api/staff', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const rows = dbAll('SELECT * FROM staff ORDER BY created_at DESC');
  res.json({ success: true, staff: rows });
});

app.post('/api/staff', requireAuth, requireRole('admin'), (req, res) => {
  const { name, role, email, phone, department } = req.body || {};
  if (!name || !role) {
    return res.status(400).json({ success: false, message: 'Name and role are required' });
  }

  const result = db.prepare(`
    INSERT INTO staff (name, role, email, phone, department)
    VALUES (?, ?, ?, ?, ?)
  `).run(name, role, email || '', phone || '', department || '');

  db.save();
  const member = db.prepare('SELECT * FROM staff WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json({ success: true, member });
});

app.get('/api/exams', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const rows = dbAll('SELECT * FROM exams ORDER BY exam_date DESC');
  res.json({ success: true, exams: rows });
});

app.post('/api/exams', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const { title, subject, exam_date, duration_minutes, room } = req.body || {};
  if (!title || !subject || !exam_date) {
    return res.status(400).json({ success: false, message: 'Title, subject and exam date are required' });
  }

  const result = db.prepare(`
    INSERT INTO exams (title, subject, exam_date, duration_minutes, room)
    VALUES (?, ?, ?, ?, ?)
  `).run(title, subject, exam_date, Number(duration_minutes || 60), room || '');

  db.save();
  const exam = db.prepare('SELECT * FROM exams WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json({ success: true, exam });
});

app.get('/api/reports', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const studentCount = db.prepare('SELECT COUNT(*) AS total FROM students').get().total;
  const staffCount = db.prepare('SELECT COUNT(*) AS total FROM staff').get().total;
  const attendanceRows = dbAll('SELECT status, COUNT(*) AS total FROM attendance GROUP BY status');
  const gradeRows = db.prepare('SELECT ROUND(AVG(score / max_score) * 100, 1) AS avg_score FROM grades WHERE max_score > 0').get();

  res.json({
    success: true,
    report: {
      studentCount,
      staffCount,
      attendance: attendanceRows,
      averageScore: Number(gradeRows?.avg_score || 0),
      latestDate: db.prepare('SELECT date FROM attendance ORDER BY date DESC LIMIT 1').get()?.date || null
    }
  });
});

app.get('/api/posts', requireAuth, (req, res) => {
  const rows = dbAll(`
    SELECT * FROM posts
    WHERE visibility = 'public'
       OR (visibility = 'private' AND ?) = 1
       OR visibility = 'teachers'
    ORDER BY created_at DESC
  `, [req.user.role === 'admin' || req.user.role === 'teacher' ? 1 : 0]);

  res.json({ success: true, posts: rows });
});

app.post('/api/posts', authLimiter, requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const { title, text, mediaType, mediaUrl, visibility = 'public' } = req.body || {};
  if (!title || !text) {
    return res.status(400).json({ success: false, message: 'Title and text are required' });
  }

  if ((visibility === 'private' || visibility === 'teachers') && req.user.role === 'student') {
    return res.status(403).json({ success: false, message: 'You cannot post in this section' });
  }

  const result = db.prepare(`
    INSERT INTO posts (title, text, media_type, media_url, visibility, author_id, author_name)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(title, text, mediaType || 'text', mediaType === 'text' ? null : (mediaUrl || ''), visibility, req.user.id, req.user.name);

  db.save();
  const lastId = Number(result.lastInsertRowid ?? result.lastInsertId ?? 0);
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(lastId);
  res.status(201).json({ success: true, post });
});

app.put('/api/posts/:id', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).json({ success: false, message: 'Post not found' });
  if (req.user.role !== 'admin' && req.user.id !== post.author_id) {
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  const { title, text, mediaType, mediaUrl, visibility } = req.body || {};
  if (!title || !text) return res.status(400).json({ success: false, message: 'Title and text are required' });

  db.prepare(`
    UPDATE posts
    SET title = ?, text = ?, media_type = ?, media_url = ?, visibility = ?
    WHERE id = ?
  `).run(title, text, mediaType || 'text', mediaType === 'text' ? null : (mediaUrl || ''), visibility || post.visibility, req.params.id);

  db.save();
  res.json({ success: true, post: db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id) });
});

app.delete('/api/posts/:id', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).json({ success: false, message: 'Post not found' });
  if (req.user.role !== 'admin' && req.user.id !== post.author_id) {
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  db.prepare('DELETE FROM posts WHERE id = ?').run(req.params.id);
  db.save();
  res.json({ success: true, message: 'Post deleted' });
});

app.listen(PORT, () => {
  console.log(`API running on http://localhost:${PORT}`);
});
