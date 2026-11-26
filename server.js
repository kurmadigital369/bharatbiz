require('dotenv').config();
const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me_in_production';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// SQLite setup
const db = new sqlite3.Database(path.join(__dirname, 'bharatbiz.db'));

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      verified INTEGER DEFAULT 0,
      otp_code TEXT,
      otp_expires_at INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS businesses (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      state TEXT NOT NULL,
      city TEXT NOT NULL,
      pin TEXT NOT NULL,
      address TEXT NOT NULL,
      phone TEXT NOT NULL,
      website TEXT,
      hours TEXT,
      is_open INTEGER DEFAULT 1,
      verified INTEGER DEFAULT 0,
      featured INTEGER DEFAULT 0,
      rating REAL DEFAULT 5.0,
      review_count INTEGER DEFAULT 0,
      tags TEXT,
      description TEXT,
      owner_email TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      business_id TEXT NOT NULL,
      author TEXT NOT NULL,
      rating INTEGER NOT NULL,
      text TEXT NOT NULL,
      date TEXT NOT NULL,
      FOREIGN KEY (business_id) REFERENCES businesses(id)
    )
  `);
});

// Nodemailer SMTP transport
function createTransporter() {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    return null;
  }
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

async function sendOtpEmail(email, name, otp) {
  const transporter = createTransporter();
  if (!transporter) {
    console.log(`[DEV FALLBACK] SMTP not configured. OTP for ${email}: ${otp}`);
    return { delivered: false, devMode: true };
  }
  await transporter.sendMail({
    from: process.env.FROM_EMAIL || process.env.SMTP_USER,
    to: email,
    subject: 'Your BharatBiz Email Verification Code',
    html: `
      <div style="font-family: sans-serif; max-width: 480px; margin: auto; padding: 24px; border: 1px solid #e2e8f0; border-radius: 12px;">
        <h2 style="color: #0f172a; margin-top: 0;">Verify your BharatBiz account</h2>
        <p style="color: #475569;">Hi ${name},</p>
        <p style="color: #475569;">Use the following 6-digit code to verify your email address. It expires in 10 minutes.</p>
        <div style="font-size: 28px; font-weight: 700; letter-spacing: 6px; color: #ea580c; background: #fff7ed; padding: 14px; text-align: center; border-radius: 8px; margin: 16px 0;">
          ${otp}
        </div>
        <p style="color: #64748b; font-size: 12px;">If you did not request this, you can safely ignore this email.</p>
      </div>
    `
  });
  return { delivered: true, devMode: false };
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const name = (req.body.name || '').trim();
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';

    if (!name || !email || password.length < 6) {
      return res.status(400).json({ error: 'Name, valid email, and password (min 6 chars) are required.' });
    }

    const existing = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => (err ? reject(err) : resolve(row)));
    });

    if (existing && existing.verified) {
      return res.status(409).json({ error: 'An account with this email already exists. Please sign in.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = Date.now() + 10 * 60 * 1000;

    if (existing) {
      await new Promise((resolve, reject) => {
        db.run(
          'UPDATE users SET name = ?, password_hash = ?, otp_code = ?, otp_expires_at = ? WHERE email = ?',
          [name, passwordHash, otp, expiresAt, email],
          (err) => (err ? reject(err) : resolve())
        );
      });
    } else {
      await new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO users (name, email, password_hash, verified, otp_code, otp_expires_at) VALUES (?, ?, ?, 0, ?, ?)',
          [name, email, passwordHash, otp, expiresAt],
          (err) => (err ? reject(err) : resolve())
        );
      });
    }

    const mailResult = await sendOtpEmail(email, name, otp);
    return res.json({
      ok: true,
      message: mailResult.delivered
        ? 'Verification OTP sent to your email.'
        : 'SMTP not configured in .env; check server console for OTP.',
      devMode: mailResult.devMode
    });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Failed to register account.' });
  }
});

// POST /api/auth/verify-otp
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const otp = (req.body.otp || '').trim();

    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => (err ? reject(err) : resolve(row)));
    });

    if (!user || user.otp_code !== otp) {
      return res.status(400).json({ error: 'Invalid OTP code.' });
    }
    if (Date.now() > Number(user.otp_expires_at)) {
      return res.status(400).json({ error: 'OTP has expired. Please register again.' });
    }

    await new Promise((resolve, reject) => {
      db.run('UPDATE users SET verified = 1, otp_code = NULL, otp_expires_at = NULL WHERE id = ?', [user.id], (err) =>
        err ? reject(err) : resolve()
      );
    });

    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ ok: true, token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) {
    console.error('Verify OTP error:', err);
    return res.status(500).json({ error: 'Verification failed.' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';

    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => (err ? reject(err) : resolve(row)));
    });

    if (!user || !user.verified) {
      return res.status(401).json({ error: 'Invalid email or account not verified.' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ ok: true, token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Login failed.' });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// GET /api/businesses
app.get('/api/businesses', (req, res) => {
  db.all('SELECT * FROM businesses ORDER BY created_at DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const parsed = rows.map(r => ({
      id: r.id,
      name: r.name,
      category: r.category,
      state: r.state,
      city: r.city,
      pin: r.pin,
      address: r.address,
      phone: r.phone,
      website: r.website,
      hours: r.hours,
      isOpen: Boolean(r.is_open),
      verified: Boolean(r.verified),
      featured: Boolean(r.featured),
      rating: r.rating,
      reviewCount: r.review_count,
      tags: r.tags ? JSON.parse(r.tags) : [],
      description: r.description,
      ownerEmail: r.owner_email,
      reviews: []
    }));
    res.json({ businesses: parsed });
  });
});

// POST /api/businesses (auth required)
app.post('/api/businesses', authMiddleware, (req, res) => {
  const b = req.body;
  if (!b.name || !b.category || !b.state || !b.city || !b.pin || !b.address || !b.phone) {
    return res.status(400).json({ error: 'Missing required business fields.' });
  }
  const id = 'biz-' + Date.now();
  const tagsJson = JSON.stringify(Array.isArray(b.tags) ? b.tags : []);
  db.run(
    `INSERT INTO businesses (id, name, category, state, city, pin, address, phone, website, hours, is_open, verified, featured, rating, review_count, tags, description, owner_email)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 1, 5.0, 1, ?, ?, ?)`,
    [id, b.name, b.category, b.state, b.city, b.pin, b.address, b.phone, b.website || '', b.hours || '9:30 AM – 7:30 PM', tagsJson, b.description || '', req.user.email],
    (err) => {
      if (err) return res.status(500).json({ error: 'Could not save business.' });
      res.status(201).json({ ok: true, id });
    }
  );
});

app.listen(PORT, () => {
  console.log(`BharatBiz server running at http://localhost:${PORT}`);
});
