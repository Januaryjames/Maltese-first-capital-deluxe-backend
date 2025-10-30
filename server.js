// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const fetch = require('node-fetch');

const { connectMongo, getGridFSBucket, shutdown } = require('./db');
const User = require('./models/User');
const Application = require('./models/Application');
const ResetToken = require('./models/ResetToken');

const {
  PORT = 8080,
  JWT_SECRET = 'change_me',
  CORS_ORIGIN = 'https://maltesefirst.com',
  TURNSTILE_SECRET,
  MONGODB_URI,
  DEV_SEED_KEY
} = process.env;

if (!MONGODB_URI) throw new Error('MONGODB_URI missing');
if (!TURNSTILE_SECRET) console.warn('WARNING: TURNSTILE_SECRET is not set. Turnstile will fail.');

const app = express();

// Security middleware
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// Rate limit
app.use('/api/', rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
}));

// Health endpoint
app.get('/api/health', (req, res) => {
  res.json({ ok: true, version: '1.1.0', uptime: process.uptime() });
});

// JWT helpers
function makeToken(user) {
  return jwt.sign({ sub: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '1h' });
}
function authRequired(role) {
  return (req, res, next) => {
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      if (role && payload.role !== role) return res.status(403).json({ error: 'Forbidden' });
      req.user = payload;
      next();
    } catch {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}

// Turnstile verification
async function verifyTurnstile(token, remoteip) {
  if (!TURNSTILE_SECRET) return false;
  try {
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `secret=${encodeURIComponent(TURNSTILE_SECRET)}&response=${encodeURIComponent(token)}&remoteip=${encodeURIComponent(remoteip || '')}`
    });
    const data = await resp.json();
    return !!data.success;
  } catch {
    return false;
  }
}

// Multer (memory) → GridFS
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024 } });

// AUTH: client login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = await User.findOne({ email: (email||'').toLowerCase(), role: 'client' });
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password || '', user.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
  return res.json({ token: makeToken(user), user: { id: user.id, name: user.name, role: user.role } });
});

// AUTH: admin login
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = await User.findOne({ email: (email||'').toLowerCase(), role: 'admin' });
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password || '', user.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
  return res.json({ token: makeToken(user), user: { id: user.id, name: user.name, role: user.role } });
});

// Password reset request (persists token)
app.post('/api/auth/request-reset', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });
  const expires = new Date(Date.now() + 1000 * 60 * 30); // 30 mins
  const token = uuidv4().replace(/-/g, '');
  await ResetToken.create({ email: email.toLowerCase(), token, expiresAt: expires });
  // TODO: email the token/link to user
  return res.status(204).end();
});

// Password reset confirm
app.post('/api/auth/reset', async (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword) return res.status(400).json({ error: 'Token and newPassword required' });
  const found = await ResetToken.findOne({ token, used: false, expiresAt: { $gt: new Date() } });
  if (!found) return res.status(400).json({ error: 'Invalid or expired token' });
  const user = await User.findOne({ email: found.email });
  if (!user) return res.status(400).json({ error: 'No account for token' });
  user.passwordHash = await bcrypt.hash(newPassword, 10);
  await user.save();
  found.used = true;
  await found.save();
  return res.status(204).end();
});

// Onboarding submit (multipart + GridFS + Turnstile)
app.post('/api/onboarding/submit',
  upload.fields([
    { name: 'passport', maxCount: 1 },
    { name: 'proofOfAddress', maxCount: 1 },
    { name: 'companyDocs', maxCount: 10 },
    { name: 'selfie', maxCount: 1 }
  ]),
  async (req, res) => {
    const remoteip = req.ip;
    const turnstileToken = req.body['cf_turnstile_response'];
    const okCaptcha = await verifyTurnstile(turnstileToken, remoteip);
    if (!okCaptcha) return res.status(400).json({ error: 'Captcha verification failed' });

    const gfs = getGridFSBucket();

    async function saveFiles(fieldName) {
      const arr = req.files?.[fieldName] || [];
      const out = [];
      for (const f of arr) {
        const filename = `${Date.now()}_${f.originalname}`;
        const uploadStream = gfs.openUploadStream(filename, { contentType: f.mimetype });
        uploadStream.end(f.buffer);
        const finished = await new Promise((resolve, reject) => {
          uploadStream.on('finish', resolve);
          uploadStream.on('error', reject);
        });
        out.push({
          gridfsId: finished._id,
          filename,
          mime: f.mimetype,
          size: f.size
        });
      }
      return out;
    }

    const [passport, proofOfAddress, companyDocs, selfie] = await Promise.all([
      saveFiles('passport'),
      saveFiles('proofOfAddress'),
      saveFiles('companyDocs'),
      saveFiles('selfie')
    ]);

    const { fullName, email, phone, companyName, country } = req.body;
    const applicationId = uuidv4();

    const doc = await Application.create({
      applicationId,
      status: 'received',
      fields: { fullName, email, phone, companyName, country },
      files: { passport, proofOfAddress, companyDocs, selfie },
      submittedByIp: remoteip
    });

    return res.json({
      applicationId: doc.applicationId,
      status: doc.status,
      receivedAt: doc.createdAt
    });
  }
);

// Example protected client endpoint
app.get('/api/client/overview', authRequired('client'), async (req, res) => {
  // TODO: pull accounts from DB; static sample for now
  res.json({
    accounts: [
      { id: 'ACC-USD-001', currency: 'USD', balance: 5000000.00 },
      { id: 'ACC-EUR-002', currency: 'EUR', balance: 1250000.00 }
    ]
  });
});

// Admin views
app.get('/api/admin/applications', authRequired('admin'), async (req, res) => {
  const items = await Application.find().sort({ createdAt: -1 }).limit(100);
  res.json({ items });
});

app.post('/api/admin/applications/:id/decision', authRequired('admin'), async (req, res) => {
  // TODO: add body {decision:"approved"|"rejected"}
  res.status(204).end();
});

// Minimal seeder (one-shot) to create demo client/admin
app.post('/api/dev/seed-admin', async (req, res) => {
  const key = req.headers['x-seed-key'];
  if (!DEV_SEED_KEY || key !== DEV_SEED_KEY) return res.status(403).json({ error: 'Forbidden' });

  const ensure = async (email, password, role, name) => {
    let u = await User.findOne({ email });
    if (!u) {
      u = await User.create({
        email,
        passwordHash: await bcrypt.hash(password, 10),
        role,
        name
      });
    }
    return u;
  };

  const client = await ensure('client@example.com', 'client123', 'client', 'Demo Client');
  const admin  = await ensure('admin@example.com',  'admin123',  'admin',  'Demo Admin');

  res.json({ ok: true, client: client.email, admin: admin.email });
});

// Start/Stop
(async () => {
  try {
    await connectMongo(MONGODB_URI);
    app.listen(PORT, () => console.log(`API listening on :${PORT}`));
    const handle = async () => { await shutdown(); process.exit(0); };
    process.on('SIGINT', handle);
    process.on('SIGTERM', handle);
  } catch (err) {
    console.error('Boot error:', err);
    process.exit(1);
  }
})();
