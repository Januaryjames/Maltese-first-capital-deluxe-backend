// Maltese First Capital — backend (email-only submit + admin bootstrap + dev seed)
// CORS fixed for x-seed-key; Turnstile optional; Mongo optional (for accounts).

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const nodemailer = require('nodemailer');
const { randomUUID } = require('crypto');
const mongoose = require('mongoose');

// ───────────────────────────────── ENV
const {
  PORT = 8080,
  NODE_ENV = 'production',
  CORS_ORIGIN = 'https://maltesefirst.com,https://www.maltesefirst.com',
  DEV_SEED_KEY = '',
  JWT_SECRET = 'change_me',
  MONGODB_URI = '',
  // email
  SMTP_HOST = '', SMTP_PORT = '', SMTP_USER = '', SMTP_PASS = '',
  NOTIFY_FROM = 'Maltese First <no-reply@maltesefirst.com>',
  NOTIFY_TO = 'hello@maltesefirst.com',
  // captcha
  TURNSTILE_SECRET = '',
  BYPASS_CAPTCHA = '1'
} = process.env;

// ───────────────────────────────── App
const app = express();
app.set('trust proxy', 1);

// CORS + preflight (allow custom admin seed header)
const ALLOWED = CORS_ORIGIN.split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) =>
    !origin || ALLOWED.includes(origin) ? cb(null, true) : cb(new Error('Not allowed by CORS')),
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Requested-With','x-seed-key','X-Seed-Key']
}));
app.options('*', cors());

// Helmet (CSP off to simplify Turnstile/inline)
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use('/api/', rateLimit({ windowMs: 10*60*1000, max: 200 }));

// ───────────────────────────────── Mailer
let mailer = null;
if (SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS) {
  mailer = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: Number(SMTP_PORT) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
}
async function sendMail(subject, html, attachments = []) {
  if (!mailer) throw new Error('SMTP not configured');
  return mailer.sendMail({
    from: NOTIFY_FROM,
    to: NOTIFY_TO,
    subject,
    html,
    attachments
  });
}

// ───────────────────────────────── Mongo (optional; needed for accounts)
let mongoReady = false;
if (MONGODB_URI) {
  mongoose.connect(MONGODB_URI, { maxPoolSize: 20 })
    .then(() => { mongoReady = true; console.log('Mongo connected:', mongoose.connection.name); })
    .catch(e => { console.error('Mongo connect error:', e.message); });
}

// Schemas (if Mongo present)
const User = mongoose.models.User || new mongoose.model('User', new mongoose.Schema({
  email: { type:String, unique:true, index:true, required:true, lowercase:true, trim:true },
  passwordHash: { type:String, required:true },
  role: { type:String, enum:['client','admin'], default:'client', index:true },
  name: { type:String, trim:true }
},{timestamps:true}));

const TxnSchema = new mongoose.Schema({
  ts: { type: Date, default: () => new Date() },
  type: { type: String, enum: ['credit','debit'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  description: String,
  meta: Object
}, { _id: false });

const Account = mongoose.models.Account || new mongoose.model('Account', new mongoose.Schema({
  accountNo: { type: String, unique: true, index: true },   // 8-digit
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  status: { type: String, enum: ['not_activated','active','suspended'], default: 'not_activated', index: true },
  currency: { type: String, default: 'USD' },
  balance: { type: Number, default: 0 },
  lines: [TxnSchema],
  companyName: { type: String, default: '' }
}, { timestamps: true }));

function genAccountNo(){ return String(Math.floor(10_000_000 + Math.random()*90_000_000)); }
function makeToken(u){ return jwt.sign({ sub:u.id, role:u.role, name:u.name }, JWT_SECRET, { expiresIn:'1h' }); }

// ───────────────────────────────── Multer (email-only attachments)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 16 * 1024 * 1024 } // 16MB per file
});
const kycFields = upload.fields([
  { name:'passport', maxCount:5 },
  { name:'proofOfAddress', maxCount:5 },
  { name:'companyDocs', maxCount:20 },
  { name:'selfie', maxCount:2 },
  // alt names used in your form
  { name:'docs_id', maxCount:5 },
  { name:'docs_poa', maxCount:5 },
  { name:'docs_corporate', maxCount:20 },
  { name:'docs_sof', maxCount:20 },
  { name:'selfie_file', maxCount:2 }
]);

// ───────────────────────────────── Helpers
async function verifyTurnstile(token, ip) {
  if (BYPASS_CAPTCHA === '1') return true;
  if (!TURNSTILE_SECRET) return true;
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: {'content-type':'application/x-www-form-urlencoded'},
      body: `secret=${encodeURIComponent(TURNSTILE_SECRET)}&response=${encodeURIComponent(token||'')}&remoteip=${encodeURIComponent(ip||'')}`
    });
    const d = await r.json();
    return !!d.success;
  } catch {
    return false;
  }
}

function fileListFrom(req, names) {
  const out = [];
  for (const n of names) {
    const arr = req.files?.[n] || [];
    out.push(...arr);
  }
  return out;
}

// ───────────────────────────────── Routes
app.get('/api/health', (_req,res)=> res.json({ ok:true, env:NODE_ENV, mongo:mongoReady, uptime:process.uptime() }));

// SMTP debug
app.get('/api/debug/smtp', async (_req,res) => {
  try {
    await sendMail('SMTP OK', '<p>SMTP check ok.</p>');
    res.json({ ok:true });
  } catch (e) {
    res.status(500).json({ ok:false, error:'SMTP_VERIFY_FAILED', detail:e.message });
  }
});

// Email-only KYC submission (fast path)
async function emailOnlyHandler(req, res) {
  try {
    // Turnstile (optional)
    const ts = req.body?.['cf_turnstile_response'] || req.body?.['cf-turnstile-response'] || '';
    const tsOK = await verifyTurnstile(ts, req.ip);
    if (!tsOK) return res.status(400).json({ error:'Captcha verification failed' });

    // Pull attachments from any of the supported field names
    const files = [
      ...fileListFrom(req, ['passport','docs_id']),
      ...fileListFrom(req, ['proofOfAddress','docs_poa']),
      ...fileListFrom(req, ['companyDocs','docs_corporate','docs_sof']),
      ...fileListFrom(req, ['selfie','selfie_file'])
    ];
    const attachments = files.map(f => ({
      filename: f.originalname,
      content: f.buffer,
      contentType: f.mimetype
    }));

    // Basic HTML summary
    const b = req.body || {};
    const html = `
      <h2>New Account Application (Email-Only)</h2>
      <table border="1" cellpadding="6" cellspacing="0">
        <tr><td><b>Company / Account Name</b></td><td>${b.company_name || b.companyName || '-'}</td></tr>
        <tr><td><b>Authorised Person</b></td><td>${b.authorised_person || b.authorized_person || b.fullName || '-'}</td></tr>
        <tr><td><b>Email</b></td><td>${b.email || '-'}</td></tr>
        <tr><td><b>Phone</b></td><td>${b.phone || '-'}</td></tr>
        <tr><td><b>Country</b></td><td>${b.country || '-'}</td></tr>
        <tr><td><b>Address</b></td><td>${b.company_address || b.address || '-'}</td></tr>
        <tr><td><b>Account Type</b></td><td>${b.account_type || b.accountType || '-'}</td></tr>
        <tr><td><b>Currency</b></td><td>${b.currency || '-'}</td></tr>
        <tr><td><b>Commercial Registration</b></td><td>${b.commercial_registration || b.commercialRegistration || '-'}</td></tr>
        <tr><td><b>Source of Funds</b></td><td>${b.source_of_funds || b.sourceOfFunds || '-'}</td></tr>
        <tr><td><b>Notes</b></td><td>${b.notes || '-'}</td></tr>
        <tr><td><b>IP</b></td><td>${req.ip}</td></tr>
      </table>
      <p>Attachments: ${attachments.length}</p>
    `;

    await sendMail('New Account Application (Email-Only)', html, attachments);
    return res.json({ ok:true, delivered:true, attachments:attachments.length });
  } catch (e) {
    console.error('emailOnly error:', e);
    return res.status(500).json({ error:'Server error' });
  }
}

// Wire multiple aliases used by the site to the same handler
app.post('/api/onboarding/email-only', kycFields, emailOnlyHandler);
app.post('/api/onboarding/submit', kycFields, emailOnlyHandler);
app.post('/api/onboarding/account-open', kycFields, emailOnlyHandler);
app.post('/api/public/account-open', kycFields, emailOnlyHandler);

// ───────────────────────────────── Admin bootstrap (create admin user)
app.post('/api/admin/bootstrap', async (req, res) => {
  try {
    const key = req.headers['x-seed-key'] || req.headers['X-Seed-Key'];
    if (!DEV_SEED_KEY || key !== DEV_SEED_KEY) return res.status(403).json({ error:'Forbidden' });
    if (!mongoReady) return res.status(500).json({ error:'Mongo not configured' });

    const { email, password, name = 'Administrator' } = req.body || {};
    if (!email || !password) return res.status(400).json({ error:'email and password required' });

    const exists = await User.findOne({ email: email.toLowerCase(), role: 'admin' });
    if (exists) return res.status(409).json({ error:'Admin already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    await User.create({ email: email.toLowerCase(), name, role: 'admin', passwordHash });
    res.json({ ok: true });
  } catch (e) {
    console.error('bootstrap error:', e);
    res.status(500).json({ error:'Server error' });
  }
});

// ───────────────────────────────── Dev seed account for a client
app.post('/api/admin/dev-seed-account', async (req, res) => {
  try {
    const key = req.headers['x-seed-key'] || req.headers['X-Seed-Key'];
    if (!DEV_SEED_KEY || key !== DEV_SEED_KEY) return res.status(403).json({ error:'Forbidden' });
    if (!mongoReady) return res.status(500).json({ error:'Mongo not configured' });

    const { email, amount = 0, currency = 'USD', status = 'active', ts, companyName = '' } = req.body || {};
    if (!email) return res.status(400).json({ error:'email required' });

    let user = await User.findOne({ email: email.toLowerCase(), role: 'client' });
    if (!user) {
      const temp = randomUUID().slice(0, 12);
      user = await User.create({
        email: email.toLowerCase(),
        name: email.split('@')[0],
        role: 'client',
        passwordHash: await bcrypt.hash(temp, 10)
      });
    }

    const accountNo = genAccountNo();
    const when = ts ? new Date(ts) : new Date();
    const acct = await Account.create({
      accountNo,
      owner: user._id,
      status,
      currency,
      balance: amount,
      companyName,
      lines: amount > 0 ? [
        { ts: when, type:'credit', amount, currency, description:'Admin Seed', meta:{ source:'admin-seed' } }
      ] : []
    });

    res.json({ ok:true, accountNo: acct.accountNo, user: user.email, status: acct.status, companyName: acct.companyName });
  } catch (e) {
    console.error('dev-seed error:', e);
    res.status(500).json({ error:'Server error' });
  }
});

// ───────────────────────────────── Auth (minimal)
app.post('/api/auth/login', async (req, res) => {
  try {
    if (!mongoReady) return res.status(500).json({ error:'Mongo not configured' });
    const { email, password } = req.body || {};
    const u = await User.findOne({ email:(email||'').toLowerCase(), role:'client' });
    if (!u) return res.status(400).json({ error:'Invalid credentials' });
    const ok = await bcrypt.compare(password||'', u.passwordHash);
    if (!ok) return res.status(400).json({ error:'Invalid credentials' });
    res.json({ token: makeToken(u), user:{ id:u.id, email:u.email, name:u.name, role:u.role } });
  } catch (e) {
    console.error('client login error:', e);
    res.status(500).json({ error:'Server error' });
  }
});

app.post('/api/admin/login', async (req, res) => {
  try {
    if (!mongoReady) return res.status(500).json({ error:'Mongo not configured' });
    const { email, password } = req.body || {};
    const u = await User.findOne({ email:(email||'').toLowerCase(), role:'admin' });
    if (!u) return res.status(400).json({ error:'Invalid credentials' });
    const ok = await bcrypt.compare(password||'', u.passwordHash);
    if (!ok) return res.status(400).json({ error:'Invalid credentials' });
    res.json({ token: makeToken(u), user:{ id:u.id, email:u.email, name:u.name, role:u.role } });
  } catch (e) {
    console.error('admin login error:', e);
    res.status(500).json({ error:'Server error' });
  }
});

// Friendly multer errors
app.use((err, _req, res, next) => {
  if (err && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'File too large (max 16MB each)' });
  }
  next(err);
});

// ───────────────────────────────── Boot
app.listen(PORT, () => console.log(`API listening on :${PORT}`));
