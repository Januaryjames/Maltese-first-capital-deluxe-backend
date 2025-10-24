/**
 * Maltese First Capital — Backend API
 * Features:
 * - Health check for Render
 * - CORS locked to maltesefirst.com
 * - MongoDB models (User, Transaction, KycSubmission, Admin)
 * - Client registration (OTP email), OTP verify, client login (JWT)
 * - 8-digit unique account number generator
 * - Admin login (JWT), add/edit/delete transactions, edit statements
 * - KYC submit / admin request-more / approve
 * - Secure headers, rate limit, JSON size limits
 *
 * Env Vars (Render → Environment):
 *  MONGODB_URI=...
 *  JWT_SECRET=longrandomstring
 *  EMAIL_USER=hello@maltesefirst.com
 *  EMAIL_PASS=<gmail_app_password>
 *  ALLOWED_ORIGIN=https://maltesefirst.com
 *  UPLOADTHING_TOKEN=<optional, if using UploadThing in the frontend>
 */

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const {
  MONGODB_URI,
  JWT_SECRET,
  EMAIL_USER,
  EMAIL_PASS,
  ALLOWED_ORIGIN
} = process.env;

if (!MONGODB_URI || !JWT_SECRET || !EMAIL_USER || !EMAIL_PASS) {
  console.log('[WARN] Missing required env vars. Check MONGODB_URI, JWT_SECRET, EMAIL_USER, EMAIL_PASS.');
}

const app = express();

/* ---------- Security / Infra ---------- */
app.set('trust proxy', 1); // needed behind Render proxy
app.use(helmet({
  crossOriginEmbedderPolicy: false, // allow images/fonts
  contentSecurityPolicy: false      // CSP handled at static site; API returns JSON
}));

// CORS only for your domain(s)
const allowedOrigins = [
  'https://maltesefirst.com',
  'https://www.maltesefirst.com',
];
if (ALLOWED_ORIGIN && !allowedOrigins.includes(ALLOWED_ORIGIN)) {
  allowedOrigins.push(ALLOWED_ORIGIN);
}
app.use(cors({
  origin: (origin, cb) => {
    // allow curl/Postman with no origin
    if (!origin) return cb(null, true);
    cb(null, allowedOrigins.includes(origin));
  },
  credentials: true
}));

// rate limit to keep bots in check
app.use('/api/', rateLimit({
  windowMs: 60 * 1000,
  max: 120
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

/* ---------- Database ---------- */
mongoose.set('strictQuery', true);
mongoose.connect(MONGODB_URI, { dbName: 'mfc' })
  .then(() => console.log('[DB] connected'))
  .catch(err => console.error('[DB] error', err));

/* ---------- Schemas ---------- */
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, sparse: true, index: true },
  passwordHash: String,
  fullName: String,
  accountNumber: { type: String, unique: true, sparse: true, index: true }, // 8 digits
  baseCurrency: { type: String, default: 'USD' },
  balance: { type: Number, default: 0 },
  statementNotes: { type: String, default: '' }, // admin-editable statement blurb
  createdAt: { type: Date, default: Date.now },

  // OTP for registration / login verification
  otp: {
    code: String,
    expiresAt: Date,
    purpose: String // 'register' | 'login'
  },

  // Simple KYC status
  kyc: {
    status: { type: String, enum: ['none', 'submitted', 'needs-more', 'approved'], default: 'none' },
    documents: [{
      kind: String,           // 'id', 'poa', 'selfie'
      url: String,
      uploadedAt: Date
    }],
    adminNotes: String
  }
});

const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  type: { type: String, enum: ['credit', 'debit'], required: true },
  currency: { type: String, default: 'USD' },
  amount: { type: Number, required: true },
  description: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  editedAt: Date
});

const kycSubmissionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  items: [{
    kind: String, // 'id', 'poa', 'selfie'
    url: String
  }],
  status: { type: String, enum: ['submitted', 'needs-more', 'approved'], default: 'submitted' },
  notes: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: Date
});

const adminSchema = new mongoose.Schema({
  username: { type: String, unique: true, index: true },
  passwordHash: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const KycSubmission = mongoose.model('KycSubmission', kycSubmissionSchema);
const Admin = mongoose.model('Admin', adminSchema);

/* ---------- Mail (OTP) ---------- */
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: EMAIL_USER, pass: EMAIL_PASS }
});

async function sendOtpEmail(to, code) {
  const html = `
    <div style="font-family:system-ui,Segoe UI,Roboto,Arial;padding:16px">
      <h2 style="margin:0 0 8px;color:#0b2a3d">Your Maltese First Capital code</h2>
      <p>Use the one-time code below to continue:</p>
      <div style="font-size:26px;font-weight:800;letter-spacing:3px;color:#0b2a3d">${code}</div>
      <p style="color:#666">This code expires in 10 minutes.</p>
    </div>`;
  await transporter.sendMail({
    from: `Maltese First Capital <${EMAIL_USER}>`,
    to,
    subject: 'Your verification code',
    html
  });
}

/* ---------- Helpers ---------- */
function signToken(payload, expires = '7d') {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: expires });
}

function authUser(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { uid }
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function authAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.admin) throw new Error('not admin');
    req.admin = decoded; // { aid, admin:true }
    next();
  } catch {
    res.status(401).json({ error: 'Invalid admin token' });
  }
}

async function generateUniqueAccountNumber() {
  // 8-digit, not starting with zero, ensure unique
  let tries = 0;
  while (tries < 20) {
    const n = Math.floor(10000000 + Math.random() * 90000000).toString();
    const exists = await User.findOne({ accountNumber: n }).lean();
    if (!exists) return n;
    tries++;
  }
  throw new Error('Failed to generate unique account number');
}

/* ---------- Routes ---------- */

// Health check for Render
app.get('/api/health', (req, res) => res.json({ ok: true }));

/* ----- Admin seed (one-time) ----- */
app.post('/api/admin/seed', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username & password required' });
    const exists = await Admin.findOne({ username });
    if (exists) return res.json({ ok: true, note: 'Admin already exists' });
    const passwordHash = await bcrypt.hash(password, 12);
    await Admin.create({ username, passwordHash });
    res.json({ ok: true });
  } catch (e) {
    console.error('seed error', e);
    res.status(500).json({ error: 'seed failed' });
  }
});

/* ----- Admin auth ----- */
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body || {};
  const admin = await Admin.findOne({ username });
  if (!admin) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, admin.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = signToken({ admin: true, aid: admin._id }, '12h');
  res.json({ token });
});

/* ----- Client: register (send OTP) ----- */
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, fullName, baseCurrency = 'USD' } = req.body || {};
    if (!email || !fullName) return res.status(400).json({ error: 'Missing fields' });

    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({ email, fullName, baseCurrency, kyc: { status: 'none' } });
    }

    // new OTP
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = { code, expiresAt: new Date(Date.now() + 10 * 60 * 1000), purpose: 'register' };
    await user.save();

    await sendOtpEmail(email, code);
    res.json({ ok: true });
  } catch (e) {
    console.error('register error', e);
    res.status(500).json({ error: 'register failed' });
  }
});

/* ----- Client: verify OTP -> finalize account (with 8-digit #) ----- */
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, code, password } = req.body || {};
    const user = await User.findOne({ email });
    if (!user || !user.otp) return res.status(400).json({ error: 'Invalid code' });
    if (user.otp.purpose !== 'register') return res.status(400).json({ error: 'Wrong flow' });
    if (user.otp.code !== code || new Date(user.otp.expiresAt) < new Date()) {
      return res.status(400).json({ error: 'Invalid/expired code' });
    }

    // assign account number if missing
    if (!user.accountNumber) {
      user.accountNumber = await generateUniqueAccountNumber();
    }
    if (password) {
      user.passwordHash = await bcrypt.hash(password, 12);
    }
    user.otp = undefined;
    await user.save();

    const token = signToken({ uid: user._id }, '7d');
    res.json({
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        accountNumber: user.accountNumber,
        baseCurrency: user.baseCurrency,
        balance: user.balance,
        statementNotes: user.statementNotes
      }
    });
  } catch (e) {
    console.error('verify error', e);
    res.status(500).json({ error: 'verify failed' });
  }
});

/* ----- Client: login ----- */
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = await User.findOne({ email });
  if (!user || !user.passwordHash) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = signToken({ uid: user._id }, '7d');
  res.json({
    token,
    user: {
      id: user._id,
      fullName: user.fullName,
      email: user.email,
      accountNumber: user.accountNumber,
      baseCurrency: user.baseCurrency,
      balance: user.balance,
      statementNotes: user.statementNotes
    }
  });
});

/* ----- Client: me + transactions ----- */
app.get('/api/user/me', authUser, async (req, res) => {
  const u = await User.findById(req.user.uid).lean();
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json({
    id: u._id,
    fullName: u.fullName,
    email: u.email,
    accountNumber: u.accountNumber,
    baseCurrency: u.baseCurrency,
    balance: u.balance,
    statementNotes: u.statementNotes,
    kyc: u.kyc?.status || 'none'
  });
});

app.get('/api/user/transactions', authUser, async (req, res) => {
  const list = await Transaction.find({ userId: req.user.uid }).sort({ createdAt: -1 }).lean();
  res.json(list);
});

/* ----- KYC: submit (client) ----- */
app.post('/api/kyc/submit', authUser, async (req, res) => {
  const { items = [] } = req.body || {};
  if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'No documents' });

  const sub = await KycSubmission.create({
    userId: req.user.uid,
    items,
    status: 'submitted',
    createdAt: new Date()
  });

  await User.findByIdAndUpdate(req.user.uid, { $set: { 'kyc.status': 'submitted' } });
  res.json({ ok: true, id: sub._id });
});

/* ----- Admin: KYC queue / actions ----- */
app.get('/api/admin/kyc', authAdmin, async (req, res) => {
  const items = await KycSubmission.find({}).sort({ createdAt: -1 }).lean();
  res.json(items);
});

app.post('/api/admin/kyc/:id/request-more', authAdmin, async (req, res) => {
  const { id } = req.params;
  const { notes } = req.body || {};
  const sub = await KycSubmission.findById(id);
  if (!sub) return res.status(404).json({ error: 'Not found' });
  sub.status = 'needs-more';
  sub.notes = notes || 'Please provide additional documentation.';
  sub.updatedAt = new Date();
  await sub.save();
  await User.findByIdAndUpdate(sub.userId, { $set: { 'kyc.status': 'needs-more', 'kyc.adminNotes': sub.notes } });
  res.json({ ok: true });
});

app.post('/api/admin/kyc/:id/approve', authAdmin, async (req, res) => {
  const { id } = req.params;
  const sub = await KycSubmission.findById(id);
  if (!sub) return res.status(404).json({ error: 'Not found' });
  sub.status = 'approved';
  sub.updatedAt = new Date();
  await sub.save();
  await User.findByIdAndUpdate(sub.userId, { $set: { 'kyc.status': 'approved' } });
  res.json({ ok: true });
});

/* ----- Admin: transactions ----- */
app.post('/api/admin/tx', authAdmin, async (req, res) => {
  try {
    const { userId, type, currency = 'USD', amount, description = '' } = req.body || {};
    if (!userId || !type || !amount) return res.status(400).json({ error: 'Missing fields' });
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const tx = await Transaction.create({ userId, type, currency, amount, description });
    // update balance
    const delta = type === 'credit' ? amount : -amount;
    user.balance = Number((user.balance + delta).toFixed(2));
    await user.save();

    res.json({ ok: true, tx });
  } catch (e) {
    console.error('tx add error', e);
    res.status(500).json({ error: 'failed' });
  }
});

app.put('/api/admin/tx/:id', authAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const tx = await Transaction.findById(id);
    if (!tx) return res.status(404).json({ error: 'Not found' });

    const { type, currency, amount, description } = req.body || {};
    const user = await User.findById(tx.userId);
    if (!user) return res.status(404).json({ error: 'User missing' });

    // revert old delta
    const oldDelta = tx.type === 'credit' ? tx.amount : -tx.amount;
    user.balance = Number((user.balance - oldDelta).toFixed(2));

    // apply new values
    if (type) tx.type = type;
    if (currency) tx.currency = currency;
    if (typeof amount === 'number') tx.amount = amount;
    if (typeof description === 'string') tx.description = description;
    tx.editedAt = new Date();
    await tx.save();

    // apply new delta
    const newDelta = tx.type === 'credit' ? tx.amount : -tx.amount;
    user.balance = Number((user.balance + newDelta).toFixed(2));
    await user.save();

    res.json({ ok: true, tx });
  } catch (e) {
    console.error('tx edit error', e);
    res.status(500).json({ error: 'failed' });
  }
});

app.delete('/api/admin/tx/:id', authAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const tx = await Transaction.findById(id);
    if (!tx) return res.status(404).json({ error: 'Not found' });
    const user = await User.findById(tx.userId);
    if (user) {
      const delta = tx.type === 'credit' ? tx.amount : -tx.amount;
      user.balance = Number((user.balance - delta).toFixed(2));
      await user.save();
    }
    await tx.deleteOne();
    res.json({ ok: true });
  } catch (e) {
    console.error('tx delete error', e);
    res.status(500).json({ error: 'failed' });
  }
});

/* ----- Admin: statement text (per user) ----- */
app.get('/api/admin/statement/:userId', authAdmin, async (req, res) => {
  const u = await User.findById(req.params.userId).lean();
  if (!u) return res.status(404).json({ error: 'User not found' });
  res.json({ statementNotes: u.statementNotes || '' });
});

app.put('/api/admin/statement/:userId', authAdmin, async (req, res) => {
  const { statementNotes = '' } = req.body || {};
  await User.findByIdAndUpdate(req.params.userId, { $set: { statementNotes } });
  res.json({ ok: true });
});

/* ---------- Start ---------- */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`[API] listening on ${PORT}`));
