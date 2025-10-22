// server.js  — Maltese First Capital (Node 20+, ESM)
// Ensure your package.json has:  "type": "module",  "start": "node server.js"

import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';

// ----------- ENV -----------
const {
  PORT = 10000,
  MONGODB_URI,
  JWT_SECRET = 'change_me',
  EMAIL_USER,
  EMAIL_PASS,
  ADMIN_USER = 'mfcliveadmin',
  ADMIN_PASS = 'MFC!7hP9r2qZsX8d',
  FRONTEND_ORIGINS // optional: comma-separated allowlist
} = process.env;

if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI missing'); process.exit(1);
}

// ----------- APP -----------
const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(helmet());

// CORS allowlist (your two Render static sites by default)
const defaultOrigins = [
  'https://maltese-first-capital-deluxe-frontend.onrender.com',
  'https://maltese-first-capital-deluxe-frontend-full.onrender.com'
];
const allowList = (FRONTEND_ORIGINS ? FRONTEND_ORIGINS.split(',') : defaultOrigins)
  .map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => cb(null, !origin || allowList.includes(origin)),
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.options('*', cors());

// Basic rate limits
const authLimiter = rateLimit({ windowMs: 60_000, max: 60 });
app.use('/api/', authLimiter);

// ----------- DB -----------
await mongoose.connect(MONGODB_URI, { dbName: 'mfc_internal' });
mongoose.connection.on('connected', () => console.log('✅ Mongo connected'));

// ----------- MODELS -----------
const UserSchema = new mongoose.Schema({
  fullName: String,
  email: { type: String, unique: true },
  passwordHash: String,
  phone: String,
  address: String,
  govId: String
}, { timestamps: true });
const User = mongoose.model('User', UserSchema);

const AccountSchema = new mongoose.Schema({
  userId: mongoose.ObjectId,
  currency: { type: String, enum: ['USD','EUR'] },
  accountNumber: { type: String, index: true }, // 8-digit string
  balance: { type: Number, default: 0 }
}, { timestamps: true });
const Account = mongoose.model('Account', AccountSchema);

const TxSchema = new mongoose.Schema({
  userId: mongoose.ObjectId,
  currency: { type: String, enum: ['USD','EUR'] },
  type: { type: String, enum: ['credit','debit'] },
  amount: Number,
  desc: String
}, { timestamps: true });
const Tx = mongoose.model('Tx', TxSchema);

// Temporary registration (email OTP before creating user)
const TempRegSchema = new mongoose.Schema({
  fullName: String, email: String, passwordHash: String,
  phone: String, address: String, govId: String,
  otp: String, otpExpires: Date
}, { timestamps: true });
const TempReg = mongoose.model('TempReg', TempRegSchema);

// Login 2FA (email OTP)
const Login2FASchema = new mongoose.Schema({
  userId: mongoose.ObjectId,
  otp: String, otpExpires: Date
}, { timestamps: true });
const Login2FA = mongoose.model('Login2FA', Login2FASchema);

// KYC records (UploadThing URLs saved here)
const KYCSchema = new mongoose.Schema({
  regId: String,
  userId: mongoose.ObjectId,
  fullName: String,
  email: String,
  docType: String,
  docFrontUrl: String,
  docBackUrl: String,
  selfieUrl: String,
  status: { type: String, enum: ['pending','approved','rejected'], default: 'pending' },
  notes: String,
  createdAt: { type: Date, default: Date.now },
  decidedAt: Date
});
const KYC = mongoose.model('KYC', KYCSchema);

// ----------- HELPERS -----------
const tokenFor = (sub, role) => jwt.sign({ sub, role }, JWT_SECRET, { expiresIn: '2d' });

async function sendMail(to, subject, text) {
  if (!EMAIL_USER || !EMAIL_PASS) {
    console.log('✉️ (dev) email to:', to, subject, text);
    return;
  }
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: EMAIL_USER, pass: EMAIL_PASS }
  });
  await transporter.sendMail({ from: EMAIL_USER, to, subject, text });
}

function genOTP(n = 6) {
  return Array.from({ length: n }, () => Math.floor(Math.random() * 10)).join('');
}

async function genUnique8() {
  while (true) {
    const num = String(Math.floor(Math.random() * 90_000_000) + 10_000_000); // 8-digit, no leading 0
    const exists = await Account.findOne({ accountNumber: num }).lean();
    if (!exists) return num;
  }
}

async function createStarterAccounts(userId) {
  const usd = await genUnique8();
  const eur = await genUnique8();
  await Account.insertMany([
    { userId, currency: 'USD', accountNumber: usd, balance: 0 },
    { userId, currency: 'EUR', accountNumber: eur, balance: 0 }
  ]);
}

// Auth middleware
function auth(role) {
  return (req, res, next) => {
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : '';
    try {
      const dec = jwt.verify(token, JWT_SECRET);
      if (role && dec.role !== role) return res.status(403).send('Forbidden');
      req.auth = dec; next();
    } catch {
      return res.status(401).send('Unauthorized');
    }
  };
}

// ----------- ROUTES -----------

// Health
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// ADMIN LOGIN
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USER || password !== ADMIN_PASS) {
    return res.status(400).send('Invalid admin credentials');
  }
  return res.json({ token: tokenFor('admin', 'admin') });
});

// CLIENT REGISTRATION (sends OTP, stores temp)
app.post('/api/auth/register', async (req, res) => {
  const { fullName, email, password, phone, address, govId } = req.body || {};
  if (!fullName || !email || !password) return res.status(400).json({ message: 'Missing fields' });

  const existing = await User.findOne({ email }).lean();
  if (existing) return res.status(400).json({ message: 'Email already registered' });

  const otp = genOTP(6);
  const passwordHash = await bcrypt.hash(password, 10);
  const tr = await TempReg.create({
    fullName, email, passwordHash, phone, address, govId,
    otp, otpExpires: new Date(Date.now() + 10 * 60 * 1000) // 10 min
  });

  await sendMail(email, 'Your Maltese First Capital OTP', `Your OTP is: ${otp}`);

  return res.json({ regId: tr._id.toString() });
});

// VERIFY OTP → create User + starter accounts
app.post('/api/auth/verify-otp', async (req, res) => {
  const { regId, otp } = req.body || {};
  const tr = await TempReg.findById(regId);
  if (!tr) return res.status(400).json({ ok: false, message: 'Registration not found' });
  if (tr.otp !== otp || tr.otpExpires < new Date()) {
    return res.status(400).json({ ok: false, message: 'Invalid/expired OTP' });
  }

  const user = await User.create({
    fullName: tr.fullName,
    email: tr.email,
    passwordHash: tr.passwordHash,
    phone: tr.phone,
    address: tr.address,
    govId: tr.govId
  });
  await createStarterAccounts(user._id);
  await TempReg.deleteOne({ _id: tr._id });

  return res.json({ ok: true, userId: user._id.toString() });
});

// CLIENT LOGIN (step 1 → send OTP)
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const u = await User.findOne({ email });
  if (!u) return res.status(400).json({ message: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, u.passwordHash || '');
  if (!ok) return res.status(400).json({ message: 'Invalid credentials' });

  const otp = genOTP(6);
  await Login2FA.create({
    userId: u._id,
    otp,
    otpExpires: new Date(Date.now() + 10 * 60 * 1000)
  });
  await sendMail(u.email, 'Your login OTP', `Your OTP is: ${otp}`);

  return res.json({ loginId: u._id.toString() }); // client will use /verify-2fa with this
});

// CLIENT LOGIN (step 2 → verify OTP & issue JWT)
app.post('/api/auth/verify-2fa', async (req, res) => {
  const { loginId, otp } = req.body || {};
  const rec = await Login2FA.findOne({ userId: loginId }).sort({ createdAt: -1 });
  if (!rec) return res.status(400).json({ message: 'No OTP pending' });
  if (rec.otp !== otp || rec.otpExpires < new Date()) {
    return res.status(400).json({ message: 'Invalid/expired OTP' });
  }
  await Login2FA.deleteMany({ userId: loginId });
  return res.json({ token: tokenFor(loginId, 'client') });
});

// CLIENT DASHBOARD DATA
app.get('/api/client/overview', auth('client'), async (req, res) => {
  const userId = req.auth.sub;
  const user = await User.findById(userId).lean();
  const accts = await Account.find({ userId }).lean();
  const tx = await Tx.find({ userId }).sort({ createdAt: -1 }).limit(50).lean();
  res.json({ user, accounts: accts, transactions: tx });
});

// ADMIN: ADD TRANSACTION (credit/debit)
app.post('/api/admin/tx', auth('admin'), async (req, res) => {
  try {
    const { userId, currency, type, amount, desc } = req.body || {};
    if (!userId || !currency || !type || amount == null) {
      return res.status(400).json({ message: 'Missing fields' });
    }
    const val = Number(String(amount).replace(/,/g, ''));
    if (Number.isNaN(val) || val <= 0) return res.status(400).json({ message: 'Invalid amount' });

    const acct = await Account.findOne({ userId, currency });
    if (!acct) return res.status(404).json({ message: 'Account not found' });

    let newBal = acct.balance;
    if (type === 'credit') newBal += val;
    else if (type === 'debit') newBal -= val;
    else return res.status(400).json({ message: 'Invalid type' });

    acct.balance = newBal;
    await acct.save();

    const tx = await Tx.create({ userId, currency, type, amount: val, desc });
    return res.json({ ok: true, tx });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: 'Server error' });
  }
});

// ----------- KYC (UploadThing URLs) -----------

// Client sends UploadThing URLs + basic meta. Stored as 'pending' for admin review.
app.post('/api/kyc/attach', async (req, res) => {
  const { regId, userId, fullName, email, docType, docFrontUrl, docBackUrl, selfieUrl } = req.body || {};
  if (!(regId || userId)) return res.status(400).json({ message: 'Missing regId or userId' });

  const k = await KYC.create({
    regId, userId, fullName, email, docType, docFrontUrl, docBackUrl, selfieUrl, status: 'pending'
  });
  res.json({ ok: true, kycId: k._id.toString() });
});

// List pending for admin
app.get('/api/admin/kyc/pending', auth('admin'), async (_req, res) => {
  const list = await KYC.find({ status: 'pending' }).sort({ createdAt: 1 }).lean();
  res.json(list);
});

// Admin decision
app.post('/api/admin/kyc/:kycId/decision', auth('admin'), async (req, res) => {
  const { approve, notes } = req.body || {};
  const k = await KYC.findById(req.params.kycId);
  if (!k) return res.status(404).send('Not found');

  k.status = approve ? 'approved' : 'rejected';
  k.notes = notes || '';
  k.decidedAt = new Date();
  await k.save();

  res.json({ ok: true });
});

// ----------- START -----------
app.listen(PORT, () => {
  console.log(`🚀 Server listening on :${PORT}`);
});
