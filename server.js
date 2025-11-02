// server.js — MFC "easy" API (v1.0)
// Minimal endpoints: health, admin bootstrap/login, client login,
// upsert-client (create/update user + account), client overview.
// Deps: express, mongoose, bcryptjs, jsonwebtoken

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// ─────────────────────────────────────────────────────────── Env
const {
  PORT = 8080,
  NODE_ENV = 'production',
  JWT_SECRET = 'change_me',
  DEV_SEED_KEY = '',
  CORS_ORIGIN = 'https://maltesefirst.com,https://www.maltesefirst.com',
} = process.env;

const MONGODB_URI = process.env.MONGODB_URI || process.env.MONGO_URI;
if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI (or MONGO_URI) is required');
  process.exit(1);
}

// ─────────────────────────────────────────────────────────── App
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));

// Simple CORS (no external package)
const ALLOWED = CORS_ORIGIN.split(',').map(s => s.trim()).filter(Boolean);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || ALLOWED.includes(origin)) {
    if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Requested-With, x-seed-key'
  );
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, PUT, PATCH, DELETE, OPTIONS'
  );
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

// ─────────────────────────────────────────────────────────── DB
let mongoReady = false;
mongoose.set('strictQuery', true);
mongoose
  .connect(MONGODB_URI, { maxPoolSize: 15 })
  .then(() => { mongoReady = true; console.log('✅ Mongo connected'); })
  .catch(err => { console.error('❌ Mongo error', err); process.exit(1); });

// ─────────────────────────────────────────────────────────── Models
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, index: true, lowercase: true, trim: true, required: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['client','admin'], default: 'client', index: true },
  name: { type: String, trim: true }
}, { timestamps: true });

const txnSchema = new mongoose.Schema({
  ts: { type: Date, default: () => new Date() },
  type: { type: String, enum: ['credit','debit'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  description: String,
  meta: Object
}, { _id: false });

const accountSchema = new mongoose.Schema({
  accountNo: { type: String, unique: true, index: true },        // 8-digit string
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  companyName: { type: String, trim: true },                      // business holder label
  status: { type: String, enum: ['not_activated','active','suspended'], default: 'not_activated', index: true },
  currency: { type: String, default: 'USD' },
  balance: { type: Number, default: 0 },
  lines: [txnSchema]
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Account = mongoose.model('Account', accountSchema);

// ─────────────────────────────────────────────────────────── Helpers
const makeToken = (u) =>
  jwt.sign({ sub: u.id, role: u.role, name: u.name }, JWT_SECRET, { expiresIn: '12h' });

const authRequired = (role) => (req,res,next) => {
  const hdr = req.headers.authorization || '';
  const tok = hdr.startsWith('Bearer ') ? hdr.slice(7) : '';
  if (!tok) return res.status(401).json({ error: 'Missing token' });
  try {
    const p = jwt.verify(tok, JWT_SECRET);
    if (role && p.role !== role) return res.status(403).json({ error: 'Forbidden' });
    req.user = p; next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const genAccountNo = () => String(Math.floor(10_000_000 + Math.random()*90_000_000));

// ─────────────────────────────────────────────────────────── Routes
app.get('/api/health', (_req,res) =>
  res.json({ ok: true, env: NODE_ENV, version: 'easy-1.0', mongo: mongoReady })
);

// Admin bootstrap (create first admin). Protected by x-seed-key = DEV_SEED_KEY
app.post('/api/admin/bootstrap', async (req, res) => {
  try {
    if (!mongoReady) return res.status(500).json({ error: 'Mongo not configured' });
    const key = req.headers['x-seed-key'] || '';
    if (!DEV_SEED_KEY || key !== DEV_SEED_KEY) return res.status(403).json({ error: 'Forbidden' });

    const { email, password, name='Administrator' } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const exists = await User.findOne({ email: email.toLowerCase(), role: 'admin' });
    if (exists) return res.status(409).json({ error: 'Admin already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    await User.create({ email: email.toLowerCase(), name, role: 'admin', passwordHash });
    res.json({ ok: true });
  } catch (e) {
    console.error('bootstrap error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin login
app.post('/api/admin/login', async (req,res)=>{
  const { email, password } = req.body || {};
  const u = await User.findOne({ email: (email||'').toLowerCase(), role: 'admin' });
  if (!u) return res.status(400).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password || '', u.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
  res.json({ token: makeToken(u), user: { id: u.id, name: u.name, role: u.role } });
});

// Client login
app.post('/api/auth/login', async (req,res)=>{
  const { email, password } = req.body || {};
  const u = await User.findOne({ email: (email||'').toLowerCase(), role: 'client' });
  if (!u) return res.status(400).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password || '', u.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
  res.json({ token: makeToken(u), user: { id: u.id, name: u.name, role: u.role } });
});

app.get('/api/auth/me', authRequired(), async (req,res)=>{
  const u = await User.findById(req.user.sub).select('email name role createdAt');
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json({ user: { email: u.email, name: u.name, role: u.role, createdAt: u.createdAt } });
});

// Upsert client (create/update user + create/attach active account)
// Protected by x-seed-key = DEV_SEED_KEY
app.post('/api/admin/upsert-client', async (req, res) => {
  try {
    const key = req.headers['x-seed-key'] || '';
    if (!DEV_SEED_KEY || key !== DEV_SEED_KEY) return res.status(403).json({ error:'Forbidden' });
    if (!mongoReady) return res.status(500).json({ error:'Mongo not configured' });

    const {
      email, password, name,
      companyName = '',
      createAccount = true,
      status = 'active',
      currency = 'USD',
      amount = 0,
      ts
    } = req.body || {};

    if (!email || !password) return res.status(400).json({ error:'email and password required' });

    let user = await User.findOne({ email: email.toLowerCase(), role: 'client' });
    if (!user) {
      user = await User.create({
        email: email.toLowerCase(),
        name: name || email.split('@')[0],
        role: 'client',
        passwordHash: await bcrypt.hash(password, 10)
      });
    } else {
      if (name) user.name = name;
      user.passwordHash = await bcrypt.hash(password, 10);
      await user.save();
    }

    let acct = null;
    if (createAccount) {
      acct = await Account.findOne({ owner: user._id, companyName });
      if (!acct) {
        acct = await Account.create({
          accountNo: genAccountNo(),
          owner: user._id,
          companyName,
          status,
          currency,
          balance: amount,
          lines: amount > 0 ? [{
            ts: ts ? new Date(ts) : new Date(),
            type: 'credit', amount, currency, description: 'Initial', meta: { source: 'admin-upsert' }
          }] : []
        });
      } else {
        acct.status = status;
        acct.currency = currency || acct.currency;
        await acct.save();
      }
    }

    res.json({
      ok: true,
      user: { email: user.email, name: user.name },
      account: acct ? {
        accountNo: acct.accountNo, status: acct.status, currency: acct.currency,
        balance: acct.balance, companyName: acct.companyName
      } : null
    });
  } catch (e) {
    console.error('upsert-client error:', e);
    res.status(500).json({ error:'Server error' });
  }
});

// Client overview
app.get('/api/client/overview', authRequired('client'), async (req,res)=>{
  const accounts = await Account.find({ owner: req.user.sub }).select('-__v');
  res.json({ accounts });
});

// 404
app.use((_req,res) => res.status(404).json({ error: 'Not found' }));

// ─────────────────────────────────────────────────────────── Boot
app.listen(PORT, () => console.log(`🚀 API listening on :${PORT}`));
