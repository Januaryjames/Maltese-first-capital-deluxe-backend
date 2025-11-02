// server.js — Maltese First Capital (Simplified API)
// Focus: auth, admin upsert, client overview, email-only onboarding
// No GridFS, no Helmet, minimal deps; designed for Render.

// ──────────────────────────────────────────────────────────────────────────────
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');

const {
  PORT = 8080,
  NODE_ENV = 'production',
  MONGODB_URI,
  JWT_SECRET = 'change_me',
  DEV_SEED_KEY,
  // CORS (comma-separated)
  CORS_ORIGIN = 'https://maltesefirst.com,https://www.maltesefirst.com',
  // SMTP (optional but recommended)
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
  NOTIFY_FROM = 'Maltese First <no-reply@maltesefirst.com>',
  NOTIFY_TO = 'hello@maltesefirst.com'
} = process.env;

if (!MONGODB_URI) {
  console.error('MONGODB_URI is required'); process.exit(1);
}

// ──────────────────────────────────────────────────────────────────────────────
// Mailer (optional — onboarding/email-only uses this)
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
  if (!mailer) return { ok:false, delivered:false, reason:'mailer_not_configured' };
  const info = await mailer.sendMail({
    from: NOTIFY_FROM,
    to: NOTIFY_TO,
    subject, html,
    attachments
  });
  return { ok:true, delivered:true, messageId: info.messageId, attachments: attachments.length };
}

// ──────────────────────────────────────────────────────────────────────────────
// App + CORS
const app = express();
app.set('trust proxy', 1);

const ALLOWED = CORS_ORIGIN.split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => (!origin || ALLOWED.includes(origin)) ? cb(null, true) : cb(new Error('Not allowed by CORS')),
  credentials: false,
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','x-seed-key']
}));
app.options('*', cors());

app.use(express.json({ limit:'4mb' }));
app.use(express.urlencoded({ extended:true, limit:'4mb' }));

// Multer (in-memory) for email-only attachments
const uploadAny = multer({ storage: multer.memoryStorage(), limits:{ fileSize: 16 * 1024 * 1024 } });

// ──────────────────────────────────────────────────────────────────────────────
// Mongo + Models
(async () => { await mongoose.connect(MONGODB_URI, { maxPoolSize: 20 }); console.log('Mongo connected'); })()
.catch(e => { console.error('Mongo connect failed:', e); process.exit(1); });

const User = mongoose.model('User', new mongoose.Schema({
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

const Account = mongoose.model('Account', new mongoose.Schema({
  accountNo: { type:String, unique:true, index:true },   // 8-digit
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index:true },
  holderName: { type:String, trim:true },                // Company / Account Holder
  status: { type:String, enum:['not_activated','active','suspended'], default:'not_activated', index:true },
  currency: { type:String, default:'USD' },
  balance: { type:Number, default:0 },
  lines: [TxnSchema]
},{timestamps:true}));

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
function makeToken(u){ return jwt.sign({ sub:u.id, role:u.role, name:u.name }, JWT_SECRET, { expiresIn:'12h' }); }
function authRequired(role){
  return (req,res,next)=>{
    const hdr=req.headers.authorization||''; const t=hdr.startsWith('Bearer ')?hdr.slice(7):null;
    if(!t) return res.status(401).json({error:'Missing token'});
    try{ const p=jwt.verify(t, JWT_SECRET); if(role && p.role!==role) return res.status(403).json({error:'Forbidden'}); req.user=p; next(); }
    catch{ return res.status(401).json({error:'Invalid token'}); }
  };
}
async function genAccountNoUnique() {
  for (let i=0;i<20;i++){
    const n = String(Math.floor(10_000_000 + Math.random()*90_000_000));
    if (!(await Account.exists({ accountNo:n }))) return n;
  }
  throw new Error('Could not generate unique account number');
}

// ──────────────────────────────────────────────────────────────────────────────
// Health
app.get('/api/health', (_req,res)=> res.json({ ok:true, env:NODE_ENV, version:'simple-1.0.0', uptime:process.uptime() }));

// ──────────────────────────────────────────────────────────────────────────────
// Auth (client + admin)
app.post('/api/auth/login', async (req,res)=>{
  const { email, password } = req.body || {};
  const u = await User.findOne({ email:(email||'').toLowerCase(), role:'client' });
  if(!u) return res.status(400).json({error:'Invalid credentials'});
  const ok = await bcrypt.compare(password||'', u.passwordHash);
  if(!ok) return res.status(400).json({error:'Invalid credentials'});
  res.json({ token:makeToken(u), user:{ email:u.email, name:u.name, role:u.role } });
});
app.post('/api/admin/login', async (req,res)=>{
  const { email, password } = req.body || {};
  const u = await User.findOne({ email:(email||'').toLowerCase(), role:'admin' });
  if(!u) return res.status(400).json({error:'Invalid credentials'});
  const ok = await bcrypt.compare(password||'', u.passwordHash);
  if(!ok) return res.status(400).json({error:'Invalid credentials'});
  res.json({ token:makeToken(u), user:{ email:u.email, name:u.name, role:u.role } });
});
app.get('/api/auth/me', authRequired(), async (req,res)=>{
  const u = await User.findById(req.user.sub).select('email name role createdAt');
  if(!u) return res.status(404).json({error:'Not found'});
  res.json({ user:u });
});

// ──────────────────────────────────────────────────────────────────────────────
// Admin bootstrap (seed key)
app.post('/api/admin/bootstrap', async (req,res)=>{
  const key = req.headers['x-seed-key'];
  if (!DEV_SEED_KEY || key !== DEV_SEED_KEY) return res.status(403).json({ error:'Forbidden' });
  const { email, password, name='Administrator' } = req.body || {};
  if (!email || !password) return res.status(400).json({ error:'email and password required' });
  const exists = await User.findOne({ email:email.toLowerCase(), role:'admin' });
  if (exists) return res.json({ ok:true, already:true });
  const passwordHash = await bcrypt.hash(password, 10);
  await User.create({ email:email.toLowerCase(), passwordHash, role:'admin', name });
  res.json({ ok:true });
});

// Admin: upsert client + create account (easiest path)
app.post('/api/admin/upsert-client', async (req,res)=>{
  const key = req.headers['x-seed-key'];
  if (!DEV_SEED_KEY || key !== DEV_SEED_KEY) return res.status(403).json({ error:'Forbidden' });

  const {
    email, password, name,
    companyName,       // will be Account holderName
    createAccount = true,
    status = 'active', currency = 'USD',
    amount = 0,        // opening balance (credit)
    ts                 // optional timestamp for the credit
  } = req.body || {};

  if (!email || !password || !name || !companyName) {
    return res.status(400).json({ error:'email, password, name, companyName required' });
  }

  // user
  let user = await User.findOne({ email: email.toLowerCase() });
  if (!user) {
    user = await User.create({
      email: email.toLowerCase(),
      name,
      role: 'client',
      passwordHash: await bcrypt.hash(password, 10),
    });
  } else {
    // update name/password if provided
    const patch = {};
    if (name) patch.name = name;
    if (password) patch.passwordHash = await bcrypt.hash(password, 10);
    if (Object.keys(patch).length) { Object.assign(user, patch); await user.save(); }
  }

  let account = null;
  if (createAccount) {
    account = await Account.findOne({ owner: user._id });
    if (!account) {
      account = await Account.create({
        accountNo: await genAccountNoUnique(),
        owner: user._id,
        holderName: companyName,
        status, currency,
        balance: 0,
        lines: []
      });
    }
    // ensure holder & status
    account.holderName = companyName;
    account.status = status;
    account.currency = currency;

    // opening credit if amount > 0 and not already present
    if (amount > 0 && !account.lines.some(l => l.meta && l.meta.kind === 'opening')) {
      const when = ts ? new Date(ts) : new Date();
      account.lines.push({
        ts: when, type: 'credit', amount, currency,
        description: 'Opening Credit',
        meta: { kind: 'opening', source: 'admin-upsert' }
      });
      account.balance = (account.balance || 0) + Number(amount);
    }
    await account.save();
  }

  res.json({
    ok: true,
    user: { email: user.email, name: user.name },
    account: account ? {
      accountNo: account.accountNo,
      holderName: account.holderName,
      status: account.status,
      currency: account.currency,
      balance: account.balance
    } : null
  });
});

// Admin: light setters (company holder / user display name)
app.post('/api/admin/set-user-name', async (req,res)=>{
  const key = req.headers['x-seed-key'];
  if (!DEV_SEED_KEY || key !== DEV_SEED_KEY) return res.status(403).json({ error:'Forbidden' });
  const { email, name } = req.body || {};
  if (!email || !name) return res.status(400).json({ error:'email and name required' });
  const u = await User.findOneAndUpdate({ email: email.toLowerCase() }, { $set:{ name } }, { new:true }).select('email name');
  if (!u) return res.status(404).json({ error:'User not found' });
  res.json({ ok:true, user:u });
});

app.post('/api/admin/set-account-holder', async (req,res)=>{
  const key = req.headers['x-seed-key'];
  if (!DEV_SEED_KEY || key !== DEV_SEED_KEY) return res.status(403).json({ error:'Forbidden' });
  const { email, holderName } = req.body || {};
  if (!email || !holderName) return res.status(400).json({ error:'email and holderName required' });
  const u = await User.findOne({ email: email.toLowerCase() }).select('_id');
  if (!u) return res.status(404).json({ error:'User not found' });
  const acct = await Account.findOneAndUpdate({ owner:u._id }, { $set:{ holderName } }, { new:true })
               .select('accountNo holderName');
  if (!acct) return res.status(404).json({ error:'Account not found' });
  res.json({ ok:true, account:acct });
});

// ──────────────────────────────────────────────────────────────────────────────
// Client: overview (JWT)
app.get('/api/client/overview', authRequired('client'), async (req,res)=>{
  const accounts = await Account.find({ owner: req.user.sub })
                    .select('accountNo holderName status currency balance lines createdAt updatedAt')
                    .sort({ createdAt: -1 });
  res.json({ accounts });
});

// ──────────────────────────────────────────────────────────────────────────────
// Onboarding — Email Only (files become attachments)
app.post('/api/onboarding/email-only', uploadAny.any(), async (req,res)=>{
  try{
    const b = req.body || {};
    const fields = Object.entries(b)
        .map(([k,v]) => `<tr><td style="padding:6px 10px;border-bottom:1px solid #eee;"><b>${k}</b></td><td style="padding:6px 10px;border-bottom:1px solid #eee;">${String(v).replace(/[<>&]/g, s => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[s]))}</td></tr>`)
        .join('');
    const html = `
      <div style="font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif">
        <h2>New Account Application</h2>
        <table style="border-collapse:collapse;border:1px solid #eee">${fields}</table>
        <p style="color:#666">Attachments: ${ (req.files||[]).length }</p>
      </div>`;

    const attachments = (req.files||[]).map(f => ({
      filename: f.originalname,
      content: f.buffer,
      contentType: f.mimetype
    }));

    const result = await sendMail('New Account Application (Email Only)', html, attachments);
    if (!result.ok) return res.status(500).json({ ok:false, error:'MAIL_FAILED' });
    res.json(result);
  }catch(e){
    console.error('email-only error:', e);
    res.status(500).json({ error:'Server error' });
  }
});

// Compatibility alias: accept multiparts and forward to email flow
app.post('/api/onboarding/submit', uploadAny.any(), async (req,res)=> {
  // reuse handler
  req.url = '/api/onboarding/email-only';
  app._router.handle(req,res,()=>{});
});

// ──────────────────────────────────────────────────────────────────────────────
// Boot
const server = app.listen(PORT, ()=> console.log(`API listening on :${PORT}`));
process.on('SIGTERM', ()=> server.close(()=>process.exit(0)));
process.on('SIGINT',  ()=> server.close(()=>process.exit(0)));
