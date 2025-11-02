// server.js — Maltese First Capital API (v2.0.0)
// Adds: /api/admin/create-client and /api/onboarding/email-only
// Keeps: auth, admin bootstrap, contact, client overview, GridFS, rate limits, CORS preflight.
// CSP disabled (Helmet), Turnstile verify with BYPASS option.

'use strict';

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const nodemailer = require('nodemailer');
const { randomUUID, createHash } = require('crypto');
const net = require('net');
const mongoose = require('mongoose');
const { MongoClient, GridFSBucket } = require('mongodb');

const {
  PORT = 8080,
  NODE_ENV = 'production',
  MONGODB_URI,
  JWT_SECRET = 'change_me',
  CORS_ORIGIN = 'https://maltesefirst.com,https://www.maltesefirst.com',
  TURNSTILE_SECRET,
  BYPASS_CAPTCHA = '0',
  DEV_SEED_KEY,
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
  NOTIFY_FROM = 'Maltese First <no-reply@maltesefirst.com>',
  NOTIFY_TO = '',
  CLAMAV_HOST, CLAMAV_PORT = 3310
} = process.env;

if (!MONGODB_URI) throw new Error('MONGODB_URI missing');

// ───────────────────────── Mailer (optional)
let mailer = null;
if (SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS) {
  mailer = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: Number(SMTP_PORT) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
}
async function sendNotify(subject, html, attachments = []) {
  if (!mailer || !NOTIFY_TO) return { ok: false, delivered: false, reason: 'mailer_not_configured' };
  const info = await mailer.sendMail({
    from: NOTIFY_FROM,
    to: NOTIFY_TO,
    subject,
    html,
    attachments
  });
  return { ok: true, delivered: !!info.messageId, id: info.messageId };
}

// ───────────────────────── App
const app = express();
app.set('trust proxy', 1);

// CORS (exact origins only) + preflight
const ALLOWED = CORS_ORIGIN.split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => (!origin || ALLOWED.includes(origin)) ? cb(null, true) : cb(new Error('Not allowed by CORS')),
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Requested-With']
}));
app.options('*', cors());

// Helmet — CSP disabled per rollout
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use('/api/', rateLimit({ windowMs: 10*60*1000, max: 120, standardHeaders: true, legacyHeaders: false }));

// ───────────────────────── Mongo + GridFS
let gfsBucket = null, nativeClient = null;
async function connectMongo(uri) {
  await mongoose.connect(uri, { maxPoolSize: 20 });
  nativeClient = new MongoClient(uri); await nativeClient.connect();
  const dbName = mongoose.connection.name;
  gfsBucket = new GridFSBucket(nativeClient.db(dbName), { bucketName: 'uploads' });
  console.log('Mongo connected:', dbName);
}
function getGridFSBucket(){ if (!gfsBucket) throw new Error('GridFS not ready'); return gfsBucket; }
async function shutdown(){ await mongoose.disconnect().catch(()=>{}); if (nativeClient) await nativeClient.close().catch(()=>{}); }

// ───────────────────────── Schemas
const User = mongoose.model('User', new mongoose.Schema({
  email: { type:String, unique:true, index:true, required:true, lowercase:true, trim:true },
  passwordHash: { type:String, required:true },
  role: { type:String, enum:['client','admin'], default:'client', index:true },
  name: { type:String, trim:true }
},{timestamps:true}));

const FileMetaSchema = new mongoose.Schema({
  gridfsId: mongoose.Schema.Types.ObjectId,
  filename: String, mime: String, size: Number,
  sha256: String,
  av: { status: String, engine: String, reason: String }
},{_id:false});

const Application = mongoose.model('Application', new mongoose.Schema({
  applicationId:{ type:String, unique:true, index:true },
  status:{ type:String, enum:['received','review','approved','rejected'], default:'received' },
  fields:{
    fullName:String, email:String, phone:String,
    companyName:String, country:String,
    address:String, currency:String,
    accountType:String, commercialRegistration:String,
    sourceOfFunds:String, notes:String,
    extra: mongoose.Schema.Types.Mixed
  },
  files:{ passport:[FileMetaSchema], proofOfAddress:[FileMetaSchema], companyDocs:[FileMetaSchema], selfie:[FileMetaSchema] },
  submittedByIp:String
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
  accountNo: { type: String, unique: true, index: true },   // 8-digit
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  status: { type: String, enum: ['not_activated','active','suspended'], default: 'not_activated', index: true },
  currency: { type: String, default: 'USD' },
  balance: { type: Number, default: 0 },
  lines: [TxnSchema]
}, { timestamps: true }));

const ResetToken = mongoose.model('ResetToken', new mongoose.Schema({
  email:{ type:String, index:true, required:true, lowercase:true, trim:true },
  token:{ type:String, required:true, unique:true },
  used:{ type:Boolean, default:false },
  expiresAt:{ type:Date, index:true }
},{timestamps:true}));

const ContactMessage = mongoose.model('ContactMessage', new mongoose.Schema({
  name:String, email:String, phone:String, subject:String, message:String,
  meta:{ userAgent:String, ip:String }
},{timestamps:true}));

// ───────────────────────── Helpers
function makeToken(u){ return jwt.sign({ sub:u.id, role:u.role, name:u.name }, JWT_SECRET, { expiresIn:'1h' }); }
function authRequired(role){
  return (req,res,next)=>{
    const hdr=req.headers.authorization||''; const t=hdr.startsWith('Bearer ')?hdr.slice(7):null;
    if(!t) return res.status(401).json({error:'Missing token'});
    try{ const p=jwt.verify(t, JWT_SECRET); if(role && p.role!==role) return res.status(403).json({error:'Forbidden'}); req.user=p; next(); }
    catch{ return res.status(401).json({error:'Invalid token'}); }
  };
}
async function verifyTurnstile(token, ip){
  if (BYPASS_CAPTCHA === '1') return true;
  if (!TURNSTILE_SECRET) return true;
  try{
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method:'POST',
      headers:{'content-type':'application/x-www-form-urlencoded'},
      body:`secret=${encodeURIComponent(TURNSTILE_SECRET)}&response=${encodeURIComponent(token||'')}&remoteip=${encodeURIComponent(ip||'')}`
    });
    const d = await r.json(); 
    return !!d.success;
  }catch{ return false; }
}
function tryObjectId(str){ try { return new mongoose.Types.ObjectId(str); } catch { return null; } }
function genAccountNo(){ return String(Math.floor(10_000_000 + Math.random()*90_000_000)); }

// Optional: ClamAV stream scan (skips if not configured)
async function clamScan(buffer){
  if(!CLAMAV_HOST) return { status:'skipped', engine:'clamav', reason:'not_configured' };
  return new Promise((resolve) => {
    const s = net.createConnection(CLAMAV_PORT, CLAMAV_HOST, () => {
      s.write("zINSTREAM\0");
      s.write(Buffer.alloc(4));
      const len = Buffer.alloc(4); len.writeUInt32BE(buffer.length, 0);
      s.write(len); s.write(buffer);
      s.write(Buffer.alloc(4)); // terminator
    });
    s.setTimeout(10000);
    s.on('data', (d) => {
      const msg = d.toString();
      if (msg.includes('FOUND')) resolve({ status:'infected', engine:'clamav', reason:msg.trim() });
      else resolve({ status:'clean', engine:'clamav' });
      s.end();
    });
    s.on('error', () => resolve({ status:'skipped', engine:'clamav', reason:'socket_error' }));
    s.on('timeout', () => { s.destroy(); resolve({ status:'skipped', engine:'clamav', reason:'timeout' }); });
  });
}

// Multer (memory)
const upload = multer({ storage: multer.memoryStorage(), limits:{ fileSize: 16*1024*1024 } });

// ───────────────────────── Routes
app.get('/api/health', (_req,res)=> res.json({ ok:true, env:NODE_ENV, version:'2.0.0', uptime:process.uptime() }));

// Auth
app.post('/api/auth/login', async (req,res)=>{
  const {email,password}=req.body||{};
  const u = await User.findOne({ email:(email||'').toLowerCase(), role:'client' });
  if(!u) return res.status(400).json({error:'Invalid credentials'});
  const ok = await bcrypt.compare(password||'', u.passwordHash);
  if(!ok) return res.status(400).json({error:'Invalid credentials'});
  res.json({ token:makeToken(u), user:{ id:u.id, name:u.name, role:u.role } });
});
app.post('/api/admin/login', async (req,res)=>{
  const {email,password}=req.body||{};
  const u = await User.findOne({ email:(email||'').toLowerCase(), role:'admin' });
  if(!u) return res.status(400).json({error:'Invalid credentials'});
  const ok = await bcrypt.compare(password||'', u.passwordHash);
  if(!ok) return res.status(400).json({error:'Invalid credentials'});
  res.json({ token:makeToken(u), user:{ id:u.id, name:u.name, role:u.role } });
});
app.get('/api/auth/me', authRequired(), async (req,res)=>{
  const u = await User.findById(req.user.sub).select('email name role createdAt');
  if(!u) return res.status(404).json({error:'Not found'});
  res.json({ user: { email:u.email, name:u.name, role:u.role, createdAt:u.createdAt } });
});
app.post('/api/auth/request-reset', async (req,res)=>{
  const {email}=req.body||{}; if(!email) return res.status(400).json({error:'Email required'});
  const token = randomUUID().replace(/-/g,'');
  const expires = new Date(Date.now()+30*60*1000);
  await ResetToken.create({ email:email.toLowerCase(), token, expiresAt:expires });
  res.status(204).end();
});
app.post('/api/auth/reset', async (req,res)=>{
  const {token,newPassword}=req.body||{}; if(!token||!newPassword) return res.status(400).json({error:'Token and newPassword required'});
  const rt = await ResetToken.findOne({ token, used:false, expiresAt:{ $gt:new Date() } });
  if(!rt) return res.status(400).json({error:'Invalid or expired token'});
  const u = await User.findOne({ email:rt.email }); if(!u) return res.status(400).json({error:'No account for token'});
  u.passwordHash = await bcrypt.hash(newPassword,10); await u.save(); rt.used=true; await rt.save(); res.status(204).end();
});

// Admin bootstrap (guarded by DEV_SEED_KEY)
app.post('/api/admin/bootstrap', async (req, res) => {
  try {
    const key = req.headers['x-seed-key'];
    if (!DEV_SEED_KEY || key !== DEV_SEED_KEY) return res.status(403).json({ error: 'Forbidden' });
    const { email, password, name = 'Administrator' } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const exists = await User.findOne({ email: email.toLowerCase(), role: 'admin' });
    if (exists) return res.status(409).json({ error: 'Admin already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    await User.create({ email: email.toLowerCase(), name, role: 'admin', passwordHash });
    res.json({ ok: true });
  } catch (e) {
    console.error('bootstrap-admin error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ───────────────────────── Onboarding: Email-only (simple, reliable)
const emailOnlyUpload = upload.fields([
  { name:'docs_corporate', maxCount: 20 },
  { name:'docs_id',        maxCount:  5 },
  { name:'docs_poa',       maxCount:  5 },
  { name:'docs_sof',       maxCount: 20 },
  { name:'selfie_file',    maxCount:  2 },
  // accept legacy names too
  { name:'passport',       maxCount:  2 },
  { name:'proofOfAddress', maxCount:  5 },
  { name:'companyDocs',    maxCount: 20 },
  { name:'selfie',         maxCount:  2 }
]);

app.post('/api/onboarding/email-only', emailOnlyUpload, async (req, res) => {
  try {
    const tsToken = req.body?.['cf_turnstile_response'] || req.body?.['cf-turnstile-response'] || '';
    const ok = await verifyTurnstile(tsToken, req.ip);
    if(!ok) return res.status(400).json({error:'Captcha verification failed'});

    // Build HTML summary
    const b = req.body || {};
    const lines = (k, d='—') => `<tr><td style="padding:6px 10px;border-bottom:1px solid #eee;"><b>${k}</b></td><td style="padding:6px 10px;border-bottom:1px solid #eee;">${d}</td></tr>`;
    const html = `
      <h3>New Account Application (Email-Only)</h3>
      <table cellspacing="0" cellpadding="0" style="border-collapse:collapse;">
        ${lines('Company / Account', b.company_name || b.companyName || '—')}
        ${lines('Authorised Person', b.authorized_person || b.authorised_person || b.fullName || '—')}
        ${lines('Email', b.email || '—')}
        ${lines('Phone', b.phone || '—')}
        ${lines('Address', b.address || '—')}
        ${lines('Country', b.country || '—')}
        ${lines('Account Type', b.account_type || b.accountType || '—')}
        ${lines('Currency', b.currency || '—')}
        ${lines('Commercial Registration', b.commercial_registration || b.commercialRegistration || '—')}
        ${lines('Source of Funds', b.source_of_funds || b.sourceOfFunds || '—')}
        ${lines('Notes', (b.notes || '').substring(0, 4000))}
      </table>
      <p style="margin-top:12px;font:14px/1.4 -apple-system,Segoe UI,Roboto,sans-serif;color:#333;">
        Submitted from IP: <code>${req.ip}</code>
      </p>
    `;

    // Attach any uploaded files
    const groups = ['docs_corporate','docs_id','docs_poa','docs_sof','selfie_file','passport','proofOfAddress','companyDocs','selfie'];
    const attachments = [];
    for (const g of groups) {
      const arr = req.files?.[g] || [];
      for (const f of arr) {
        attachments.push({ filename: f.originalname, content: f.buffer, contentType: f.mimetype });
      }
    }

    const result = await sendNotify('New Account Application', html, attachments);
    if (!result.ok) return res.status(503).json({ ok:false, delivered:false, error:'MAILER_DISABLED' });

    res.json({ ok:true, delivered:result.delivered, attachments:attachments.length });
  } catch (e) {
    console.error('email-only submit error:', e);
    res.status(500).json({ error:'Server error' });
  }
});

// ───────────────────────── Contact → email
app.post('/api/contact', upload.none(), async (req,res)=>{
  const tsToken = req.body?.['cf_turnstile_response'] || req.body?.['cf-turnstile-response'] || '';
  const ok = await verifyTurnstile(tsToken, req.ip);
  if(!ok) return res.status(400).json({error:'Captcha verification failed'});

  const { name='', email='', phone='', subject='', message='' } = req.body||{};
  await ContactMessage.create({ name, email, phone, subject, message, meta:{ userAgent:req.headers['user-agent']||'', ip:req.ip } }).catch(()=>{});
  const safe = (s='').replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
  const html = `
    <h3>New Contact Message</h3>
    <p><b>Name:</b> ${safe(name)} · <b>Email:</b> ${safe(email)} · <b>Phone:</b> ${safe(phone)}</p>
    <p><b>Subject:</b> ${safe(subject)}</p>
    <pre style="white-space:pre-wrap;border:1px solid #eee;padding:10px;border-radius:8px;">${safe(message)}</pre>
  `;
  await sendNotify('New Contact Message', html).catch(()=>{});
  res.status(204).end();
});

// ───────────────────────── Admin: create client user (+ optional account)
app.post('/api/admin/create-client', authRequired('admin'), async (req, res) => {
  try {
    const { email, password, name = '', currency = 'USD', openingBalance = 0 } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const lower = String(email).toLowerCase().trim();
    const exists = await User.findOne({ email: lower });
    if (exists) return res.status(409).json({ error: 'User already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({
      email: lower,
      name: name || lower.split('@')[0],
      role: 'client',
      passwordHash
    });

    const acct = await Account.create({
      accountNo: genAccountNo(),
      owner: user._id,
      status: 'not_activated',
      currency,
      balance: Number(openingBalance) || 0,
      lines: (Number(openingBalance) > 0)
        ? [{ ts: new Date(), type:'credit', amount:Number(openingBalance), currency, description:'Opening Balance', meta:{ source:'admin-create' } }]
        : []
    });

    return res.json({
      ok: true,
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
      account: { accountNo: acct.accountNo, status: acct.status, currency: acct.currency, balance: acct.balance }
    });
  } catch (e) {
    console.error('create-client error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ───────────────────────── Admin: list, detail, file download (for GridFS flow, kept)
app.get('/api/admin/applications', authRequired('admin'), async (_req,res)=>{
  const items = await Application.find().sort({ createdAt:-1 }).limit(100);
  res.json({ items });
});
app.get('/api/admin/applications/:id', authRequired('admin'), async (req,res)=>{
  const item = await Application.findOne({ applicationId: req.params.id });
  if(!item) return res.status(404).json({error:'Not found'}); res.json({ item });
});
app.get('/api/admin/applications/:id/files/:field/:gridId', authRequired('admin'), async (req,res)=>{
  const { id, field, gridId }=req.params;
  const appDoc = await Application.findOne({ applicationId:id }); if(!appDoc) return res.status(404).json({error:'Application not found'});
  const arr=(appDoc.files && appDoc.files[field])||[]; const meta=arr.find(f=>String(f.gridfsId)===gridId);
  if(!meta) return res.status(404).json({error:'File not found'});
  const oid=tryObjectId(gridId); if(!oid) return res.status(400).json({error:'Bad file id'});
  res.setHeader('Content-Type', meta.mime || 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${meta.filename || 'file'}"`);
  getGridFSBucket().openDownloadStream(oid).on('error',()=>res.status(500).end()).pipe(res);
});

// ───────────────────────── Client overview → real accounts
app.get('/api/client/overview', authRequired('client'), async (req,res)=>{
  const accounts = await Account.find({ owner: req.user.sub }).select('-__v');
  res.json({ accounts });
});

// ───────────────────────── Dev seed account (helper)
app.post('/api/admin/dev-seed-account', async (req,res)=>{
  const key=req.headers['x-seed-key']; if(!DEV_SEED_KEY || key!==DEV_SEED_KEY) return res.status(403).json({error:'Forbidden'});
  const { email, amount=5000000, currency='USD', ts, status='not_activated' } = req.body || {};
  if(!email) return res.status(400).json({error:'email required'});

  let user = await User.findOne({ email: email.toLowerCase() });
  if (!user) {
    user = await User.create({
      email: email.toLowerCase(),
      name: email.split('@')[0],
      role: 'client',
      passwordHash: await bcrypt.hash(randomUUID().slice(0,12), 10)
    });
  }

  const accountNo = genAccountNo();
  const when = ts ? new Date(ts) : new Date();
  const acct = await Account.create({
    accountNo, owner: user._id, status, currency,
    balance: amount,
    lines: [{ ts: when, type:'credit', amount, currency, description:'Loan Credit (Pending Activation)', meta:{ source:'admin-seed' } }]
  });

  res.json({ ok:true, accountNo: acct.accountNo, user: user.email, status: acct.status });
});

// Friendly multer errors
app.use((err, _req, res, next) => {
  if (err && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'File too large (max 16MB each)' });
  }
  next(err);
});

// ───────────────────────── Boot
(async()=>{
  try {
    await connectMongo(MONGODB_URI);
    app.listen(PORT, ()=>console.log(`API :${PORT}`));
    const stop=async()=>{ await shutdown(); process.exit(0); };
    process.on('SIGINT', stop); process.on('SIGTERM', stop);
  } catch(e){ console.error('Boot error:', e); process.exit(1); }
})();
