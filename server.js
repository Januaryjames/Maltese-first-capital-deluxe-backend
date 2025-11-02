// server.js — Maltese First Capital API (v2.0)
// Fixes: 404 on /api/public/account-open (adds GET), robust envs, dual field names,
// CORS+preflight, optional Turnstile, GridFS file ingest, admin bootstrap, health.

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
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

/* ─────────────── ENV ─────────────── */
const {
  PORT = 8080,
  NODE_ENV = 'production',
  // accept either name
  MONGODB_URI = process.env.MONGO_URI,
  JWT_SECRET = process.env.JWT_SECRET || 'change_me',
  // accept either name for origins
  CORS_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://maltesefirst.com,https://www.maltesefirst.com',
  TURNSTILE_SECRET,
  BYPASS_CAPTCHA = '0',
  DEV_SEED_KEY,
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
  NOTIFY_FROM = process.env.NOTIFY_FROM || 'Maltese First <no-reply@maltesefirst.com>',
  NOTIFY_TO = process.env.NOTIFY_TO || process.env.ADMIN_NOTIFY || '',
  CLAMAV_HOST, CLAMAV_PORT = 3310
} = process.env;

if (!MONGODB_URI) throw new Error('MONGODB_URI (or MONGO_URI) is required');

/* ─────────────── Mailer (optional) ─────────────── */
let mailer = null;
if (SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS) {
  mailer = nodemailer.createTransport({
    host: SMTP_HOST, port: Number(SMTP_PORT),
    secure: Number(SMTP_PORT) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
}
async function sendNotify(subject, html) {
  if (!mailer || !NOTIFY_TO) return;
  try { await mailer.sendMail({ from: NOTIFY_FROM, to: NOTIFY_TO, subject, html }); }
  catch (e) { console.warn('notify mail failed:', e.message); }
}

/* ─────────────── App ─────────────── */
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

// Helmet (CSP off as requested)
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: 'cross-origin' } }));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use('/api/', rateLimit({ windowMs: 10 * 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false }));

/* ─────────────── Mongo + GridFS ─────────────── */
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

/* ─────────────── Schemas ─────────────── */
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

/* ─────────────── Helpers ─────────────── */
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

/* Optional ClamAV (skips if not configured) */
async function clamScan(buffer){
  if(!CLAMAV_HOST) return { status:'skipped', engine:'clamav', reason:'not_configured' };
  return new Promise((resolve) => {
    const s = net.createConnection(CLAMAV_PORT, CLAMAV_HOST, () => {
      s.write("zINSTREAM\0");
      const len = Buffer.alloc(4); len.writeUInt32BE(buffer.length, 0);
      s.write(len); s.write(buffer);
      s.write(Buffer.alloc(4)); // 0 terminator
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

/* Uploads */
const upload = multer({ storage: multer.memoryStorage(), limits:{ fileSize: 16*1024*1024 } });

/* ─────────────── Routes ─────────────── */
app.get('/api/health', (_req,res)=> res.json({ ok:true, env:NODE_ENV, version:'2.0', uptime:process.uptime() }));

/* NEW: public probe so the frontend (and any SEO/ping) won’t 404 */
app.get('/api/public/account-open', (_req,res)=> {
  res.json({ ok:true, route:'/api/public/account-open', tip:'POST your KYC to /api/onboarding/submit or /api/onboarding/account-open' });
});

/* Auth */
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

/* Password reset minimal flow */
app.post('/api/auth/request-reset', async (req,res)=>{
  const {email}=req.body||{}; if(!email) return res.status(400).json({error:'Email required'});
  const token = randomUUID().replace(/-/g,''); const expires = new Date(Date.now()+30*60*1000);
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

/* Admin bootstrap (guarded) */
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
  } catch (e) { console.error('bootstrap-admin error', e); res.status(500).json({ error: 'Server error' }); }
});

/* Onboarding (KYC
