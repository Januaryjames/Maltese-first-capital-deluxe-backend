// server.js — Maltese First Capital API (Mongo + GridFS + JWT + Turnstile + Contact)
// Drop-in: CORS for multiple origins, 16MB/file, /api/contact, invisible Turnstile on public inputs.

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { randomUUID } = require('crypto');
const mongoose = require('mongoose');
const { MongoClient, GridFSBucket } = require('mongodb');
const cors = require('cors');

const {
  PORT = 8080,
  NODE_ENV = 'production',
  MONGODB_URI,
  JWT_SECRET = 'change_me',
  CORS_ORIGIN = 'https://maltesefirst.com',
  TURNSTILE_SECRET,
  DEV_SEED_KEY
} = process.env;

if (!MONGODB_URI) throw new Error('MONGODB_URI missing');
if (!TURNSTILE_SECRET) console.warn('WARNING: TURNSTILE_SECRET is not set');

const app = express();
app.set('trust proxy', 1);

// ---- CORS for multiple origins (apex + www supported) ----
const ALLOWED = CORS_ORIGIN.split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // allow non-browser tools
    if (ALLOWED.includes(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use('/api/', rateLimit({ windowMs: 10 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false }));

// ---- Mongo + GridFS ----
let gfsBucket = null, nativeClient = null;
async function connectMongo(uri) {
  await mongoose.connect(uri, { maxPoolSize: 20 });
  nativeClient = new MongoClient(uri); await nativeClient.connect();
  const dbName = mongoose.connection.client.s.options.dbName || mongoose.connection.name;
  gfsBucket = new GridFSBucket(nativeClient.db(dbName), { bucketName: 'uploads' });
  console.log('Mongo connected:', dbName);
}
function getGridFSBucket(){ if(!gfsBucket) throw new Error('GridFS not ready'); return gfsBucket; }
async function shutdown(){ await mongoose.disconnect().catch(()=>{}); if(nativeClient) await nativeClient.close().catch(()=>{}); }

// ---- Schemas ----
const User = mongoose.model('User', new mongoose.Schema({
  email: { type:String, unique:true, index:true, required:true, lowercase:true, trim:true },
  passwordHash: { type:String, required:true },
  role: { type:String, enum:['client','admin'], default:'client', index:true },
  name: { type:String, trim:true }
},{timestamps:true}));

const FileMetaSchema = new mongoose.Schema({
  gridfsId: mongoose.Schema.Types.ObjectId, filename:String, mime:String, size:Number
},{_id:false});

const Application = mongoose.model('Application', new mongoose.Schema({
  applicationId:{ type:String, unique:true, index:true },
  status:{ type:String, enum:['received','review','approved','rejected'], default:'received' },
  fields:{ fullName:String, email:String, phone:String, companyName:String, country:String },
  files:{ passport:[FileMetaSchema], proofOfAddress:[FileMetaSchema], companyDocs:[FileMetaSchema], selfie:[FileMetaSchema] },
  submittedByIp:String
},{timestamps:true}));

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

// ---- Helpers ----
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
  if(!TURNSTILE_SECRET) return false;
  try{
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify',{
      method:'POST',
      headers:{'content-type':'application/x-www-form-urlencoded'},
      body:`secret=${encodeURIComponent(TURNSTILE_SECRET)}&response=${encodeURIComponent(token||'')}&remoteip=${encodeURIComponent(ip||'')}`
    });
    const data = await resp.json();
    return !!data.success;
  }catch{ return false; }
}
async function requireTurnstile(req,res,next){
  const ok = await verifyTurnstile(req.body?.['cf_turnstile_response'], req.ip);
  if(!ok) return res.status(400).json({error:'Captcha verification failed'});
  next();
}

// ---- Multer (16 MB/file) ----
const upload = multer({ storage: multer.memoryStorage(), limits:{ fileSize: 16*1024*1024 } });

// ---- Routes ----
app.get('/api/health', (_req,res)=> res.json({ ok:true, env:NODE_ENV, version:'1.5.0', uptime:process.uptime() }));

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

// Reset
app.post('/api/auth/request-reset', async (req,res)=>{
  const {email}=req.body||{}; if(!email) return res.status(400).json({error:'Email required'});
  const token = randomUUID().replace(/-/g,'');
  const expires = new Date(Date.now()+30*60*1000);
  await ResetToken.create({ email:email.toLowerCase(), token, expiresAt:expires });
  res.status(204).end();
});
app.post('/api/auth/reset', async (req,res)=>{
  const {token,newPassword}=req.body||{};
  if(!token||!newPassword) return res.status(400).json({error:'Token and newPassword required'});
  const rt = await ResetToken.findOne({ token, used:false, expiresAt:{ $gt:new Date() } });
  if(!rt) return res.status(400).json({error:'Invalid or expired token'});
  const u = await User.findOne({ email:rt.email }); if(!u) return res.status(400).json({error:'No account for token'});
  u.passwordHash = await bcrypt.hash(newPassword,10); await u.save(); rt.used=true; await rt.save();
  res.status(204).end();
});

// Account Open (KYC + files + Turnstile)
app.post('/api/onboarding/submit',
  upload.fields([{name:'passport',maxCount:1},{name:'proofOfAddress',maxCount:1},{name:'companyDocs',maxCount:20},{name:'selfie',maxCount:1}]),
  requireTurnstile,
  async (req,res)=>{
    const gfs=getGridFSBucket();
    async function save(field){
      const arr=req.files?.[field]||[]; const out=[];
      for(const f of arr){
        const filename=`${Date.now()}_${f.originalname}`;
        const us=gfs.openUploadStream(filename,{contentType:f.mimetype}); us.end(f.buffer);
        const fin=await new Promise((resolve,reject)=>{ us.on('finish',resolve); us.on('error',reject); });
        out.push({ gridfsId:fin._id, filename, mime:f.mimetype, size:f.size });
      }
      return out;
    }
    const [passport,proofOfAddress,companyDocs,selfie]=await Promise.all([save('passport'),save('proofOfAddress'),save('companyDocs'),save('selfie')]);
    const { fullName,email,phone,companyName,country }=req.body;
    const applicationId = randomUUID();
    const doc = await Application.create({ applicationId, status:'received',
      fields:{fullName,email,phone,companyName,country},
      files:{passport,proofOfAddress,companyDocs,selfie},
      submittedByIp:req.ip
    });
    res.json({ applicationId:doc.applicationId, status:doc.status, receivedAt:doc.createdAt });
  }
);

// Contact (Turnstile, no email send; stored in DB)
app.post('/api/contact', requireTurnstile, express.urlencoded({extended:true}), async (req,res)=>{
  const { name='', email='', phone='', subject='', message='' } = req.body||{};
  await ContactMessage.create({
    name, email, phone, subject, message,
    meta: { userAgent: req.headers['user-agent']||'', ip: req.ip }
  });
  res.status(204).end();
});

// Admin
app.get('/api/admin/applications', authRequired('admin'), async (_req,res)=>{
  const items = await Application.find().sort({ createdAt:-1 }).limit(100);
  res.json({ items });
});
app.post('/api/admin/applications/:id/decision', authRequired('admin'), async (_req,res)=> res.status(204).end());

// Seed demo users once
app.post('/api/dev/seed-admin', async (req,res)=>{
  const key=req.headers['x-seed-key']; if(!DEV_SEED_KEY||key!==DEV_SEED_KEY) return res.status(403).json({error:'Forbidden'});
  async function ensure(email,password,role,name){ let u=await User.findOne({email}); if(!u) u=await User.create({ email, passwordHash:await bcrypt.hash(password,10), role, name }); return u; }
  const client=await ensure('client@example.com','client123','client','Demo Client');
  const admin =await ensure('admin@example.com','admin123','admin','Demo Admin');
  res.json({ ok:true, client:client.email, admin:admin.email });
});

// ---- Boot ----
(async()=>{
  try{
    await connectMongo(MONGODB_URI);
    app.listen(PORT, ()=>console.log(`API listening on :${PORT}`));
    const stop=async()=>{ await shutdown(); process.exit(0); };
    process.on('SIGINT', stop); process.on('SIGTERM', stop);
  }catch(e){ console.error('Boot error:', e); process.exit(1); }
})();
