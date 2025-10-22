import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(cors());
app.use(helmet());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 300 }));

const {
  MONGODB_URI,
  JWT_SECRET = 'CHANGE_THIS_SECRET',
  EMAIL_USER = 'hello@maltesefirst.com',
  EMAIL_PASS = '',
  ADMIN_USER = 'mfcliveadmin',
  ADMIN_PASS = 'MFC!7hP9r2qZsX8d'
} = process.env;

await mongoose.connect(MONGODB_URI || 'mongodb://127.0.0.1:27017/mfc_internal', { dbName: 'mfc_internal' });

// Models
const Account = new mongoose.Schema({ currency: String, accountNumber: String, balance: Number });
const User = mongoose.model('User', new mongoose.Schema({
  fullName: String,
  email: { type: String, unique: true },
  passwordHash: String,
  accounts: [Account]
}));
const Tx = mongoose.model('Tx', new mongoose.Schema({
  userId: mongoose.ObjectId,
  currency: String,
  amount: Number,
  type: String,
  desc: String,
  date: { type: Date, default: Date.now }
}));

function jwtToken(id, role = 'user') {
  return jwt.sign({ id, role }, JWT_SECRET, { expiresIn: '2d' });
}
function auth(role) {
  return (req, res, next) => {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    if (!token) return res.status(401).send('Missing token');
    try {
      const data = jwt.verify(token, JWT_SECRET);
      if (role && data.role !== role) return res.status(403).send('Forbidden');
      req.user = data;
      next();
    } catch { return res.status(401).send('Bad token'); }
  };
}
function randomAcct() { return Math.floor(10000000 + Math.random() * 90000000).toString(); }

const mailer = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: EMAIL_USER, pass: EMAIL_PASS }
});

app.post('/api/register', async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password) return res.status(400).send('Missing fields');
  const hashed = await bcrypt.hash(password, 10);
  const user = await User.create({
    fullName, email, passwordHash: hashed,
    accounts: [{ currency: 'USD', accountNumber: randomAcct(), balance: 0 }]
  });
  res.json({ ok: true, id: user._id });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const u = await User.findOne({ email });
  if (!u) return res.status(400).send('Bad creds');
  const ok = await bcrypt.compare(password, u.passwordHash);
  if (!ok) return res.status(400).send('Bad creds');
  res.json({ token: jwtToken(u._id) });
});

app.get('/api/me', auth(), async (req, res) => {
  const u = await User.findById(req.user.id).select('-passwordHash');
  const tx = await Tx.find({ userId: u._id }).sort({ date: -1 });
  res.json({ user: u, transactions: tx });
});

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username !== ADMIN_USER || password !== ADMIN_PASS)
    return res.status(400).send('Bad creds');
  res.json({ token: jwtToken('admin', 'admin') });
});

app.post('/api/admin/tx', auth('admin'), async (req, res) => {
  const { userId, currency, amount, type, desc } = req.body;
  const u = await User.findById(userId);
  if (!u) return res.status(404).send('User not found');
  const acc = u.accounts.find(a => a.currency === currency);
  if (!acc) return res.status(400).send('Account missing');
  const val = Number(amount);
  acc.balance = type === 'debit' ? acc.balance - val : acc.balance + val;
  await u.save();
  const t = await Tx.create({ userId: u._id, currency, amount: val, type, desc });
  res.json(t);
});

app.listen(3000, () => console.log('Server running on port 3000'));
