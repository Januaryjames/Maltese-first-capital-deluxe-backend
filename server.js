// server.js — email-only submission API (Express + Multer + Nodemailer)
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const multer = require('multer');              // <-- you missed this import
const nodemailer = require('nodemailer');
const path = require('path');

const {
  PORT = 8080,
  NODE_ENV = 'production',
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
  NOTIFY_FROM = 'Maltese First <no-reply@maltesefirst.com>',
  NOTIFY_TO   = 'hello@maltesefirst.com',
  CORS_ORIGIN = 'https://maltesefirst.com,https://www.maltesefirst.com'
} = process.env;

const app = express();
app.set('trust proxy', 1);

// CORS
const ALLOWED = CORS_ORIGIN.split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => (!origin || ALLOWED.includes(origin)) ? cb(null, true) : cb(new Error('Not allowed by CORS')),
  credentials: true,
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','X-Requested-With']
}));
app.options('*', cors());

// Body limits (we only use multipart for this route, but keep json small)
app.use(express.json({ limit: '64kb' }));

// Multer (memory) for attachments
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 16 * 1024 * 1024 } });

// Health
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, env: NODE_ENV, version: 'email-only-1.0.0', uptime: process.uptime() });
});

// POST /api/onboarding/email-only  -> sends everything to NOTIFY_TO
app.post('/api/onboarding/email-only',
  upload.fields([
    { name: 'docs_corporate', maxCount: 30 },
    { name: 'docs_id',        maxCount: 10 },
    { name: 'docs_poa',       maxCount: 10 },
    { name: 'docs_sof',       maxCount: 30 },
    { name: 'selfie_file',    maxCount: 1  }
  ]),
  async (req, res) => {
    try {
      // Mailer
      if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) {
        return res.status(500).json({ error: 'SMTP not configured' });
      }
      const transport = nodemailer.createTransport({
        host: SMTP_HOST,
        port: Number(SMTP_PORT),
        secure: Number(SMTP_PORT) === 465,
        auth: { user: SMTP_USER, pass: SMTP_PASS }
      });

      // Build plain-text summary
      const b = req.body || {};
      const lines = [
        'New Account Application (Email-Only)',
        '-----------------------------------',
        `Company / Account Name : ${b.company_name || b.companyName || '-'}`,
        `Authorised Person       : ${b.authorized_person || b.authorised_person || b.fullName || '-'}`,
        `Email                   : ${b.email || '-'}`,
        `Phone                   : ${b.phone || '-'}`,
        `Address                 : ${b.address || b.company_address || '-'}`,
        `Country                 : ${b.country || '-'}`,
        `Commercial Registration : ${b.commercial_registration || '-'}`,
        `Account Type            : ${b.account_type || b.accountType || 'Corporate – Private Client (Onboarding)'}`,
        `Primary Currency        : ${b.currency || 'USD'}`,
        `Source of Funds         : ${b.source_of_funds || b.sourceOfFunds || '-'}`,
        '',
        'Notes:',
        (b.notes || '-')
      ];

      // Collect Multer file fields cleanly
      const collect = (field) => (req.files?.[field] || []).map(f => ({
        filename: f.originalname,
        content:  f.buffer,
        contentType: f.mimetype
      }));

      const attachments = [
        ...collect('docs_corporate'),
        ...collect('docs_id'),
        ...collect('docs_poa'),
        ...collect('docs_sof'),
        ...collect('selfie_file')
      ];

      const subject = `Account Application — ${b.company_name || b.companyName || 'New Client'}`;

      await transport.sendMail({
        from: NOTIFY_FROM,
        to: NOTIFY_TO,
        subject,
        text: lines.join('\n'),
        attachments
      });

      res.json({ ok: true, delivered: true });
    } catch (e) {
      console.error('email-only submit failed:', e);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// Boot
app.listen(PORT, () => {
  console.log(`Email-only API listening on :${PORT}`);
});
