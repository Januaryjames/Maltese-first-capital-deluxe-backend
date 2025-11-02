// server.js — email-only submission API (Express + Multer + Nodemailer)
// v1.0.1 (adds SMTP verify + detailed error)
// Drop-in replacement.

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const nodemailer = require('nodemailer');

const {
  PORT = 8080,
  NODE_ENV = 'production',
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
  NOTIFY_FROM = 'Maltese First <no-reply@maltesefirst.com>',
  NOTIFY_TO   = 'hello@maltesefirst.com',
  CORS_ORIGIN = 'https://maltesefirst.com,https://www.maltesefirst.com',
  DEBUG_ERRORS = '1'               // keep 1 for now to surface SMTP reasons
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

// Light parsers (multipart handled by multer)
app.use(express.json({ limit: '64kb' }));

// Multer in-memory
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 16 * 1024 * 1024 }});

// Health
app.get('/api/health', (_req, res) => res.json({ ok: true, env: NODE_ENV, version: 'email-only-1.0.1', uptime: process.uptime() }));

function makeTransport() {
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) return null;
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: Number(SMTP_PORT) === 465,   // 465 = SSL, 587/25 = STARTTLS/plain
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
}

// Quick SMTP probe
app.get('/api/debug/smtp', async (_req, res) => {
  try {
    const t = makeTransport();
    if (!t) return res.status(500).json({ ok:false, error:'SMTP_NOT_CONFIGURED' });
    await t.verify(); // if this throws you’ll see the cause
    res.json({ ok:true });
  } catch (e) {
    res.status(500).json({ ok:false, error:'SMTP_VERIFY_FAILED', detail:e.message });
  }
});

// Email-only intake
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
      const transport = makeTransport();
      if (!transport) return res.status(500).json({ error:'SMTP_NOT_CONFIGURED' });

      // Show the exact reason if SMTP is unhappy
      await transport.verify().catch(e => {
        throw Object.assign(new Error('SMTP_VERIFY_FAILED'), { cause:e });
      });

      const b = req.body || {};
      const summaryLines = [
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

      await transport.sendMail({
        from: NOTIFY_FROM,
        to:   NOTIFY_TO,
        subject: `Account Application — ${b.company_name || b.companyName || 'New Client'}`,
        text: summaryLines.join('\n'),
        attachments
      });

      return res.json({ ok:true, delivered:true, attachments: attachments.length });
    } catch (e) {
      console.error('email-only submit failed:', e?.cause?.message || e?.message || e);
      // Surface the SMTP reason while we’re debugging
      if (DEBUG_ERRORS === '1') {
        return res.status(500).json({
          error: e.message || 'Server error',
          detail: (e.cause && e.cause.message) || undefined
        });
      }
      return res.status(500).json({ error:'Server error' });
    }
  }
);

app.listen(PORT, () => console.log(`Email-only API listening on :${PORT}`));
