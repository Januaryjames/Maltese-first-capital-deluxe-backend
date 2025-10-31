// routes/onboarding.js
// POST /api/onboarding/account-open
// Accepts multipart FormData from the Account Open page,
// verifies Cloudflare Turnstile, saves a record to Mongo,
// and (optionally) emails Ops. No visual impact.

const multer = require('multer');
const { createHash, randomUUID } = require('crypto');
const mongoose = require('mongoose');

// ---- Mongoose model (idempotent) ----
const Application = mongoose.models.Application || mongoose.model(
  'Application',
  new mongoose.Schema({
    ref: { type: String, index: true },
    status: { type: String, default: 'submitted' }, // submitted | reviewing | approved | rejected
    fields: mongoose.Schema.Types.Mixed,             // all non-file fields as-is
    files: [{
      field: String, filename: String, mime: String, size: Number, sha256: String
    }],
    ip: String
  }, { timestamps: true })
);

// ---- Turnstile verify helper ----
async function verifyTurnstile(token, ip) {
  const secret = process.env.TURNSTILE_SECRET || '';
  if (!secret || !token) return false;
  try {
    const body = new URLSearchParams();
    body.append('secret', secret);
    body.append('response', token);
    if (ip) body.append('remoteip', ip);

    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });
    const data = await r.json();
    return !!data.success;
  } catch {
    return false;
  }
}

// ---- Multer (memory) ----
// We store file *metadata* + email the attachments (optional).
// This avoids Mongo's 16MB doc limit while keeping a trail.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 16 * 1024 * 1024 } // 16MB per file, matches frontend guard
});

// ---- Optional mailer ----
let mailer = null;
(function maybeSetupMailer() {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) return;
  const nodemailer = require('nodemailer');
  mailer = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: Number(SMTP_PORT) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
})();

module.exports = function mountOnboarding(app) {
  app.post('/api/onboarding/account-open', upload.any(), async (req, res) => {
    try {
      // 1) Bot check
      const token =
        req.body['cf_turnstile_response'] ||
        req.body['cf-turnstile-response'] ||
        req.headers['x-turnstile-token'] ||
        '';
      const ok = await verifyTurnstile(token, req.ip);
      if (!ok) return res.status(400).json({ error: 'Captcha verification failed' });

      // 2) Separate fields/files
      const fields = { ...req.body };
      delete fields['cf_turnstile_response'];
      delete fields['cf-turnstile-response'];

      const ALLOWED = new Set(['application/pdf', 'image/jpeg', 'image/png', 'image/webp']);
      const filesMeta = [];
      const mailAttachments = [];

      for (const f of (req.files || [])) {
        if (!ALLOWED.has(f.mimetype)) {
          return res.status(415).json({ error: `Unsupported file type: ${f.mimetype}` });
        }
        if (f.size > 16 * 1024 * 1024) {
          return res.status(413).json({ error: 'File too large (max 16MB)' });
        }
        const sha256 = createHash('sha256').update(f.buffer).digest('hex');
        filesMeta.push({ field: f.fieldname, filename: f.originalname, mime: f.mimetype, size: f.size, sha256 });
        mailAttachments.push({ filename: f.originalname, content: f.buffer, contentType: f.mimetype });
      }

      // 3) Persist a compact record
      const ref = `MFC-${(randomUUID?.() || Math.random().toString(36).slice(2)).slice(0,8).toUpperCase()}`;
      const doc = await Application.create({
        ref, status: 'submitted', fields, files: filesMeta, ip: req.ip
      });

      // 4) Optional: email Ops
      if (mailer && process.env.NOTIFY_TO) {
        const escape = s => String(s || '').replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
        const html = `
          <h3>New Account Application</h3>
          <p><b>Ref:</b> ${escape(doc.ref)}</p>
          <p><b>From:</b> ${escape(fields.email || '')} · <b>Name:</b> ${escape(fields.authorisedPerson || fields.name || '')}</p>
          <p><b>Company:</b> ${escape(fields.company || fields.companyName || '')}</p>
          <pre>${escape(JSON.stringify(fields, null, 2))}</pre>
          <p><b>Files:</b> ${filesMeta.map(f => escape(`${f.filename} (${f.mime}, ${f.size}B)`)).join(', ') || 'none'}</p>
        `;
        await mailer.sendMail({
          from: process.env.NOTIFY_FROM || 'Maltese First <no-reply@maltesefirst.com>',
          to: process.env.NOTIFY_TO,
          subject: `New Account Application — ${doc.ref}`,
          html,
          attachments: mailAttachments
        });
      }

      // 5) Done
      return res.status(202).json({ ok: true, applicationId: doc.ref });
    } catch (e) {
      console.error('account-open error', e);
      return res.status(500).json({ error: 'Server error' });
    }
  });
};
