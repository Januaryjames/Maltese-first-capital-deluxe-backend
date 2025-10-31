// backend/privacy-routes.js
// Adds: POST /api/privacy/dsr (Turnstile-gated). Stores DSR requests and emails Ops.
// Standalone: require from server.js with `require('./privacy-routes')(app);`
const multer = require('multer');
const { createHash } = require('crypto');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');

module.exports = function(app){
  const { TURNSTILE_SECRET, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
          NOTIFY_FROM = 'Maltese First <no-reply@maltesefirst.com>',
          NOTIFY_TO = '' } = process.env;

  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

  const DSRRequest = mongoose.models.DSRRequest || mongoose.model('DSRRequest', new mongoose.Schema({
    type: { type: String, enum: ['access','rectification','erasure','restriction','portability','objection'], required: true },
    name: String,
    email: String,
    country: String,
    details: String,
    idDoc: {
      filename: String, mime: String, size: Number, sha256: String, data: Buffer
    },
    ip: String,
    status: { type: String, enum: ['received','verifying','completed','rejected'], default: 'received' }
  }, { timestamps: true }));

  let mailer = null;
  if (SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS) {
    mailer = nodemailer.createTransport({
      host: SMTP_HOST, port: Number(SMTP_PORT),
      secure: Number(SMTP_PORT) === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS }
    });
  }

  async function verifyTurnstile(token, ip){
    if (!TURNSTILE_SECRET) return false;
    try {
      const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method:'POST', headers:{'content-type':'application/x-www-form-urlencoded'},
        body:`secret=${encodeURIComponent(TURNSTILE_SECRET)}&response=${encodeURIComponent(token||'')}&remoteip=${encodeURIComponent(ip||'')}`
      });
      const d = await r.json();
      return !!d.success;
    } catch { return false; }
  }

  app.post('/api/privacy/dsr', upload.single('idDoc'), async (req, res) => {
    try {
      const ok = await verifyTurnstile(req.body?.['cf_turnstile_response'] || '', req.ip);
      if (!ok) return res.status(400).json({ error: 'Captcha verification failed' });

      const { type, name, email, country, details } = req.body || {};
      if (!type || !email || !details) return res.status(400).json({ error: 'Missing required fields' });

      let idDoc = undefined;
      const f = req.file;
      if (f && f.buffer) {
        const okTypes = new Set(['application/pdf','image/jpeg','image/png','image/webp']);
        if (!okTypes.has(f.mimetype)) return res.status(415).json({ error: 'Unsupported file type' });
        if (f.size > 5*1024*1024) return res.status(413).json({ error: 'File too large (max 5MB)' });
        idDoc = {
          filename: f.originalname,
          mime: f.mimetype,
          size: f.size,
          sha256: createHash('sha256').update(f.buffer).digest('hex'),
          data: f.buffer
        };
      }

      const doc = await DSRRequest.create({ type, name, email, country, details, idDoc, ip: req.ip });
      const id = String(doc._id);

      if (mailer && NOTIFY_TO) {
        await mailer.sendMail({
          from: NOTIFY_FROM, to: NOTIFY_TO,
          subject: `GDPR request: ${type} — ${email}`,
          html: `<h3>New GDPR request</h3>
                 <p><b>ID:</b> ${id}</p>
                 <p><b>Type:</b> ${type}</p>
                 <p><b>Name:</b> ${name||'-'} · <b>Email:</b> ${email}</p>
                 <p><b>Country:</b> ${country||'-'}</p>
                 <pre>${(details||'').replace(/[<>&]/g, s => ({{'<':'&lt;','>':'&gt;','&':'&amp;'}[s]))}</pre>`,
          attachments: idDoc ? [{ filename: idDoc.filename || 'id', content: idDoc.data, contentType: idDoc.mime }] : []
        });
      }

      return res.status(202).json({ id });
    } catch (e) {
      console.error('DSR error', e);
      return res.status(500).json({ error: 'Server error' });
    }
  });
};
