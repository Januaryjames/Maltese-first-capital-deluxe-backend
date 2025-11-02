// === Email-only Account Open (direct to hello@maltesefirst.com) ===
const emailUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 16 * 1024 * 1024 } // 16MB per file
});

// Accept both old and new field names (so you don't touch the frontend)
const emailFields = [
  { name:'passport', maxCount:2 },
  { name:'proofOfAddress', maxCount:3 },
  { name:'companyDocs', maxCount:20 },
  { name:'selfie', maxCount:1 },
  { name:'docs_id', maxCount:2 },
  { name:'docs_poa', maxCount:5 },
  { name:'docs_corporate', maxCount:20 },
  { name:'docs_sof', maxCount:20 },
  { name:'selfie_file', maxCount:1 }
];

function pickFiles(req, ...names) {
  return names.flatMap(n => (req.files?.[n] || []));
}
function escapeHtml(s){ return String(s).replace(/[<>&]/g, m => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[m])); }

app.post('/api/onboarding/email-only', emailUpload.fields(emailFields), async (req, res) => {
  try {
    if (!mailer) {
      return res.status(500).json({ error: 'Email not configured (SMTP envs missing)' });
    }

    const b = req.body || {};
    const fullName    = b.fullName || b.authorized_person || b.authorised_person || '';
    const companyName = b.companyName || b.company_name || '';
    const subject = `MFC Account Application — ${companyName || 'No Company'} — ${fullName || 'No Name'}`;

    const allFiles = [
      ...pickFiles(req, 'passport','docs_id'),
      ...pickFiles(req, 'proofOfAddress','docs_poa'),
      ...pickFiles(req, 'companyDocs','docs_corporate','docs_sof'),
      ...pickFiles(req, 'selfie','selfie_file'),
    ];

    const attachments = allFiles.map(f => ({
      filename: f.originalname || 'file',
      content: f.buffer,
      contentType: f.mimetype || 'application/octet-stream'
    }));

    const html = `
      <h2>New Account Application</h2>
      <p><b>Submitted:</b> ${new Date().toISOString()}</p>
      <h3>Client (form fields)</h3>
      <pre style="font-size:14px;line-height:1.4">${escapeHtml(JSON.stringify(b, null, 2))}</pre>
      <p><b>Total attachments:</b> ${attachments.length}</p>
    `;

    await mailer.sendMail({
      from: NOTIFY_FROM,
      to: 'hello@maltesefirst.com',
      subject,
      html,
      attachments
    });

    return res.status(202).json({ ok: true, delivered: true });
  } catch (e) {
    console.error('email-only error:', e);
    return res.status(500).json({ error: 'Email send failed' });
  }
});
