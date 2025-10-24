const nodemailer = require('nodemailer');

const EMAIL_USER = process.env.EMAIL_USER; // hello@maltesefirst.com
const EMAIL_PASS = process.env.EMAIL_PASS; // app password

let transporter = null;

function getTransporter() {
  if (transporter) return transporter;
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: EMAIL_USER, pass: EMAIL_PASS }
  });
  return transporter;
}

async function sendOtp(email, code) {
  const t = getTransporter();
  const html = `
    <div style="font-family:system-ui,Segoe UI,Arial">
      <h2>Maltese First Capital — Your OTP</h2>
      <p>Your one-time code is:</p>
      <p style="font-size:24px;font-weight:700;letter-spacing:3px">${code}</p>
      <p>This code expires in 10 minutes.</p>
    </div>`;
  await t.sendMail({
    from: `"Maltese First Capital" <${EMAIL_USER}>`,
    to: email,
    subject: 'Your One-Time Passcode',
    html
  });
}

async function notifyDocStatus(email, status, filename) {
  const t = getTransporter();
  await t.sendMail({
    from: `"Maltese First Capital" <${EMAIL_USER}>`,
    to: email,
    subject: `Document ${status}: ${filename}`,
    text: `Your document "${filename}" was ${status}.`,
    html: `<p>Your document "<b>${filename}</b>" was <b>${status}</b>.</p>`
  });
}

module.exports = { sendOtp, notifyDocStatus };
