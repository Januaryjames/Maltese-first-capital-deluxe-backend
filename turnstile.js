// turnstile.js
const fetch = require('node-fetch'); // v2

async function verifyTurnstile(token, ip) {
  const secret = process.env.TURNSTILE_SECRET;
  if (!secret) return false;
  try {
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `secret=${encodeURIComponent(secret)}&response=${encodeURIComponent(token)}&remoteip=${encodeURIComponent(ip || '')}`
    });
    const data = await resp.json();
    return !!data.success;
  } catch {
    return false;
  }
}

// Express middleware: require a valid token on this request
async function requireTurnstile(req, res, next) {
  const token = req.body?.['cf_turnstile_response'];
  const ok = await verifyTurnstile(token, req.ip);
  if (!ok) return res.status(400).json({ error: 'Captcha verification failed' });
  next();
}

module.exports = { verifyTurnstile, requireTurnstile };
