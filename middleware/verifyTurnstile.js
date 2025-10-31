// backend/middleware/verifyTurnstile.js
module.exports = async function verifyTurnstile(req, res, next){
  try {
    const token = req.body['cf_turnstile_response'] || req.body['cf-turnstile-response'] || req.headers['x-turnstile-token'];
    if (!token) return res.status(400).json({ error: 'Missing Turnstile token' });
    const secret = process.env.TURNSTILE_SECRET;
    const ip = req.ip;
    const params = new URLSearchParams();
    params.append('secret', secret);
    params.append('response', token);
    params.append('remoteip', ip);
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: params.toString()
    });
    const data = await r.json();
    if (!data.success) return res.status(403).json({ error: 'Captcha failed' });
    next();
  } catch (e) {
    console.error('Turnstile verify error', e);
    res.status(500).json({ error: 'Captcha verify error' });
  }
};
