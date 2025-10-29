require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();

/* -------- CORS -------- */
const allowed = [
  /localhost(:\d+)?$/,
  /maltesefirst\.com$/,
  /onrender\.com$/         // your Render URL during testing
];
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (allowed.some(rx => rx.test(origin))) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  }
}));
app.use(express.json({ limit: '5mb' }));

/* -------- Mongo (don’t crash on boot) -------- */
const uri = process.env.MONGO_URI;
if (!uri) console.warn('[WARN] MONGO_URI is not set — API will run but DB routes may fail.');

(async () => {
  if (!uri) return;
  try {
    await mongoose.connect(uri, { autoIndex: true });
    console.log('[OK] Mongo connected');
  } catch (err) {
    console.error('[Mongo] initial connect failed:', err.message);
    // keep server alive; Render will still see port bound
  }
})();

/* -------- Health -------- */
app.get('/api/health', (_req, res) => {
  const mongoOk = mongoose.connection?.readyState === 1;
  res.json({ ok: true, status: 'healthy', mongo: mongoOk ? 'up' : 'down' });
});

/* -------- Routes -------- */
app.use('/api/clients', require('./routes/clients'));
app.use('/api/auth',    require('./routes/auth'));
app.use('/api/admin',   require('./routes/admin'));

/* -------- Start (MUST use Render’s PORT) -------- */
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`[OK] MFC backend listening on ${PORT}`));
