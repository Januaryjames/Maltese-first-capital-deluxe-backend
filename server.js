// -----------------------------
// Maltese First Capital Backend
// -----------------------------
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const clientRoutes = require('./routes/client');
const adminRoutes  = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 10000;

// ---------- Middleware ----------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------- CORS (restrict to prod domains) ----------
app.use(cors({
  origin: ['https://maltesefirst.com', 'https://www.maltesefirst.com'],
  credentials: true,
}));

// ---------- MongoDB ----------
const uri = process.env.MONGO_URI || process.env.MONGODB_URI;
if (!uri) {
  console.error('❌ No Mongo URI set. Define MONGO_URI in Render env.');
} else {
  mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('✅ MongoDB connected'))
    .catch(err => console.error('❌ MongoDB connection error:', err.message));
}

// ---------- Health ----------
app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'mfc-backend', ts: new Date().toISOString() });
});

// ---------- API Routes ----------
app.use('/api/client', clientRoutes);
app.use('/api/admin', adminRoutes);

// ---------- Optional static (if /public exists) ----------
const publicDir = path.join(__dirname, 'public');
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
  app.get('*', (req, res) => res.sendFile(path.join(publicDir, 'index.html')));
  console.log('📁 Serving /public assets.');
} else {
  app.get('/', (req, res) => res.json({ ok: true, service: 'mfc-backend', public: false }));
  console.log('ℹ️ No /public folder; skipping static serve.');
}

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
