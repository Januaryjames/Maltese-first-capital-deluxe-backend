// -----------------------------
// Maltese First Capital Backend (Final Stable Build)
// -----------------------------

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 10000;

// ---------- Middleware ----------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------- CORS (only allow main domain) ----------
app.use(cors({
  origin: ['https://maltesefirst.com', 'https://www.maltesefirst.com'],
  credentials: true,
}));

// ---------- MongoDB Connection ----------
const uri = process.env.MONGO_URI || process.env.MONGODB_URI;

if (!uri) {
  console.error('❌ No Mongo URI found. Please set MONGO_URI in Render > Environment.');
} else {
  mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('✅ MongoDB connected'))
    .catch(err => console.error('❌ MongoDB connection error:', err.message));
}

// ---------- Health & Base Routes ----------
app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'mfc-backend', timestamp: new Date().toISOString() });
});

app.get('/api/test', (req, res) => {
  res.json({ message: 'Maltese First Capital backend operational ✅' });
});

// ---------- ROUTE IMPORTS ----------
const clientRoutes = require('./routes/client');
const adminRoutes = require('./routes/admin');

app.use('/api/client', clientRoutes);
app.use('/api/admin', adminRoutes);

// ---------- Static File Serving (Optional) ----------
const publicDir = path.join(__dirname, 'public');
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
  app.get('*', (req, res) => res.sendFile(path.join(publicDir, 'index.html')));
  console.log('📁 Serving static /public assets.');
} else {
  console.log('ℹ️ No /public folder detected — skipping static serve.');
}

// ---------- Start Server ----------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
