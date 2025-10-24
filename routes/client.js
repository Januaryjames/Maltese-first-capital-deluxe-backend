const express = require('express');
const multer  = require('multer');
const path    = require('path');
const ClientDoc = require('../models/ClientDoc');
const r = express.Router();

const upload = multer({ dest: path.join(__dirname, '../uploads'), limits: { fileSize: 15 * 1024 * 1024 } });

// Middleware placeholder for client auth
function authClient(req, res, next){ next(); } // <-- Replace with real auth later

r.post('/document', authClient, upload.single('file'), async (req, res) => {
  const { category = 'OTHER' } = req.body;
  if (!req.file) return res.status(400).send('No file uploaded.');
  const fileURL = `/uploads/${req.file.filename}`;
  const doc = await ClientDoc.create({
    userId: 'demoUser', clientName: 'Demo Client', clientEmail: 'client@example.com',
    category, filename: req.file.originalname, url: fileURL, status: 'pending'
  });
  res.json({ id: doc._id, url: doc.url });
});

r.get('/documents', authClient, async (req, res) => {
  const docs = await ClientDoc.find().sort({ createdAt: -1 }).lean();
  res.json(docs);
});

r.delete('/document/:id', authClient, async (req, res) => {
  await ClientDoc.deleteOne({ _id: req.params.id });
  res.json({ ok: true });
});

module.exports = r;
