const express = require('express');
const ClientDoc = require('../models/ClientDoc');
const r = express.Router();

// Fake admin auth for now (replace later)
function authAdmin(req,res,next){ next(); }

r.get('/documents', authAdmin, async (req, res) => {
  const docs = await ClientDoc.find().sort({ createdAt: -1 }).limit(200).lean();
  res.json(docs);
});

r.post('/document/:id/approve', authAdmin, async (req, res) => {
  await ClientDoc.findByIdAndUpdate(req.params.id, { status: 'approved' });
  res.json({ ok: true });
});

r.post('/document/:id/reject', authAdmin, async (req, res) => {
  await ClientDoc.findByIdAndUpdate(req.params.id, { status: 'rejected' });
  res.json({ ok: true });
});

r.post('/document/request-docs', authAdmin, async (req, res) => {
  const { userId, note } = req.body;
  console.log(`Requesting more docs from ${userId}: ${note}`);
  res.json({ ok: true });
});

module.exports = r;
