// routes/auth.js
const express = require('express');
const jwt = require('jsonwebtoken');
const Client = require('../models/Client');
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

/** Client login (email + accountNumber) */
router.post('/login', async (req, res) => {
  const { email, accountNumber } = req.body;
  const client = await Client.findOne({ email, accountNumber });
  if (!client) return res.status(401).json({ ok: false, error: 'Invalid credentials' });
  if (client.status !== 'approved') return res.status(403).json({ ok: false, error: 'Account not approved' });

  const token = jwt.sign({ cid: client._id }, JWT_SECRET, { expiresIn: '2d' });
  res.json({ ok: true, token, clientId: client._id });
});

module.exports = router;
