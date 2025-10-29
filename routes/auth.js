const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const Client = require('../models/Client');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

/**
 * POST /api/auth/login
 * Dev-simple login: email match + (optional) last4 phone as pin
 * Replace with OTP later.
 */
router.post('/login', async (req, res, next) => {
  try {
    const { email, pin } = req.body;
    const c = await Client.findOne({ email }).lean();
    if (!c) return res.status(401).json({ error: 'Invalid credentials' });

    // Optional: accept last 4 digits of phone as pin in dev
    const last4 = (c.phone || '').replace(/\D/g, '').slice(-4);
    if (last4 && pin && pin !== last4) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ sub: c._id, email: c.email }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, clientId: c._id, accountNumber: c.accountNumber, name: c.fullName });
  } catch (err) { next(err); }
});

module.exports = router;
