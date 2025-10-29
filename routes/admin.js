const express = require('express');
const router = express.Router();
const Client = require('../models/Client');
const Transaction = require('../models/Transaction');

function checkAdmin(req, res, next) {
  if ((req.headers['x-admin-key'] || '') !== (process.env.ADMIN_KEY || '')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// Approve client
router.post('/approve', checkAdmin, async (req, res, next) => {
  try {
    const { clientId } = req.body;
    const c = await Client.findByIdAndUpdate(clientId, { status: 'approved' }, { new: true });
    if (!c) return res.status(404).json({ error: 'Client not found' });
    res.json({ ok: true, status: c.status });
  } catch (err) { next(err); }
});

// Set balances
router.post('/balances', checkAdmin, async (req, res, next) => {
  try {
    const { clientId, balances } = req.body; // { current, savings, investments }
    const c = await Client.findByIdAndUpdate(clientId, { balances }, { new: true });
    if (!c) return res.status(404).json({ error: 'Client not found' });
    res.json({ ok: true, balances: c.balances });
  } catch (err) { next(err); }
});

// Add transaction
router.post('/transactions', checkAdmin, async (req, res, next) => {
  try {
    const { clientId, type, amount, currency = 'USD', memo } = req.body;
    const t = await Transaction.create({ client: clientId, type, amount, currency, memo });
    res.status(201).json({ ok: true, transaction: t });
  } catch (err) { next(err); }
});

module.exports = router;
