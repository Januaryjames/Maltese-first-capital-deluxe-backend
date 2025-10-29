const express = require('express');
const router = express.Router();
const Client = require('../models/Client');
const Transaction = require('../models/Transaction');

// Generate unique 8-digit account number
async function nextAccountNumber() {
  for (let i = 0; i < 10; i++) {
    const num = Math.floor(10000000 + Math.random() * 90000000).toString();
    const exists = await Client.findOne({ accountNumber: num }).lean();
    if (!exists) return num;
  }
  // ultra-rare: fallback uses time-based suffix
  return (Date.now() % 100000000).toString().padStart(8, '0');
}

/**
 * POST /api/clients
 * Create KYC application
 */
router.post('/', async (req, res, next) => {
  try {
    const {
      fullName, email, phone, nationality, address, sourceOfFunds,
      passportUrl, proofOfAddressUrl
    } = req.body;

    const accountNumber = await nextAccountNumber();
    const client = await Client.create({
      fullName, email, phone, nationality, address, sourceOfFunds,
      docs: { passportUrl, proofOfAddressUrl },
      accountNumber,
      status: 'pending',
      balances: { current: 0, savings: 0, investments: 0 }
    });

    res.status(201).json({
      message: 'Application received',
      clientId: client._id,
      accountNumber: client.accountNumber,
      status: client.status
    });
  } catch (err) { next(err); }
});

/**
 * GET /api/clients/:id/overview
 * Dashboard payload
 */
router.get('/:id/overview', async (req, res, next) => {
  try {
    const c = await Client.findById(req.params.id).lean();
    if (!c) return res.status(404).json({ error: 'Client not found' });

    const txns = await Transaction.find({ client: c._id })
      .sort({ date: -1 }).limit(10).lean();

    res.json({
      name: c.fullName,
      accountNumber: c.accountNumber,
      status: c.status,
      balances: c.balances,
      recentTransactions: txns
    });
  } catch (err) { next(err); }
});

module.exports = router;
