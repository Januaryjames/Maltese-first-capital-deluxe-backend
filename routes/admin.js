// routes/admin.js
const express = require('express');
const Client = require('../models/Client');
const Tx = require('../models/Transaction');
const router = express.Router();

// ultra-simple admin “auth”
const ADMIN_KEY = process.env.ADMIN_KEY || 'change-me';
router.use((req, res, next) => {
  if (req.headers['x-admin-key'] === ADMIN_KEY) return next();
  return res.status(401).json({ ok:false, error:'Unauthorized' });
});

/** Approve client */
router.patch('/clients/:id/approve', async (req,res)=>{
  const c = await Client.findByIdAndUpdate(req.params.id, { status:'approved' }, { new: true });
  if(!c) return res.status(404).json({ ok:false, error:'Not found' });
  res.json({ ok:true, client:c });
});

/** Update balances (partial) */
router.patch('/clients/:id/balances', async (req,res)=>{
  const c = await Client.findById(req.params.id);
  if(!c) return res.status(404).json({ ok:false, error:'Not found' });
  c.balances = { ...c.balances, ...req.body }; // e.g. { USD: 1234.56 }
  await c.save();
  res.json({ ok:true, balances:c.balances });
});

/** Post a transaction */
router.post('/clients/:id/transactions', async (req,res)=>{
  const c = await Client.findById(req.params.id);
  if(!c) return res.status(404).json({ ok:false, error:'Not found' });
  const { currency, amount, type, description } = req.body;

  // update balance first
  const prev = Number(c.balances[currency] || 0);
  const next = type === 'credit' ? prev + amount : prev - amount;
  c.balances[currency] = next;
  await c.save();

  const tx = await Tx.create({ client: c._id, currency, amount, type, description, balanceAfter: next });
  res.status(201).json({ ok:true, tx });
});

module.exports = router;
