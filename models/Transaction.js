// models/Transaction.js
const mongoose = require('mongoose');
const TransactionSchema = new mongoose.Schema({
  client: { type: mongoose.Schema.Types.ObjectId, ref: 'Client', index: true },
  date:   { type: Date, default: Date.now },
  currency: { type: String, required: true },
  amount:   { type: Number, required: true }, // +credit / -debit
  type:     { type: String, enum: ['credit','debit'], required: true },
  description: String,
  balanceAfter: Number
}, { timestamps: true });

module.exports = mongoose.model('Transaction', TransactionSchema);
