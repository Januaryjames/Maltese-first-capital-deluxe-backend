// models/Client.js
const mongoose = require('mongoose');

const BalanceSchema = new mongoose.Schema({
  USD: { type: Number, default: 0 },
  EUR: { type: Number, default: 0 },
  // add more currencies as needed
}, { _id: false });

const ClientSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email:    { type: String, required: true, index: true, unique: true },
  phone:    { type: String },
  nationality: String,
  address: String,
  sourceOfFunds: String,
  accountNumber: { type: String, unique: true, index: true }, // 8-digit
  status: { type: String, enum: ['pending','approved','rejected'], default: 'pending' },
  balances: { type: BalanceSchema, default: () => ({}) },
}, { timestamps: true });

module.exports = mongoose.model('Client', ClientSchema);
