const { Schema, model } = require('mongoose');

const ClientSchema = new Schema({
  fullName: String,
  email: { type: String, index: true },
  phone: String,
  nationality: String,
  address: String,
  sourceOfFunds: String,
  docs: {
    passportUrl: String,
    proofOfAddressUrl: String
  },
  accountNumber: { type: String, unique: true, index: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending', index: true },
  balances: {
    current: { type: Number, default: 0 },
    savings: { type: Number, default: 0 },
    investments: { type: Number, default: 0 }
  }
}, { timestamps: true });

module.exports = model('Client', ClientSchema);
