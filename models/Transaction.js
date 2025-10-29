const { Schema, model, Types } = require('mongoose');

const TxSchema = new Schema({
  client: { type: Types.ObjectId, ref: 'Client', index: true },
  type: { type: String, enum: ['credit', 'debit'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'USD' },
  memo: String,
  date: { type: Date, default: Date.now, index: true }
}, { timestamps: true });

module.exports = model('Transaction', TxSchema);
