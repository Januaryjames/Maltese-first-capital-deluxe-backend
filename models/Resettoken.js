// models/ResetToken.js
const mongoose = require('mongoose');

const ResetTokenSchema = new mongoose.Schema({
  email: { type: String, index: true, required: true, lowercase: true, trim: true },
  token: { type: String, required: true, unique: true },
  used: { type: Boolean, default: false },
  expiresAt: { type: Date, index: true }
}, { timestamps: true });

ResetTokenSchema.index({ email: 1, expiresAt: 1 });

module.exports = mongoose.model('ResetToken', ResetTokenSchema);
