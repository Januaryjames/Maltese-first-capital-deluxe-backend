const mongoose = require('mongoose');

const OtpCodeSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  code:      { type: String, required: true },
  expiresAt: { type: Date, required: true }
}, { timestamps: true });

OtpCodeSchema.index({ userId: 1, expiresAt: 1 });

module.exports = mongoose.model('OtpCode', OtpCodeSchema);
