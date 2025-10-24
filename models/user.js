const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email:    { type: String, required: true, unique: true, index: true },
  passwordHash: { type: String, required: true },
  accountNumber: { type: String, required: true, unique: true }, // 8 digits
  // Simple profile fields you may expand later:
  phone: String,
  address: String
}, { timestamps: true });

module.exports = mongoose.model('User', UserSchema);
