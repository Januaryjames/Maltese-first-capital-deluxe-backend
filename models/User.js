// models/User.js
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true, index: true, required: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['client', 'admin'], default: 'client', index: true },
  name: { type: String, trim: true }
}, { timestamps: true });

UserSchema.index({ email: 1 });

module.exports = mongoose.model('User', UserSchema);
