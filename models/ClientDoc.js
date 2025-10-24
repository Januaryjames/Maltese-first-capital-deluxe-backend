const mongoose = require('mongoose');

const clientDocSchema = new mongoose.Schema({
  userId: { type: String, index: true },
  clientName: String,
  clientEmail: String,
  category: { type: String, enum: ['ID','POA','SOURCE','OTHER'], default: 'OTHER' },
  filename: String,
  url: String,
  status: { type: String, enum: ['pending','review','approved','rejected'], default: 'pending', index: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('ClientDoc', clientDocSchema);
