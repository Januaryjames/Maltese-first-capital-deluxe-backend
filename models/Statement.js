// models/Statement.js
const mongoose = require('mongoose');
const StatementSchema = new mongoose.Schema({
  client: { type: mongoose.Schema.Types.ObjectId, ref: 'Client', index: true },
  periodStart: Date,
  periodEnd:   Date,
  text:        String
}, { timestamps: true });
module.exports = mongoose.model('Statement', StatementSchema);
