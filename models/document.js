const mongoose = require('mongoose');

const DocumentSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  url:       { type: String, required: true },         // upload URL (UploadThing or Cloudflare)
  filename:  { type: String, required: true },
  docType:   { type: String, enum: ['passport','id','utility','bank_statement','other'], default: 'other' },
  status:    { type: String, enum: ['pending','approved','rejected'], default: 'pending' },
  notes:     { type: String },
  reviewedAt:{ type: Date },
  reviewedBy:{ type: String } // admin username
}, { timestamps: true });

module.exports = mongoose.model('Document', DocumentSchema);
