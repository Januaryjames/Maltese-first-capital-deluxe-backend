// models/Application.js
const mongoose = require('mongoose');

const FileMetaSchema = new mongoose.Schema({
  gridfsId: mongoose.Schema.Types.ObjectId,
  filename: String,
  mime: String,
  size: Number
}, { _id: false });

const ApplicationSchema = new mongoose.Schema({
  applicationId: { type: String, unique: true, index: true },
  status: { type: String, enum: ['received', 'review', 'approved', 'rejected'], default: 'received' },
  fields: {
    fullName: String,
    email: String,
    phone: String,
    companyName: String,
    country: String
  },
  files: {
    passport: [FileMetaSchema],
    proofOfAddress: [FileMetaSchema],
    companyDocs: [FileMetaSchema],
    selfie: [FileMetaSchema]
  },
  submittedByIp: String
}, { timestamps: true });

ApplicationSchema.index({ status: 1, createdAt: -1 });

module.exports = mongoose.model('Application', ApplicationSchema);
