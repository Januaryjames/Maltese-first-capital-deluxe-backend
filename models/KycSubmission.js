// models/KycSubmission.js
import mongoose from "mongoose";
const KyCSchema = new mongoose.Schema({
  fullName: String,
  email: String,
  phone: String,
  nationality: String,
  pep: { type: Boolean, default: false },
  address: String,
  idType: String,
  idNumber: String,
  taxResidency: String,
  sourceOfFunds: String,
  files: [String], // file paths in /uploads
  status: { type: String, enum: ["pending","approved","rejected"], default: "pending", index: true }
}, { timestamps: true });

export default mongoose.models.KycSubmission || mongoose.model("KycSubmission", KyCSchema);
