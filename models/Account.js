// models/Account.js
import mongoose from "mongoose";
const AccountSchema = new mongoose.Schema({
  number: { type: String, unique: true, index: true },   // 8 digits
  holderUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
  holderName: String,
  holderEmail: String,
  currency: { type: String, default: "USD" },
  balance: { type: Number, default: 0 }
}, { timestamps: true });

export default mongoose.models.Account || mongoose.model("Account", AccountSchema);
