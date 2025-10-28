// models/Transaction.js
import mongoose from "mongoose";
const TxSchema = new mongoose.Schema({
  accountNumber: { type: String, index: true },
  type: { type: String, enum: ["credit", "debit"] },
  amount: Number,
  memo: String
}, { timestamps: true });

export default mongoose.models.Transaction || mongoose.model("Transaction", TxSchema);
