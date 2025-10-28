// models/User.js
import mongoose from "mongoose";
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, index: true },
  passwordHash: String,
  role: { type: String, enum: ["admin", "client"], default: "client", index: true }
}, { timestamps: true });

export default mongoose.models.User || mongoose.model("User", UserSchema);
