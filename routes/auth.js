// routes/auth.js
import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

import User from "../models/User.js";
import Account from "../models/Account.js";
import Transaction from "../models/Transaction.js";
import { requireClient } from "../middleware/auth.js";

const r = Router();

// ---- Client login ----
r.post("/client/login", async (req, res) => {
  const { email, password } = req.body || {};
  const u = await User.findOne({ email });
  if (!u) return res.status(401).send("Invalid credentials");
  const ok = await bcrypt.compare(password, u.passwordHash || "");
  if (!ok || u.role !== "client") return res.status(401).send("Invalid credentials");
  const token = jwt.sign({ id: u._id, email: u.email, role: "client" }, process.env.JWT_SECRET, { expiresIn: "7d" });
  res.json({ token });
});

// ---- Me + accounts ----
r.get("/client/me", requireClient, async (req, res) => {
  const u = await User.findById(req.user.id).lean();
  const accounts = await Account.find({ holderUserId: u._id }).lean();
  res.json({ email: u.email, name: u.name, accounts });
});

// ---- Account transactions ----
r.get("/client/accounts/:number/transactions", requireClient, async (req, res) => {
  const rows = await Transaction.find({ accountNumber: req.params.number })
    .sort({ createdAt: -1 }).limit(100).lean();
  res.json(rows);
});

export default r;
