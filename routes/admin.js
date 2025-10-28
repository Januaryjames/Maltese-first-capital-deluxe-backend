// routes/admin.js
import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

import { requireAdmin } from "../middleware/auth.js";
import User from "../models/User.js";
import Account from "../models/Account.js";
import Transaction from "../models/Transaction.js";
import KycSubmission from "../models/KycSubmission.js";

const r = Router();

// Admin login
r.post("/login", async (req, res) => {
  const { email, password } = req.body || {};
  const u = await User.findOne({ email, role: "admin" });
  if (!u) return res.status(401).send("Invalid credentials");
  const ok = await bcrypt.compare(password, u.passwordHash || "");
  if (!ok) return res.status(401).send("Invalid credentials");
  const token = jwt.sign({ id: u._id, email: u.email, role: "admin" }, process.env.JWT_SECRET, { expiresIn: "7d" });
  res.json({ token });
});

// Create a client + 8-digit account
r.post("/accounts", requireAdmin, async (req, res) => {
  const { holderName, holderEmail, currency = "USD" } = req.body || {};
  let user = await User.findOne({ email: holderEmail });
  if (!user) {
    const tempPass = Math.random().toString(36).slice(2, 10);
    user = await User.create({
      name: holderName, email: holderEmail,
      passwordHash: await bcrypt.hash(tempPass, 10), role: "client"
    });
  }
  let number;
  do { number = String(Math.floor(10_000_000 + Math.random() * 90_000_000)); }
  while (await Account.findOne({ number }));

  const account = await Account.create({
    number, holderUserId: user._id, holderName, holderEmail, currency, balance: 0
  });

  res.json({ ok: true, account });
});

// Post a credit/debit
r.post("/accounts/:number/txn", requireAdmin, async (req, res) => {
  const { type, amount, memo } = req.body || {};
  const acc = await Account.findOne({ number: req.params.number });
  if (!acc) return res.status(404).send("Account not found");
  const amt = Number(amount || 0);
  if (!amt || !["credit", "debit"].includes(type)) return res.status(400).send("Bad request");
  await Transaction.create({ accountNumber: acc.number, type, amount: amt, memo });
  acc.balance += type === "credit" ? amt : -amt;
  await acc.save();
  res.json({ ok: true, balance: acc.balance });
});

// KYC queue
r.get("/kyc", requireAdmin, async (_req, res) => {
  const items = await KycSubmission.find({ status: "pending" }).sort({ createdAt: -1 }).lean();
  res.json(items);
});

export default r;
