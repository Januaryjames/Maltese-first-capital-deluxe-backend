// routes/clients.js
const express = require('express');
const Client = require('../models/Client');
const Tx = require('../models/Transaction');
const generateAccountNumber = require('../utils/generateAccountNumber');
const router = express.Router();

/** KYC: create client (public) */
router.post('/', async (req, res) => {
  try {
    const { fullName, email, phone, nationality, address, sourceOfFunds } = req.body;
    const accountNumber = generateAccountNumber();
    const client = await Client.create({ fullName, email, phone, nationality, address, sourceOfFunds, accountNumber });
    res.status(201).json({ ok: true, clientId: client._id, accountNumber, status: client.status });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

/** Client summary (authed) */
router.get('/:id/summary', async (req, res) => {
  try {
    const client = await Client.findById(req.params.id).lean();
    if (!client) return res.status(404).json({ ok: false, error: 'Not found' });

    const transactions = await Tx.find({ client: client._id })
      .sort({ date: -1 }).limit(10).lean();

    res.json({
      ok: true,
      client: {
        fullName: client.fullName,
        accountNumber: client.accountNumber,
        status: client.status,
        balances: client.balances
      },
      transactions
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

module.exports = router;// routes/client.js
const express = require("express");
const router = express.Router();
const multer = require("multer");
const path = require("path");
const fs = require("fs");

// Multer storage config
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, "../uploads");
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e6);
    cb(null, unique + "-" + file.originalname);
  },
});
const upload = multer({ storage });

// Mock user data
let documents = [];

// Profile endpoint
router.get("/me", (req, res) => {
  res.json({
    name: "John Doe",
    email: "john@doe.com",
    phone: "+356 9999 0000",
    address1: "St. Anne Street",
    city: "Floriana",
    zip: "FRN 9010",
    country: "Malta",
    currency: "EUR",
  });
});

// List documents
router.get("/documents", (req, res) => {
  res.json(documents);
});

// Upload new document
router.post("/document", upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  const doc = {
    id: documents.length + 1,
    category: req.body.category || "OTHER",
    filename: req.file.filename,
    path: `/uploads/${req.file.filename}`,
    url: `/uploads/${req.file.filename}`,
    createdAt: new Date(),
    status: "pending",
  };
  documents.push(doc);
  res.json(doc);
});

// Delete document
router.delete("/document/:id", (req, res) => {
  const id = parseInt(req.params.id);
  documents = documents.filter((d) => d.id !== id);
  res.json({ success: true });
});

// Change password (mock)
router.post("/password", (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword)
    return res.status(400).json({ error: "Missing fields" });
  res.json({ message: "Password updated" });
});

module.exports = router;
