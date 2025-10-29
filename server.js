// server.js — Express + Mongo + JWT + CORS + Multer
// Env: MONGODB_URI, JWT_SECRET, PORT

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const multer = require("multer");

const app = express();
app.use(helmet());
app.use(express.json({ limit: "2mb" }));

// CORS — allow your prod + local
const allowed = ["https://maltesefirst.com", "http://localhost:5500", "http://localhost:3000"];
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowed.includes(origin)) return cb(null, true);
    return cb(new Error("Not allowed by CORS"));
  },
  credentials: true
}));

// Health
app.get("/health", (req, res) => res.json({ ok: true, ts: Date.now() }));

// Mongo
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/mfc";
mongoose.connect(MONGODB_URI, { })
  .then(() => console.log("Mongo connected"))
  .catch((e) => console.error("Mongo error", e));

// Schemas
const UserSchema = new mongoose.Schema({
  email: { type: String, index: true, unique: true },
  passwordHash: String, // demo-only; replace with real hash
  role: { type: String, enum: ["client", "admin"], default: "client" },
});

const TransactionSchema = new mongoose.Schema({
  date: { type: Date, default: Date.now },
  description: String,
  amount: Number,
  balance: Number
});

const ClientSchema = new mongoose.Schema({
  userId: { type: mongoose.Types.ObjectId, ref: "User" },
  fullName: String,
  phone: String,
  nationality: String,
  address: String,
  sourceOfFunds: String,
  // docs (filenames or links)
  passportFile: String,
  proofAddressFile: String,
  status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
  accountNumber: { type: String, index: true }, // 8-digit
  balances: [
    { ccy: String, amount: Number }
  ],
  statementNote: String,
  transactions: [TransactionSchema]
});

const User = mongoose.model("User", UserSchema);
const Client = mongoose.model("Client", ClientSchema);

// JWT helpers
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
function sign(user) {
  return jwt.sign({ sub: user._id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
}
function auth(requiredRole) {
  return (req, res, next) => {
    const h = req.headers.authorization || "";
    const t = h.startsWith("Bearer ") ? h.slice(7) : null;
    if (!t) return res.status(401).json({ message: "Missing token" });
    try {
      const payload = jwt.verify(t, JWT_SECRET);
      req.user = payload;
      if (requiredRole && payload.role !== requiredRole) return res.status(403).json({ message: "Forbidden" });
      next();
    } catch (e) {
      return res.status(401).json({ message: "Invalid token" });
    }
  };
}

// Multer for uploads (memory -> you can swap to S3/local disk as needed)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// ROUTES

// 1) KYC Apply (anonymous)
app.post("/api/clients/apply", upload.fields([{ name: "passport" }, { name: "proofAddress" }]), async (req, res) => {
  try {
    const { fullName, email, phone, nationality, address, sourceOfFunds } = req.body;
    if (!fullName || !email) return res.status(400).json({ message: "fullName and email are required" });

    // Upsert user (demo: no password; you can email a magic link/OTP)
    let user = await User.findOne({ email });
    if (!user) user = await User.create({ email, role: "client" });

    // Save file names (in real life, upload buffers to S3 and store URLs)
    const passportFile = req.files?.passport?.[0]?.originalname || null;
    const proofAddressFile = req.files?.proofAddress?.[0]?.originalname || null;

    let client = await Client.findOne({ userId: user._id });
    if (!client) client = new Client({ userId: user._id });

    client.set({
      fullName, phone, nationality, address, sourceOfFunds,
      passportFile, proofAddressFile,
      status: "pending"
    });

    await client.save();
    return res.json({ ok: true, applicationId: client._id });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: "Apply failed" });
  }
});

// 2) Auth (very simple email+password demo)
// Replace with proper hashing or OTP flow.
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });

    let user = await User.findOne({ email });
    if (!user) {
      // optional: auto-create for demo purposes
      user = await User.create({ email, role: "client" });
      // also create an empty client record for demo
      await Client.create({
        userId: user._id,
        fullName: email.split("@")[0],
        balances: [{ ccy: "USD", amount: 0 }, { ccy: "EUR", amount: 0 }],
        transactions: []
      });
    }
    const token = sign(user);
    res.json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Login failed" });
  }
});

// 3) Client overview (protected)
app.get("/api/clients/me/overview", auth(), async (req, res) => {
  try {
    const userId = req.user.sub;
    const user = await User.findById(userId);
    const client = await Client.findOne({ userId });

    if (!client) return res.status(404).json({ message: "Client profile not found" });

    // Ensure 8-digit account number exists
    if (!client.accountNumber) {
      client.accountNumber = String(Math.floor(10000000 + Math.random()*90000000));
      await client.save();
    }

    const out = {
      name: client.fullName || user.email,
      accountNumber: client.accountNumber,
      balances: client.balances?.length ? client.balances : [{ ccy: "USD", amount: 0 }],
      transactions: client.transactions || [],
      statementNote: client.statementNote || ""
    };
    res.json(out);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Overview failed" });
  }
});

// ADMIN (stubs)
// Approve client + set balances or account number
app.post("/api/admin/approve/:id", auth("admin"), async (req, res) => {
  try {
    const client = await Client.findById(req.params.id);
    if (!client) return res.status(404).json({ message: "Not found" });
    if (!client.accountNumber) client.accountNumber = String(Math.floor(10000000 + Math.random()*90000000));
    client.status = "approved";
    if (Array.isArray(req.body?.balances)) client.balances = req.body.balances;
    await client.save();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Approve failed" });
  }
});

// Add transaction
app.post("/api/admin/clients/:id/transactions", auth("admin"), async (req, res) => {
  try {
    const { date, description, amount } = req.body || {};
    const client = await Client.findById(req.params.id);
    if (!client) return res.status(404).json({ message: "Not found" });

    const lastBal = client.transactions?.length ? client.transactions[client.transactions.length - 1].balance : (client.balances?.[0]?.amount || 0);
    const newBal = Number(lastBal) + Number(amount || 0);

    client.transactions.push({
      date: date ? new Date(date) : new Date(),
      description: description || "",
      amount: Number(amount || 0),
      balance: newBal
    });

    // Optional: keep first currency in sync for demo
    if (client.balances?.length) client.balances[0].amount = newBal;

    await client.save();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Add transaction failed" });
  }
});

// Update statement note
app.post("/api/admin/clients/:id/statement-note", auth("admin"), async (req, res) => {
  try {
    const client = await Client.findById(req.params.id);
    if (!client) return res.status(404).json({ message: "Not found" });
    client.statementNote = req.body?.note || "";
    await client.save();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ message: "Update note failed" });
  }
});

// Listen
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`API listening on :${PORT}`));
