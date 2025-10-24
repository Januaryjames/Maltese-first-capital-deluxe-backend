// server.js — OTP auth + document uploads + admin notifications
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import multer from "multer";
import nodemailer from "nodemailer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

// ---------- ENV ----------
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const MONGODB_URI = process.env.MONGODB_URI; // MUST include a database name after .net/
const EMAIL_USER = process.env.EMAIL_USER;   // hello@maltesefirst.com
const EMAIL_PASS = process.env.EMAIL_PASS;   // app password
const ADMIN_NOTIFY = process.env.ADMIN_NOTIFY || EMAIL_USER; // who receives upload alerts
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || "*";

// ---------- PATH HELPERS ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Ensure /uploads exists for multer
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ---------- APP ----------
const app = express();
app.use(express.json());
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({ origin: CLIENT_ORIGIN, credentials: true }));

// Basic rate limit (tune as needed)
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });
app.use(limiter);

// Serve uploaded files (optional, for admin preview)
app.use("/uploads", express.static(UPLOAD_DIR));

// ---------- DB ----------
if (!MONGODB_URI || !MONGODB_URI.includes(".net/")) {
  console.error("❌ MONGODB_URI missing or has no /<dbname>. Fix your Render env.");
}
await mongoose
  .connect(MONGODB_URI, { dbName: undefined }) // db is in the URI path
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err.message));

// ---------- EMAIL ----------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: EMAIL_USER, pass: EMAIL_PASS }
});

// ---------- MODELS ----------
const userSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, required: true },
    fullName: String,
    isAdmin: { type: Boolean, default: false },
    passwordHash: String // optional (not used for OTP flow)
  },
  { timestamps: true }
);

const otpSchema = new mongoose.Schema(
  {
    email: { type: String, index: true },
    codeHash: String,
    expiresAt: Date,
    attempts: { type: Number, default: 0 }
  },
  { timestamps: true }
);

const docSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    docType: String, // e.g., "passport", "proof_of_address", "bank_statement"
    filename: String,
    originalName: String,
    status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
    note: String
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Otp = mongoose.model("Otp", otpSchema);
const Document = mongoose.model("Document", docSchema);

// ---------- AUTH HELPERS ----------
const auth = (req, res, next) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
};

const adminOnly = (req, res, next) => {
  if (!req.user?.isAdmin) return res.status(403).json({ error: "Admin only" });
  next();
};

// ---------- MULTER ----------
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) => {
    const safe = file.originalname.replace(/[^a-z0-9.\-_]/gi, "_").toLowerCase();
    const stamp = Date.now();
    cb(null, `${stamp}-${safe}`);
  }
});
const upload = multer({ storage });

// ---------- ROUTES ----------
app.get("/api/health", (req, res) => res.json({ ok: true }));

// 1) OTP: request code
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Valid email required" });

    // Create user if not exists
    let user = await User.findOne({ email });
    if (!user) user = await User.create({ email });

    // Generate 6-digit OTP
    const code = (Math.floor(100000 + Math.random() * 900000)).toString();
    const codeHash = await bcrypt.hash(code, 10);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await Otp.deleteMany({ email });
    await Otp.create({ email, codeHash, expiresAt });

    // Email OTP
    await transporter.sendMail({
      from: `Maltese First Capital <${EMAIL_USER}>`,
      to: email,
      subject: "Your Maltese First Capital Login Code",
      text: `Your OTP is ${code}. It expires in 10 minutes.`,
      html: `<p>Your OTP is <b style="font-size:18px">${code}</b>. It expires in 10 minutes.</p>`
    });

    return res.json({ ok: true, message: "OTP sent" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to send OTP" });
  }
});

// 2) OTP: verify code, return JWT
app.post("/api/auth/verify", async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: "Email and code required" });

    const record = await Otp.findOne({ email });
    if (!record) return res.status(400).json({ error: "No active code. Please request a new one." });

    if (record.expiresAt < new Date()) {
      await Otp.deleteOne({ _id: record._id });
      return res.status(400).json({ error: "Code expired. Request a new one." });
    }

    const ok = await bcrypt.compare(code, record.codeHash);
    if (!ok) {
      record.attempts += 1;
      await record.save();
      return res.status(400).json({ error: "Invalid code" });
    }

    const user = await User.findOne({ email });
    await Otp.deleteOne({ _id: record._id });

    const token = jwt.sign(
      { userId: user._id, email: user.email, isAdmin: !!user.isAdmin },
      JWT_SECRET,
      { expiresIn: "2d" }
    );

    return res.json({ ok: true, token, user: { id: user._id, email: user.email, isAdmin: user.isAdmin } });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Verification failed" });
  }
});

// (Optional) Simple admin login by env creds (kept for compatibility)
app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    const token = jwt.sign(
      { userId: "admin", email: ADMIN_NOTIFY, isAdmin: true },
      JWT_SECRET,
      { expiresIn: "1d" }
    );
    return res.json({ ok: true, token });
  }
  return res.status(401).json({ error: "Invalid admin credentials" });
});

// 3) Client uploads documents (auth required)
// form-data: fields => docType, file => "file"
app.post("/api/client/upload-docs", auth, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file received" });

    const { docType } = req.body;
    const doc = await Document.create({
      userId: req.user.userId,
      docType: docType || "unspecified",
      filename: req.file.filename,
      originalName: req.file.originalname,
      status: "pending"
    });

    // Notify admin
    const user = await User.findById(req.user.userId);
    const link = `${req.protocol}://${req.get("host")}/uploads/${doc.filename}`;
    await transporter.sendMail({
      from: `Maltese First Capital <${EMAIL_USER}>`,
      to: ADMIN_NOTIFY,
      subject: "New KYC document uploaded",
      html: `
        <p>A client uploaded a new document.</p>
        <ul>
          <li><b>Client:</b> ${user?.email || req.user.email}</li>
          <li><b>Type:</b> ${doc.docType}</li>
          <li><b>File:</b> ${doc.originalName}</li>
          <li><b>Preview:</b> <a href="${link}">${doc.filename}</a></li>
        </ul>
        <p>Use the admin dashboard to approve or reject.</p>
      `
    });

    return res.json({ ok: true, document: doc });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Upload failed" });
  }
});

// 4) Admin: list pending documents
app.get("/api/admin/docs", auth, adminOnly, async (req, res) => {
  const docs = await Document.find({ status: "pending" }).sort({ createdAt: -1 }).populate("userId", "email");
  res.json({ ok: true, docs });
});

// 5) Admin: approve/reject document
app.post("/api/admin/docs/:id/decision", auth, adminOnly, async (req, res) => {
  const { action, note } = req.body; // action = "approve" | "reject"
  if (!["approve", "reject"].includes(action)) return res.status(400).json({ error: "Invalid action" });

  const doc = await Document.findById(req.params.id);
  if (!doc) return res.status(404).json({ error: "Document not found" });

  doc.status = action === "approve" ? "approved" : "rejected";
  if (note) doc.note = note;
  await doc.save();

  // Notify client by email (if email exists)
  const owner = await User.findById(doc.userId);
  if (owner?.email) {
    await transporter.sendMail({
      from: `Maltese First Capital <${EMAIL_USER}>`,
      to: owner.email,
      subject: `Your document was ${doc.status}`,
      html: `<p>Your uploaded document (<b>${doc.originalName}</b>) was <b>${doc.status}</b>.</p>${note ? `<p>Note: ${note}</p>` : ""}`
    });
  }

  res.json({ ok: true, doc });
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
