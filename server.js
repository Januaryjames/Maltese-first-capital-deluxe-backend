// server.js — Maltese First Capital Backend
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 10000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Ensure uploads folder exists
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log("📁 Created /uploads directory");
}
app.use("/uploads", express.static(uploadsDir));

// MongoDB Connection
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Routes
const clientRoutes = require("./routes/client");
const adminRoutes = require("./routes/admin");

app.use("/api/client", clientRoutes);
app.use("/api/admin", adminRoutes);

// Health check
app.get("/api/health", (req, res) => res.json({ ok: true }));

// Frontend static fallback (optional)
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => {
  const file = path.join(__dirname, "public", "index.html");
  if (fs.existsSync(file)) res.sendFile(file);
  else res.status(404).send("Not Found");
});

// Start server
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
