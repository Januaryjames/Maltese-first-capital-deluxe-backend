// routes/admin.js
const express = require("express");
const router = express.Router();

// Mock document DB
let documents = [
  { id: 1, clientName: "John Doe", clientEmail: "john@doe.com", category: "ID", status: "pending", createdAt: new Date() },
  { id: 2, clientName: "Sarah Borg", clientEmail: "sarah@borg.com", category: "POA", status: "review", createdAt: new Date() },
];

// List all docs
router.get("/documents", (req, res) => {
  res.json(documents);
});

// Approve
router.post("/document/:id/approve", (req, res) => {
  const id = parseInt(req.params.id);
  documents = documents.map((d) =>
    d.id === id ? { ...d, status: "approved" } : d
  );
  res.json({ message: "Document approved" });
});

// Reject
router.post("/document/:id/reject", (req, res) => {
  const id = parseInt(req.params.id);
  documents = documents.map((d) =>
    d.id === id ? { ...d, status: "rejected" } : d
  );
  res.json({ message: "Document rejected" });
});

// Request more docs
router.post("/document/request-docs", (req, res) => {
  const { userId, note } = req.body;
  if (!userId || !note)
    return res.status(400).json({ error: "Missing userId or note" });
  res.json({ message: `Request sent to user ${userId}` });
});

module.exports = router;
