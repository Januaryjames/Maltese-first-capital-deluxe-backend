const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();

// ---------- Approve Uploaded Docs ----------
router.get('/documents', (req, res) => {
  const dir = path.join(__dirname, '../uploads');
  if (!fs.existsSync(dir)) return res.json({ documents: [] });

  const files = fs.readdirSync(dir);
  res.json({ documents: files });
});

router.post('/approve', (req, res) => {
  const { filename } = req.body;
  if (!filename) return res.status(400).json({ error: 'Filename missing' });

  // This is where you’d flag approval status in MongoDB later
  res.json({ message: `Document "${filename}" approved.` });
});

module.exports = router;
