// routes/public.js
import { Router } from "express";
import multer from "multer";
import path from "path";
import KycSubmission from "../models/KycSubmission.js";
import { sendEmail } from "../utils/email.js"; // you already have utils/email.js

const r = Router();

const storage = multer.diskStorage({
  destination: (_req, _f, cb) => cb(null, "uploads"),
  filename: (_req, file, cb) => cb(null, `${Date.now()}-${file.originalname.replace(/\s+/g,"_")}`)
});
const upload = multer({ storage });

// Public KYC submit (multipart form)
r.post("/kyc", upload.array("files", 6), async (req, res) => {
  const payload = req.body || {};
  const files = (req.files || []).map(f => `/${f.path}`); // keep relative path
  const rec = await KycSubmission.create({ ...payload, files });

  // Email hello@
  const lines = Object.entries(payload).map(([k,v])=>`<div><b>${k}</b>: ${String(v||"")}</div>`).join("");
  const links = files.map(f=>`<div><a href="${f}">${path.basename(f)}</a></div>`).join("");
  try {
    await sendEmail("hello@maltesefirst.com", "New KYC Submission", `${lines}${links}`);
  } catch (e) {
    // keep going; stored in DB regardless
    console.error("Email error:", e.message);
  }
  res.json({ ok: true, id: rec._id });
});

export default r;
