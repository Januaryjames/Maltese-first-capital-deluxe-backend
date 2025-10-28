// middleware/auth.js
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

function getToken(req) {
  const h = req.headers.authorization || "";
  const parts = h.split(" ");
  return parts.length === 2 ? parts[1] : null;
}

export function requireClient(req, res, next) {
  try {
    const token = getToken(req);
    if (!token) return res.status(401).send("Unauthorized");
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (payload.role !== "client") return res.status(403).send("Forbidden");
    req.user = payload;
    next();
  } catch {
    return res.status(401).send("Unauthorized");
  }
}

export function requireAdmin(req, res, next) {
  try {
    const token = getToken(req);
    if (!token) return res.status(401).send("Unauthorized");
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (payload.role !== "admin") return res.status(403).send("Forbidden");
    req.user = payload;
    next();
  } catch {
    return res.status(401).send("Unauthorized");
  }
}
