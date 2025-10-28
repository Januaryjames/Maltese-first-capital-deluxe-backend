// server.js
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

import authRoutes from "./routes/auth.js";
import publicRoutes from "./routes/public.js";
import adminRoutes from "./routes/admin.js";

const app = express();
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static("uploads"));

app.use("/api/auth", authRoutes);
app.use("/api/public", publicRoutes);
app.use("/api/admin", adminRoutes);

app.get("/api/health", (_req,res)=>res.json({ ok: true }));

const PORT = process.env.PORT || 8080;
mongoose.connect(process.env.MONGO_URI).then(()=>{
  app.listen(PORT, ()=>console.log("API listening on", PORT));
}).catch(err=>{ console.error(err); process.exit(1); });
