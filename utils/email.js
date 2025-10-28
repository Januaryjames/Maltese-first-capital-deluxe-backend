// utils/email.js  (ESM)
import nodemailer from "nodemailer";
import dotenv from "dotenv";
dotenv.config();

const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: Number(process.env.MAIL_PORT || 587),
  secure: false,
  auth: { user: process.env.MAIL_USER, pass: process.env.MAIL_PASS },
});

export async function sendEmail(to, subject, html) {
  if (!process.env.MAIL_FROM) {
    throw new Error("MAIL_FROM not set");
  }
  return transporter.sendMail({
    from: process.env.MAIL_FROM,
    to,
    subject,
    html,
  });
}

// optional: keep a default for flexibility
export default sendEmail;
