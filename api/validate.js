// api/validate.js — Vercel Serverless Function
// Serial Numbers disimpan di Environment Variable: SERIAL_NUMBERS
// Format ENV: SN-UMKM-001,SN-UMKM-002,SN-UMKM-003 (dipisah koma)

import crypto from "crypto";

// Rate limiter sederhana (in-memory, reset tiap cold start Vercel)
const attempts = new Map();
const MAX_ATTEMPTS = 5;       // max percobaan gagal
const BLOCK_DURATION = 15 * 60 * 1000; // 15 menit blokir

function getClientIP(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.headers["x-real-ip"] ||
    "unknown"
  );
}

function isBlocked(ip) {
  const record = attempts.get(ip);
  if (!record) return false;
  if (record.count >= MAX_ATTEMPTS) {
    if (Date.now() - record.lastAttempt < BLOCK_DURATION) return true;
    attempts.delete(ip); // reset setelah masa blokir habis
  }
  return false;
}

function recordFailedAttempt(ip) {
  const record = attempts.get(ip) || { count: 0, lastAttempt: 0 };
  record.count += 1;
  record.lastAttempt = Date.now();
  attempts.set(ip, record);
}

function resetAttempts(ip) {
  attempts.delete(ip);
}

// Bandingkan SN dengan timing-safe compare (anti timing attack)
function safeCompare(a, b) {
  const bufA = Buffer.from(a.padEnd(128));
  const bufB = Buffer.from(b.padEnd(128));
  return crypto.timingSafeEqual(bufA, bufB) && a === b;
}

export default async function handler(req, res) {
  // Hanya terima POST
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, message: "Method not allowed" });
  }

  // CORS: hanya izinkan domain sendiri
  const origin = req.headers.origin || "";
  const allowedOrigins = (process.env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim());
  if (allowedOrigins.length > 0 && allowedOrigins[0] !== "" && !allowedOrigins.includes(origin)) {
    return res.status(403).json({ ok: false, message: "Forbidden" });
  }

  const ip = getClientIP(req);

  // Cek rate limit
  if (isBlocked(ip)) {
    return res.status(429).json({
      ok: false,
      message: "Terlalu banyak percobaan gagal. Coba lagi dalam 15 menit.",
    });
  }

  const { sn } = req.body || {};

  if (!sn || typeof sn !== "string") {
    return res.status(400).json({ ok: false, message: "Serial number tidak valid." });
  }

  // Ambil daftar SN dari environment variable
  const rawSNList = process.env.SERIAL_NUMBERS || "";
  if (!rawSNList) {
    console.error("ENV SERIAL_NUMBERS belum diset!");
    return res.status(500).json({ ok: false, message: "Konfigurasi server error." });
  }

  // Normalisasi: uppercase + hapus spasi
  const snInput = sn.trim().toUpperCase();
  const validSNs = rawSNList
    .split(",")
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean);

  // Cek apakah SN ada di daftar (timing-safe)
  const isValid = validSNs.some((validSN) => safeCompare(snInput, validSN));

  if (!isValid) {
    recordFailedAttempt(ip);
    const record = attempts.get(ip);
    const remaining = MAX_ATTEMPTS - (record?.count || 0);
    return res.status(401).json({
      ok: false,
      message: `Serial number salah. Sisa percobaan: ${Math.max(0, remaining)}`,
    });
  }

  // Berhasil → reset rate limit
  resetAttempts(ip);

  // Buat token akses (HMAC dari SN + secret)
  const secret = process.env.TOKEN_SECRET || "ganti-ini-dengan-secret-acak-panjang";
  const token = crypto
    .createHmac("sha256", secret)
    .update(snInput)
    .digest("hex");

  return res.status(200).json({ ok: true, token });
}
