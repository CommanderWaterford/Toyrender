// --- Env ---
require("dotenv").config({ path: "/var/www/toyrender.com/.env" });

// --- Core imports ---
const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const helmet = require("helmet");
const crypto = require("crypto");
const sharp = require("sharp");
const rateLimit = require("express-rate-limit");
const slowDown = require("express-slow-down");
const Bottleneck = require("bottleneck");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const validator = require("validator");
const zxcvbn = require("zxcvbn");
const { GoogleGenAI } = require("@google/genai");
const Stripe = require("stripe");
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// --- App init ---
const app = express();
const PORT = parseInt(process.env.PORT || "3060", 10);
// Right after you define PORT
const BASE_URL = "https://toyrender.com";

app.set("trust proxy", 1);

// --- Security middleware ---
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: "same-site" },
  })
);

// --- CORS (restrict to your site) ---
const allowedOrigins = (process.env.CORS_ORIGIN || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
app.use(
  cors({
    origin: allowedOrigins.length ? allowedOrigins : true,
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"],
    credentials: true,
  })
);

// --- Stripe Webhook (must receive RAW body) ---

app.post(
  "/payments/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.warn("⚠️  Webhook signature verification failed.", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      console.log("Stripe webhook event:", event.type);
      if (event.type === "checkout.session.completed") {
        const session = event.data.object;

        // Only award on paid sessions
        if (session.payment_status !== "paid") {
          console.log("Webhook: session not paid, skipping.", {
            id: session.id,
            status: session.payment_status,
          });
          return res.json({ received: true, skipped: "not paid" });
        }

        const userId = Number(
          session.metadata?.userId || session.client_reference_id
        );
        const credits = Number(session.metadata?.credits || 10);
        const amount = Number(session.amount_total || 500); // cents
        const currency = String(session.currency || "usd").toLowerCase();

        // Use payment_intent as the unique idempotency key (best across events)
        const idempotencyKey = String(session.payment_intent || session.id);

        if (userId && credits > 0) {
          console.log("Granting credits from webhook", {
            userId,
            credits,
            eventId: idempotencyKey,
          });
          await grantCreditsAfterPayment({
            eventId: idempotencyKey,
            userId,
            amount,
            currency,
            credits,
          });
        } else {
          console.error("Webhook missing metadata userId/credits", {
            metadata: session.metadata,
            client_reference_id: session.client_reference_id,
          });
        }
      }

      res.json({ received: true });
    } catch (err) {
      console.error("Webhook handler error:", err);
      res.status(500).send("Webhook handler failed");
    }
  }
);

app.post(
  "/api/payments/confirm",
  express.json(),
  ensureAuth,
  async (req, res) => {
    try {
      const sessionId = req.body?.session_id || req.query?.session_id;
      if (!sessionId)
        return res.status(400).json({ error: "session_id required" });

      const session = await stripe.checkout.sessions.retrieve(sessionId);

      if (session.mode !== "payment")
        return res.status(400).json({ error: "Not a payment session" });
      if (session.payment_status !== "paid")
        return res.status(409).json({ error: "Session not paid" });

      const userIdFromSession = Number(
        session.metadata?.userId || session.client_reference_id
      );
      if (userIdFromSession !== req.session.userId)
        return res
          .status(403)
          .json({ error: "Session does not belong to you" });

      const credits = Number(session.metadata?.credits || 10);
      const amount = Number(session.amount_total || 500);
      const currency = String(session.currency || "usd").toLowerCase();
      const idempotencyKey = String(session.payment_intent || session.id);

      await grantCreditsAfterPayment({
        eventId: idempotencyKey,
        userId: req.session.userId,
        amount,
        currency,
        credits,
      });

      const uc = await get(
        "SELECT paid_remaining FROM user_credits WHERE user_id=?",
        [req.session.userId]
      );
      res.json({ ok: true, paid_remaining: uc?.paid_remaining || 0 });
    } catch (e) {
      console.error("confirm error:", e?.message || e);
      res.status(500).json({ error: e?.message || "confirm failed" });
    }
  }
);

// --- Body parsers ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// --- Session (SQLite-backed) ---
const DATA_DIR = path.resolve(__dirname, "_data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

app.use(
  session({
    store: new SQLiteStore({
      db: "sessions.sqlite",
      dir: DATA_DIR,
    }),
    secret:
      process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: (process.env.COOKIE_SECURE || "true") === "true",
      maxAge: 1000 * 60 * 60 * 24 * 60, // ~60 days
    },
    name: "sid",
  })
);

// --- Paths ---
const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOADS_DIR = path.join(PUBLIC_DIR, "uploads");
const RESULTS_DIR = path.join(PUBLIC_DIR, "results");
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(RESULTS_DIR)) fs.mkdirSync(RESULTS_DIR, { recursive: true });

// --- Static files ---
app.use(express.static(PUBLIC_DIR));

// --- NDJSON logger (generation events) ---
const LOG_DIR = path.join(__dirname, "_logs");
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
const GEN_LOG_PATH = path.join(LOG_DIR, "generation.ndjson");
const genLogStream = fs.createWriteStream(GEN_LOG_PATH, { flags: "a" });

// --- REPLACE THE OLD logGen FUNCTION WITH THIS ---
function logGen(data) {
  try {
    const ts = new Date().toISOString();
    const { event, reqId, duration_ms, userEmail, file, output, error } = data;

    let logLine = `[${ts}] EVENT: ${event.toUpperCase()} | REQ: ${reqId} | USER: ${userEmail}`;

    if (duration_ms) {
      logLine += ` | DURATION: ${duration_ms}ms`;
    }

    if (file) {
      logLine += ` | FILE: "${file.name}" (${(file.size / 1024).toFixed(
        2
      )} KB)`;
    }

    if (output && output.image) {
      logLine += ` | OUTPUT: ${output.image}`;
    }

    if (error) {
      logLine += ` | ERROR: ${error.message || "Unknown Error"}`;
    }

    genLogStream.write(logLine + "\n");
  } catch (err) {
    console.error("!!! FAILED TO WRITE TO GENERATION LOG !!!", err);
  }
}
// --- END OF REPLACEMENT ---

process.on("SIGINT", () => genLogStream.end(() => process.exit(0)));
process.on("SIGTERM", () => genLogStream.end(() => process.exit(0)));

// --- SQLite helpers ---
const DB_PATH = path.join(DATA_DIR, "app.sqlite");
const db = new sqlite3.Database(DB_PATH);
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}
async function txn(fn) {
  await run("BEGIN IMMEDIATE");
  try {
    const res = await fn();
    await run("COMMIT");
    return res;
  } catch (e) {
    await run("ROLLBACK");
    throw e;
  }
}

// ApplyWaterMark Function
async function applyWatermark(imagePath) {
  // === OPACITY CONTROLS ===
  // Adjust these values between 0 (fully transparent) and 1 (fully opaque)

  // CENTER WATERMARK OPACITY
  const CENTER_TEXT_OPACITY = 0.3; // Main "TOYRENDER.COM" text opacity (0.4 = 40% visible)
  const CENTER_SUBTITLE_OPACITY = 0.3; // "FREE TRIAL" text opacity
  const CENTER_STROKE_OPACITY = 0.3; // Border around center text
  const CENTER_SHADOW_OPACITY = 0.5; // Drop shadow opacity

  // CORNER WATERMARK OPACITY
  const CORNER_BACKGROUND_OPACITY = 0.7; // Black background box opacity
  const CORNER_SUBTITLE_OPACITY = 0.8; // "Buy credits..." text opacity

  try {
    // Create bottom-right watermark SVG
    const cornerWatermarkSVG = Buffer.from(`
      <svg width="300" height="80" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:#9333ea;stop-opacity:1" />
            <stop offset="100%" style="stop-color:#ec4899;stop-opacity:1" />
          </linearGradient>
        </defs>
        <rect x="0" y="0" width="300" height="80" rx="10" fill="rgba(0,0,0,${CORNER_BACKGROUND_OPACITY})"/>
        <text x="150" y="35" font-family="Arial, sans-serif" font-size="28" font-weight="bold" fill="url(#grad)" text-anchor="middle">
          Toyrender.com
        </text>
        <text x="150" y="60" font-family="Arial, sans-serif" font-size="14" fill="rgba(255,255,255,${CORNER_SUBTITLE_OPACITY})" text-anchor="middle">
          Buy credits for watermark-free images
        </text>
      </svg>
    `);

    // Create center watermark SVG with adjustable opacity
    const centerWatermarkSVG = Buffer.from(`
      <svg width="400" height="120" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="centerGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:#ffffff;stop-opacity:${CENTER_TEXT_OPACITY}" />
            <stop offset="50%" style="stop-color:#9333ea;stop-opacity:${CENTER_TEXT_OPACITY}" />
            <stop offset="100%" style="stop-color:#ec4899;stop-opacity:${CENTER_TEXT_OPACITY}" />
          </linearGradient>
          <filter id="shadow">
            <feDropShadow dx="2" dy="2" stdDeviation="3" flood-opacity="${CENTER_SHADOW_OPACITY}"/>
          </filter>
        </defs>
        <text x="200" y="60" font-family="Arial, sans-serif" font-size="48" font-weight="bold" 
              fill="url(#centerGrad)" text-anchor="middle" filter="url(#shadow)" 
              stroke="rgba(255,255,255,${CENTER_STROKE_OPACITY})" stroke-width="1">
          TOYRENDER.COM
        </text>
        <text x="200" y="90" font-family="Arial, sans-serif" font-size="18" 
              fill="rgba(255,255,255,${CENTER_SUBTITLE_OPACITY})" text-anchor="middle" filter="url(#shadow)">
          FREE TRIAL
        </text>
      </svg>
    `);

    // Read the original image
    const imageBuffer = await fs.promises.readFile(imagePath);

    // Get image metadata to determine if we need to resize the center watermark
    const metadata = await sharp(imageBuffer).metadata();

    // Scale center watermark based on image size
    let centerWatermarkBuffer = centerWatermarkSVG;
    if (metadata.width && metadata.width < 800) {
      // Create a smaller version for smaller images (with same opacity settings)
      centerWatermarkBuffer = Buffer.from(`
        <svg width="250" height="80" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <linearGradient id="centerGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" style="stop-color:#ffffff;stop-opacity:${CENTER_TEXT_OPACITY}" />
              <stop offset="50%" style="stop-color:#9333ea;stop-opacity:${CENTER_TEXT_OPACITY}" />
              <stop offset="100%" style="stop-color:#ec4899;stop-opacity:${CENTER_TEXT_OPACITY}" />
            </linearGradient>
            <filter id="shadow">
              <feDropShadow dx="1" dy="1" stdDeviation="2" flood-opacity="${CENTER_SHADOW_OPACITY}"/>
            </filter>
          </defs>
          <text x="125" y="40" font-family="Arial, sans-serif" font-size="30" font-weight="bold" 
                fill="url(#centerGrad)" text-anchor="middle" filter="url(#shadow)" 
                stroke="rgba(255,255,255,${CENTER_STROKE_OPACITY})" stroke-width="1">
            TOYRENDER.COM
          </text>
          <text x="125" y="60" font-family="Arial, sans-serif" font-size="14" 
                fill="rgba(255,255,255,${CENTER_SUBTITLE_OPACITY})" text-anchor="middle" filter="url(#shadow)">
            FREE TRIAL
          </text>
        </svg>
      `);
    }

    // Apply both watermarks using sharp
    const watermarkedBuffer = await sharp(imageBuffer)
      .composite([
        {
          input: centerWatermarkBuffer,
          gravity: "center",
          blend: "over",
        },
        {
          input: cornerWatermarkSVG,
          gravity: "southeast",
          blend: "over",
        },
      ])
      .toBuffer();

    // Write back to the same file
    await fs.promises.writeFile(imagePath, watermarkedBuffer);

    console.log(
      `Dual watermarks applied successfully to ${path.basename(imagePath)}`
    );
    return true;
  } catch (error) {
    console.error("Error applying watermarks:", error);
    return false;
  }
}

// --- DB schema ---
(async () => {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      verified_at TEXT,
      role TEXT NOT NULL DEFAULT 'user'
    )
  `);
  await run(`
    CREATE TABLE IF NOT EXISTS user_credits (
      user_id INTEGER PRIMARY KEY,
      free_remaining INTEGER NOT NULL DEFAULT 3,
      free_renew_utc TEXT NOT NULL,
      paid_remaining INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
  await run(`
    CREATE TABLE IF NOT EXISTS gen_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      req_id TEXT NOT NULL,
      status TEXT NOT NULL,
      cost INTEGER NOT NULL DEFAULT 1,
      img_hash16 TEXT,
      input_bytes INTEGER,
      ip TEXT,
      ua TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await run(`
  CREATE TABLE IF NOT EXISTS payments (
    id TEXT PRIMARY KEY,            -- Stripe event id (idempotency)
    user_id INTEGER NOT NULL,
    amount INTEGER NOT NULL,        -- cents
    currency TEXT NOT NULL,
    credits_added INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`);
})().catch((e) => {
  console.error("DB init error:", e);
  process.exit(1);
});

// --- Utils ---
const FIGURINE_PROMPT1 = `Create a 1/7 scale commercialized figurine of the characters in the picture, in a realistic style, in a real environment. The figurine is placed on a computer desk. The figurine has a round transparent acrylic base, with no text on the base. The content on the computer screen is a 3D modeling process of this figurine. Next to the computer screen is a toy packaging box, designed in a style reminiscent of high-quality collectible figures, printed with original artwork. The packaging features two-dimensional flat illustrations.`;

function nextUtcMidnightISO() {
  const d = new Date();
  d.setUTCHours(24, 0, 0, 0);
  return d.toISOString().slice(0, 19).replace("T", " ");
}

const MAX_SIZE =
  parseInt(process.env.MAX_FILE_SIZE_MB || "10", 10) * 1024 * 1024;

// Fast 413 guard (prevents waste on huge bodies)
function bodySizeGuard(req, res, next) {
  const len = Number(req.get("content-length") || 0);
  if (len && len > MAX_SIZE) {
    return res.status(413).json({ error: "File too large" });
  }
  next();
}

// --- Robust filename filter ---
const forbiddenPrefixes = [
  "porn",
  "porno",
  "xxx",
  "nsfw",
  "nude",
  "naked",
  "erotic",
  "erotica",
  "explicit",
  "adult",
  "desnudo",
  "desnuda",
  "desnudos",
  "desnudas",
  "erotico",
  "erótico",
  "sexual",
  "sexo",
  "pornografie",
  "nackt",
  "erotik",
  "sex",
  "pornographie",
  "nu",
  "nue",
  "nus",
  "érotique",
  "erotique",
  "sexe",
  "sexuel",
  "nudez",
  "nu",
  "nua",
  "nudo",
  "nuda",
  "nudi",
  "sessuale",
  "sesso",
];

const forbiddenKeywords = [
  "porn",
  "porno",
  "pornography",
  "nsfw",
  "xxx",
  "adult",
  "explicit",
  "lewd",
  "hardcore",
  "softcore",
  "nude",
  "nudes",
  "naked",
  "topless",
  "bottomless",
  "stripper",
  "striptease",
  "sex",
  "sexual",
  "sext",
  "onlyfans",
  "fansly",
  "camgirl",
  "webcam",
  "escort",
  "fetish",
  "bdsm",
  "blowjob",
  "bj",
  "handjob",
  "anal",
  "creampie",
  "cum",
  "cumshot",
  "facial",
  "gangbang",
  "pornografia",
  "pornografía",
  "erotico",
  "erótico",
  "erotica",
  "erótica",
  "desnudo",
  "desnuda",
  "desnudos",
  "desnudas",
  "desnudez",
  "nudez",
  "fetiche",
  "pornografie",
  "nackt",
  "erotik",
  "erotisch",
  "sexuell",
  "sex",
  "pornographie",
  "nu",
  "nue",
  "nus",
  "nues",
  "érotique",
  "erotique",
  "sexe",
  "sexuel",
  "pornografia",
  "nudo",
  "nuda",
  "nudi",
  "nude",
  "erotico",
  "sessuale",
  "sesso",
];

const leetMap = new Map(
  Object.entries({
    0: "o",
    1: "i",
    3: "e",
    4: "a",
    5: "s",
    7: "t",
    8: "b",
    9: "g",
    $: "s",
    "@": "a",
  })
);
function normalizeForCheck(name) {
  const base = (path.parse(name).name || "").toLowerCase();
  let s = base.normalize("NFKD").replace(/[\u0300-\u036f]/g, "");
  s = s.replace(/[01345789$@]/g, (ch) => leetMap.get(ch) || ch);
  s = s.replace(/[_\.\-\+]+/g, " ");
  s = s.replace(/([a-z])\1{2,}/g, "$1$1");
  s = s
    .replace(/[^a-z\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return s;
}
function tokenSet(name) {
  const n = normalizeForCheck(name);
  return new Set(n.split(" ").filter(Boolean));
}
function isForbiddenFilename(original) {
  const trimmed = (original || "").trim().toLowerCase();
  const firstChunk = trimmed.split(/[^a-z0-9]+/i)[0] || "";
  const tokens = tokenSet(original);
  if (forbiddenPrefixes.some((p) => firstChunk.startsWith(p))) return true;
  for (const t of tokens) if (forbiddenKeywords.includes(t)) return true;
  return false;
}

// --- Multer (storage + filters) ---
function tsStampUTC(d = new Date()) {
  const pad = (n) => String(n).padStart(2, "0");
  return (
    d.getUTCFullYear() +
    pad(d.getUTCMonth() + 1) +
    pad(d.getUTCDate()) +
    "-" +
    pad(d.getUTCHours()) +
    pad(d.getUTCMinutes()) +
    pad(d.getUTCSeconds()) +
    "Z"
  );
}

function uploadDest(_, __, cb) {
  const d = new Date();
  const dir = path.join(
    UPLOADS_DIR,
    String(d.getUTCFullYear()),
    String(d.getUTCMonth() + 1).padStart(2, "0"),
    String(d.getUTCDate()).padStart(2, "0")
  );
  fs.mkdir(dir, { recursive: true }, () => cb(null, dir));
}

const upload = multer({
  storage: multer.diskStorage({
    destination: uploadDest, // or: (_, __, cb) => cb(null, uploadsDir)
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      const name =
        `${file.fieldname}-${tsStampUTC()}-` +
        crypto.randomBytes(4).toString("hex") +
        ext;
      cb(null, name);
    },
  }),
  limits: { fileSize: MAX_SIZE },
  fileFilter: (req, file, cb) => {
    const allowedMimes = ["image/jpeg", "image/png", "image/webp"];
    if (!allowedMimes.includes(file.mimetype)) {
      return cb(
        new Error("Invalid file type. Only JPEG, PNG, and WebP are allowed."),
        false
      );
    }
    if (isForbiddenFilename(file.originalname)) {
      return cb(new Error("Filename not allowed."), false);
    }
    cb(null, true);
  },
});

// --- Gemini + backoff ---
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
function parseQuotaViolations(err) {
  const details = err?.error?.details || [];
  const qf = details.find((d) => (d["@type"] || "").includes("QuotaFailure"));
  const viol = qf?.violations || [];
  const ids = viol.map((v) => v.quotaId || "");
  return {
    violations: viol,
    isDaily: ids.some((id) => id.includes("PerDay")),
    isPerMinute: ids.some((id) => id.includes("PerMinute")),
  };
}
function retryDelayMs(err, def = 30000) {
  const details = err?.error?.details || [];
  const ri = details.find((d) => (d["@type"] || "").includes("RetryInfo"));
  const sec = parseInt((ri?.retryDelay || "").match(/(\d+)s/)?.[1] || "", 10);
  return Number.isFinite(sec) ? sec * 1000 : def;
}
async function withBackoff(fn, tries = 2) {
  for (let i = 0; i < tries; i++) {
    try {
      return await fn();
    } catch (e) {
      if (e?.status !== 429) throw e;
      const q = parseQuotaViolations(e);
      if (q.isDaily) {
        const err = new Error("DAILY_QUOTA_EXCEEDED");
        err.status = 429;
        err.reason = "daily";
        throw err;
      }
      await new Promise((r) => setTimeout(r, retryDelayMs(e, 30000)));
    }
  }
  const err = new Error("RATE_LIMITED_AFTER_RETRIES");
  err.status = 429;
  throw err;
}
const modelLimiter = new Bottleneck({ maxConcurrent: 1, minTime: 1500 });

// --- Auth helpers ---
function ensureAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).json({ error: "Auth required" });
}
async function userById(id) {
  return await get("SELECT id, email, role FROM users WHERE id = ?", [id]);
}

// --- Credits ---
const FREE_DAILY_CREDITS = 0; // hard-disable daily bucket
const STARTER_CREDITS = parseInt(process.env.STARTER_CREDITS || "2", 10);

async function consumeCredits(userId, cost = 1) {
  return txn(async () => {
    let uc = await get("SELECT * FROM user_credits WHERE user_id = ?", [
      userId,
    ]);
    if (!uc) {
      // In case the user existed before this change, create a row now with starter credits
      await run(
        "INSERT INTO user_credits (user_id, free_remaining, free_renew_utc, paid_remaining) VALUES (?,?,?,?)",
        [userId, 0, nextUtcMidnightISO(), STARTER_CREDITS]
      );
      uc = await get("SELECT * FROM user_credits WHERE user_id = ?", [userId]);
    }

    if (uc.paid_remaining >= cost) {
      const newPaid = uc.paid_remaining - cost;
      await run(
        "UPDATE user_credits SET paid_remaining=?, updated_at=datetime('now') WHERE user_id=?",
        [newPaid, userId]
      );
      return {
        ok: true,
        source: "paid",
        free_remaining: 0,
        paid_remaining: newPaid,
      };
    }

    // Not enough credits
    return { ok: false };
  });
}

async function refundCredit(userId, amount = 1) {
  await run(
    "UPDATE user_credits SET paid_remaining = paid_remaining + ?, updated_at=datetime('now') WHERE user_id=?",
    [amount, userId]
  );
}

async function isRecentDuplicate(userId, imgHash16) {
  const row = await get(
    "SELECT id FROM gen_events WHERE user_id=? AND img_hash16=? AND created_at >= datetime('now','-6 hours') LIMIT 1",
    [userId, imgHash16]
  );
  return !!row;
}

// --- Rate limiting (global + per-user for /api/generate) ---
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later." },
});
app.use("/api/", apiLimiter);

const perUserGenerateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.MAX_UPLOADS_PER_15M || "12", 10),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    req.session?.userId ? `u:${req.session.userId}` : req.ip,
  message: { error: "Too many uploads. Try again later." },
});
const burstSlowdown = slowDown({
  windowMs: 60 * 1000,
  delayAfter: Math.max(
    1,
    Math.floor((parseInt(process.env.MAX_UPLOADS_PER_15M || "12", 10) * 2) / 3)
  ),
  delayMs: 250,
});

// Limit JSON body size a bit (put before routes)
// app.use(express.json({ limit: "100kb" }));
// app.use(express.urlencoded({ extended: true, limit: "100kb" }));

// Per-route limiter for auth (IP-based)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30, // 30 attempts per 15m per IP (register+login combined)
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Try later." },
});

// Basic “slow down” after a handful of tries
const authSlowdown = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 10, // after 10 hits per window
  delayMs: 250, // add 250ms per extra hit
});

function stripControlChars(s = "") {
  // Remove invisible control chars & trim
  return s.replace(/[\u0000-\u001F\u007F-\u009F]/g, "").trim();
}

function normalizeEmailStrict(emailRaw) {
  const e = stripControlChars(emailRaw).toLowerCase();
  // Don’t remove Gmail dots; keep user expectation intact
  const norm = validator.normalizeEmail(e, {
    gmail_remove_dots: false,
    gmail_convert_googlemaildotcom: true,
    outlookdotcom_remove_subaddress: true,
    yahoo_remove_subaddress: true,
    icloud_remove_subaddress: true,
  });
  if (!norm) return null;
  if (norm.length > 190) return null; // match DB column
  if (!validator.isEmail(norm, { allow_utf8_local_part: true })) return null;
  return norm;
}

// ---- Disposable email detection ----
const punycode = require("punycode/"); // built-in shim; no config needed
let psl = null;
try {
  psl = require("psl");
} catch (_) {
  /* optional */
}

// Normalizes a host and returns its registrable base (eTLD+1).
function registrableDomain(host) {
  const ascii = punycode.toASCII(
    String(host || "")
      .toLowerCase()
      .trim()
  );
  if (!ascii) return "";
  if (psl) {
    const parsed = psl.parse(ascii);
    return parsed.domain || ascii;
  }
  // Fallback (not perfect): handle common 2-level public suffixes
  const parts = ascii.split(".");
  if (parts.length <= 2) return ascii;
  const twoLevel = new Set([
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.jp",
    "co.kr",
    "co.in",
    "co.id",
    "com.br",
    "com.mx",
    "com.tr",
    "com.sg",
  ]);
  const last2 = parts.slice(-2).join(".");
  const last3 = parts.slice(-3).join(".");
  return twoLevel.has(last3) ? last3 : last2;
}

// blocklist (roots only; subdomains will match automatically)
const DISPOSABLE_DOMAINS = new Set([
  // GuerrillaMail family
  "guerrillamail.com",
  "sharklasers.com",
  "grr.la",
  "guerrillamail.de",
  "guerrillamail.org",
  "guerrillamail.net",
  "guerrillamailblock.com",

  // Mailinator
  "mailinator.com",
  "mailinator.net",
  "mailinator.org",
  "mailinator2.com",

  // YOPmail family
  "yopmail.com",
  "yopmail.fr",
  "yopmail.net",
  "cool.fr.nf",
  "jetable.fr.nf",
  "nospam.ze.tc",
  "courriel.fr.nf",
  "moncourrier.fr.nf",

  // 10MinuteMail & friends
  "10minutemail.com",
  "10minutemail.net",
  "10minutemail.co.uk",
  "10minemail.com",
  "10minutemail.org",
  "mvrht.net",

  // Temp-Mail family
  "temp-mail.org",
  "temp-mail.io",
  "temp-mail.com",
  "tempmailo.com",
  "tempmail.email",
  "tempmail.plus",
  "tempmail.net",
  "tempail.com",
  "tempm.com",
  "mail.tm",

  // Nada / DropMail / Mailsac-like
  "getnada.com",
  "nada.ltd",
  "dropmail.me",
  "mailsac.com",

  // Mohmal / Moakt
  "mohmal.com",
  "moakt.com",
  "tmailt.com",
  "tmpmail.org",

  // Dispostable / Maildrop / MailCatch
  "dispostable.com",
  "maildrop.cc",
  "mailcatch.com",
  "mailcatch.co",

  // Mailnesia / MintEmail / MeltMail
  "mailnesia.com",
  "mintemail.com",
  "meltmail.com",

  // Throwaway / Trashmail families
  "throwawaymail.com",
  "trashmail.com",
  "trashmail.de",
  "trashmail.me",
  "trash-mail.com",
  "trashmail.ws",
  "mytrashmail.com",
  "fakeinbox.com",
  "fakeinbox.org",

  // Fakemail generators
  "fakemail.net",
  "fakemailgenerator.com",
  "emailtemporanea.com",
  "emailtemporanee.com",
  "emailtemporario.com.br",
  "tempinbox.com",
  "spam4.me",

  // Spamgourmet & variants
  "spamgourmet.com",
  "spamgourmet.net",
  "antichef.net",
  "dfgh.net",

  // 33mail
  "33mail.com",

  // Harakirimail / Guerrilla-like
  "harakirimail.com",
  "mytemp.email",

  // GetAirMail
  "getairmail.com",
  "airmail.cc",

  // Mohmal alternates
  "mailmoakt.com",
  "bareed.ws",
  "tmpmail.net",

  // Mail7 / TMail
  "mail7.io",
  "tmail.ws",

  // OwlyMail / LinshiMail / Onetime
  "owlymail.com",
  "linshiyouxiang.net",
  "onetime.email",

  // Other common providers seen in abuse lists
  "maildrop.top",
  "yopmail.top",
  "tempr.email",
  "mailpoof.com",
  "anonymbox.com",
  "inboxbear.com",
  "inboxkitten.com",
  "spamdecoy.net",
  "spambog.com",
  "spambog.de",
  "spambog.ru",
  "spambox.us",
  "mohmal.in",
  "echomail.xyz",
  "mailnull.com",
  "mail-temporaire.com",
  "kamdemail.com",
  "dismail.de",
  "mailhub.pro",
]);

// Allow ops to extend at runtime via env
if (process.env.EXTRA_DISPOSABLE_DOMAINS) {
  process.env.EXTRA_DISPOSABLE_DOMAINS.split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
    .forEach((d) => DISPOSABLE_DOMAINS.add(d));
}

// ---- Disposable email check (uses registrableDomain + blocklist) ----
function isDisposable(email) {
  if (!email || typeof email !== "string") return false;
  const at = email.lastIndexOf("@");
  if (at < 0) return false;

  const hostRaw = email
    .slice(at + 1)
    .trim()
    .toLowerCase();
  if (!hostRaw) return false;

  // base registrable, e.g. sub.mailinator.com -> mailinator.com
  const base = registrableDomain(hostRaw);
  if (!base) return false;

  // match root (fast path)
  if (DISPOSABLE_DOMAINS.has(base)) return true;

  // extra safety: if someone listed an exact subdomain in env extension
  if (DISPOSABLE_DOMAINS.has(hostRaw)) return true;

  return false;
}

// Password policy
function checkPassword(pwRaw, email = "") {
  // Don’t trim passwords; users may want leading/trailing spaces; but reject control chars
  const pw = pwRaw.replace(/[\u0000-\u001F\u007F-\u009F]/g, "");
  if (pw.length < 8)
    return { ok: false, err: "Password must be at least 8 characters." };
  if (pw.length > 72) return { ok: false, err: "Password too long (max 72)." }; // bcrypt limit
  const { score } = zxcvbn(pw, [email]);
  if (score < 2)
    return {
      ok: false,
      err: "Password too weak. Use more characters or add words.",
    };
  return { ok: true, pw };
}

async function grantCreditsAfterPayment({
  eventId,
  userId,
  amount,
  currency,
  credits,
}) {
  return txn(async () => {
    // idempotency: skip if this event was already processed
    const already = await get("SELECT 1 FROM payments WHERE id = ?", [eventId]);
    if (already) return { ok: true, deduped: true };

    // ensure the user_credits row exists
    const uc = await get("SELECT 1 FROM user_credits WHERE user_id = ?", [
      userId,
    ]);
    if (!uc) {
      await run(
        "INSERT INTO user_credits (user_id, free_remaining, free_renew_utc, paid_remaining) VALUES (?,?,?,?)",
        [userId, 0, nextUtcMidnightISO(), 0]
      );
    }

    // add credits
    await run(
      "UPDATE user_credits SET paid_remaining = paid_remaining + ?, updated_at = datetime('now') WHERE user_id = ?",
      [credits, userId]
    );

    // record payment
    await run(
      `INSERT INTO payments (id, user_id, amount, currency, credits_added)
       VALUES (?,?,?,?,?)`,
      [eventId, userId, amount, currency, credits]
    );

    return { ok: true };
  });
}

app.post("/api/payments/checkout", ensureAuth, async (req, res) => {
  try {
    if (!process.env.STRIPE_SECRET_KEY)
      throw new Error("Missing STRIPE_SECRET_KEY");
    if (!process.env.STRIPE_PRICE_PRO_PACK)
      throw new Error("Missing STRIPE_PRICE_PRO_PACK");

    const userId = req.session.userId;
    const user = await userById(userId);

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items: [{ price: process.env.STRIPE_PRICE_PRO_PACK, quantity: 1 }],
      customer_email: user.email,

      // keep BOTH for redundancy; you'll read either in webhook/confirm
      client_reference_id: String(userId),
      metadata: {
        userId: String(userId),
        credits: "10",
        package: "pro_pack_10_credits",
      },

      allow_promotion_codes: true,
      billing_address_collection: "auto",
      automatic_tax: { enabled: true },

      // send them to your success endpoint with {CHECKOUT_SESSION_ID}
      success_url: `${BASE_URL}/checkout/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${BASE_URL}/?checkout_status=cancel`,
    });

    res.json({ id: session.id, url: session.url });
  } catch (err) {
    console.error("checkout create error:", err?.message || err);
    res
      .status(500)
      .json({ error: err?.message || "Unable to start checkout." });
  }
});

app.get("/checkout/success", ensureAuth, (req, res) => {
  const sid = (req.query.session_id || "").toString();
  res.send(`
    <!doctype html>
    <meta charset="utf-8">
    <title>Finalizing your credits…</title>
    <body style="font-family:system-ui; color:#e5e7eb; background:#0f172a; text-align:center; padding:40px">
      <h1>🔄 Finalizing your credits…</h1>
      <p>Please wait a moment.</p>
      <script>
        (async () => {
          try {
            const r = await fetch('/api/payments/confirm', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'include',
              body: JSON.stringify({ session_id: ${JSON.stringify(sid)} })
            });
            // ignore response – the next page will fetch fresh credits
          } catch (e) {}
          location.href = '/';
        })();
      </script>
    </body>
  `);
});

app.get("/config.js", (_req, res) => {
  const pk = process.env.STRIPE_PUBLISHABLE_KEY || "";
  res.set("Cache-Control", "public, max-age=300, must-revalidate"); // optional
  res
    .type("application/javascript")
    .send(`window.STRIPE_PK = ${JSON.stringify(pk)};`);
});

// --- Auth routes ---
app.post(
  ["/auth/register", "/api/auth/register"],
  authLimiter,
  authSlowdown,
  async (req, res) => {
    try {
      // Enforce JSON
      if (!/application\/json/i.test(req.headers["content-type"] || "")) {
        return res.status(415).json({ error: "Use application/json" });
      }

      const email = normalizeEmailStrict(req.body?.email || "");
      const pwCheck = checkPassword(
        String(req.body?.password || ""),
        email || ""
      );
      if (!email) return res.status(400).json({ error: "Invalid email" });
      if (isDisposable(email))
        return res.status(400).json({ error: "Disposable email not allowed" });
      if (!pwCheck.ok) return res.status(400).json({ error: pwCheck.err });

      // Prevent user enumeration timing leaks by doing a small fake hash even if user exists
      const existing = await get("SELECT id FROM users WHERE email = ?", [
        email,
      ]);
      if (existing) {
        // Optional: respond 200 to avoid enumeration, but UX is worse.
        // Here we keep 409 and still burn ~bcrypt time for parity.
        await bcrypt.hash("dummyPasswordToNormalizeTiming", 12);
        return res.status(409).json({ error: "Email already registered" });
      }

      const hash = await bcrypt.hash(pwCheck.pw, 12);

      // Transaction: create user + starter credits atomically
      await txn(async () => {
        const r = await run(
          "INSERT INTO users (email, password_hash) VALUES (?,?)",
          [email, hash]
        );
        const userId = r.lastID;

        await run(
          "INSERT INTO user_credits (user_id, free_remaining, free_renew_utc, paid_remaining) VALUES (?,?,?,?)",
          [userId, 0, nextUtcMidnightISO(), STARTER_CREDITS] // “free” unused; we only use paid_remaining
        );

        if (req.session && typeof req.session.regenerate === "function") {
          await new Promise((resolve, reject) =>
            req.session.regenerate((err) => {
              if (err) return reject(err);
              req.session.userId = userId;
              resolve();
            })
          );
        } else if (req.session) {
          req.session.userId = userId;
        } else {
          throw new Error("Session not initialized");
        }
      });

      res
        .status(201)
        .json({ ok: true, user: await userById(req.session.userId) });
    } catch (e) {
      res.status(500).json({ error: e.message || "register failed" });
    }
  }
);

app.post(
  ["/auth/login", "/api/auth/login"],
  authLimiter,
  authSlowdown,
  async (req, res) => {
    try {
      if (!/application\/json/i.test(req.headers["content-type"] || "")) {
        return res.status(415).json({ error: "Use application/json" });
      }
      const email = normalizeEmailStrict(req.body?.email || "");
      const password = String(req.body?.password || "").replace(
        /[\u0000-\u001F\u007F-\u009F]/g,
        ""
      );
      if (!email || !password)
        return res.status(400).json({ error: "email and password required" });

      const user = await get("SELECT * FROM users WHERE email = ?", [email]);
      // Compare with a dummy hash to normalize timing if user not found
      const hash =
        user?.password_hash ||
        "$2b$12$C2wI3ipYv9a7dZlXf5sA3eVn0vU2gkTFQH/2K4kR0fF6qS9sC8F7y"; // random valid bcrypt
      const ok = await bcrypt.compare(password, hash);
      if (!user || !ok)
        return res.status(401).json({ error: "Invalid credentials" });

      if (req.session && typeof req.session.regenerate === "function") {
        await new Promise((resolve, reject) =>
          req.session.regenerate((err) => {
            if (err) return reject(err);
            req.session.userId = user.id; // <-- login uses user.id
            resolve();
          })
        );
      } else if (req.session) {
        req.session.userId = user.id;
      } else {
        throw new Error("Session not initialized");
      }

      res.json({ ok: true, user: await userById(req.session.userId) });
    } catch (e) {
      res.status(500).json({ error: e.message || "login failed" });
    }
  }
);

app.post(["/auth/logout", "/api/auth/logout"], (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get(["/auth/me", "/api/auth/me"], async (req, res) => {
  res.set("Cache-Control", "no-store"); // <— add this

  if (!req.session?.userId)
    return res.json({ ok: true, user: null, credits: { remaining: 0 } });

  const user = await userById(req.session.userId);
  const uc = await get(
    "SELECT paid_remaining FROM user_credits WHERE user_id=?",
    [req.session.userId]
  );

  return res.json({
    ok: true,
    user,
    credits: { remaining: uc ? uc.paid_remaining : 0 },
  });
});

// --- Probe route ---
app.get("/api/probe", async (_req, res) => {
  try {
    const r = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: [{ role: "user", parts: [{ text: "ping" }] }],
    });
    res.json({ ok: true, message: "probe ok" });
  } catch (e) {
    res
      .status(e?.status || 500)
      .json({ ok: false, error: e?.message || "probe failed" });
  }
});

// --- Generate route ---
// Modify the /api/generate endpoint (around line 1100-1200)
// Replace the existing endpoint with this updated version:

app.post(
  "/api/generate",
  ensureAuth,
  burstSlowdown,
  perUserGenerateLimiter,
  bodySizeGuard,
  upload.single("photo"),
  async (req, res) => {
    const userId = req.session.userId;
    // Get user email for logging
    let userEmail = "unknown";
    try {
      const user = await get("SELECT email FROM users WHERE id = ?", [userId]);
      if (user) {
        userEmail = user.email;
      }
    } catch (dbError) {
      console.error("Error fetching user email for logging:", dbError);
    }

    const reqId =
      (crypto.randomUUID && crypto.randomUUID()) ||
      Date.now() + "-" + Math.random().toString(16).slice(2);
    const t0 = Date.now();
    let inputPath = null;

    try {
      if (!req.file) return res.status(400).json({ error: "No file uploaded" });
      inputPath = req.file.path;

      // read + hash early
      const raw = fs.readFileSync(inputPath);
      const imgHash16 = crypto
        .createHash("sha256")
        .update(raw)
        .digest("hex")
        .slice(0, 16);

      // deny recent dup (do not spend credit)
      if (await isRecentDuplicate(userId, imgHash16)) {
        fs.unlink(inputPath, () => {});
        return res
          .status(429)
          .json({ error: "Duplicate image detected. Try a different photo." });
      }

      // consume one credit
      const credit = await consumeCredits(userId, 1);
      if (!credit.ok) {
        fs.unlink(inputPath, () => {});
        return res.status(402).json({
          error: "Out of credits",
          retryAfterSec: credit.retryAfterSec,
          message: "Upgrade or wait until tomorrow.",
        });
      }

      // Check if this was a free credit (for watermarking decision)
      // Since you're using STARTER_CREDITS in paid_remaining, we need to track differently
      // Get current user credits to determine if they have purchased credits
      const userCredits = await get(
        "SELECT paid_remaining FROM user_credits WHERE user_id = ?",
        [userId]
      );

      // Check if user has made any payments
      const hasPayments = await get(
        "SELECT id FROM payments WHERE user_id = ? LIMIT 1",
        [userId]
      );

      // User is on free trial if they have no payment history and only starter credits
      const isFreeTrial =
        !hasPayments && userCredits.paid_remaining <= STARTER_CREDITS;

      // Log start
      await run(
        "INSERT INTO gen_events (user_id, req_id, status, img_hash16, input_bytes, ip, ua) VALUES (?,?,?,?,?,?,?)",
        [
          userId,
          reqId,
          "started",
          imgHash16,
          req.file.size,
          req.ip,
          (req.get("user-agent") || "").slice(0, 255),
        ]
      );

      // metadata (best-effort)
      let meta = {};
      try {
        meta = await sharp(raw).metadata();
      } catch {}

      // resize/compress
      let resizedBuf = raw;
      try {
        resizedBuf = await sharp(raw)
          .resize({
            width: 1280,
            height: 1280,
            fit: "inside",
            withoutEnlargement: true,
          })
          .jpeg({ quality: 80 })
          .toBuffer();
      } catch (e) {
        console.warn("sharp failed; using original:", e.message);
      }

      const prompt =
        (req.body.prompt && String(req.body.prompt).trim()) || FIGURINE_PROMPT1;
      const parts = [
        { text: prompt },
        {
          inlineData: {
            mimeType: "image/jpeg",
            data: resizedBuf.toString("base64"),
          },
        },
      ];

      // Model call with throttle + backoff
      const response = await modelLimiter.schedule(() =>
        withBackoff(() =>
          ai.models.generateContent({
            model: "gemini-2.5-flash-image-preview",
            contents: [{ role: "user", parts }],
          })
        )
      );

      // Extract outputs
      const cand = response?.candidates?.[0]?.content?.parts || [];
      let outImagePath = null;
      let outText = "";
      for (const part of cand) {
        if (part.text) outText += part.text + "\n";
        else if (part.inlineData?.data) {
          const buffer = Buffer.from(part.inlineData.data, "base64");
          const fname = `gemini-output-${Date.now()}.png`;
          outImagePath = path.join(RESULTS_DIR, fname);
          fs.writeFileSync(outImagePath, buffer);

          // APPLY WATERMARK FOR FREE TRIAL USERS
          if (isFreeTrial && outImagePath) {
            console.log(`Applying watermark for free trial user: ${userEmail}`);
            try {
              await applyWatermark(outImagePath);
              console.log(`Watermark applied successfully to ${fname}`);
            } catch (watermarkError) {
              console.error(
                `Failed to apply watermark to ${fname}:`,
                watermarkError
              );
              // Continue even if watermark fails - don't break the user experience
            }
          }
        }
      }

      // Log success
      await run("UPDATE gen_events SET status='success' WHERE req_id=?", [
        reqId,
      ]);

      // stream log
      const logData = {
        event: "gen_success",
        reqId,
        duration_ms: Date.now() - t0,
        userEmail: userEmail,
        output: {
          image: outImagePath ? path.basename(outImagePath) : null,
          text_len: outText.trim().length,
          watermarked: isFreeTrial, // Log whether image was watermarked
        },
        file: {
          name: req.file.originalname,
          savedAs: req.file.filename,
          mimetype: req.file.mimetype,
          size: req.file.size,
          format: meta.format || null,
          width: meta.width || null,
          height: meta.height || null,
        },
        user_id: userId,
        is_free_trial: isFreeTrial,
      };
      logGen(logData);

      return res.json({
        ok: true,
        text: outText.trim(),
        imageUrl: outImagePath
          ? "/results/" + path.basename(outImagePath)
          : null,
        watermarked: isFreeTrial, // Let frontend know if image was watermarked
      });
    } catch (e) {
      // refund on failure
      try {
        await run("UPDATE gen_events SET status='error' WHERE req_id=?", [
          reqId,
        ]);
      } catch {}
      try {
        await refundCredit(userId, 1);
      } catch {}
      console.error("Generation error:", e?.message || e);

      // Log error
      logGen({
        event: "gen_error",
        reqId,
        duration_ms: Date.now() - t0,
        userEmail: userEmail,
        error: { message: e?.message || "Unknown error" },
        user_id: userId,
      });

      return res.status(e?.status || 500).json({
        ok: false,
        status: e?.status || 500,
        error: e?.message || "Generation failed",
        reason: e?.reason || null,
        details: e?.error?.details || null,
      });
    } finally {
      // if (inputPath) fs.unlink(inputPath, () => {}); // disk hygiene: always remove upload
    }
  }
);

// --- Hourly cleanup of old files ---
const RETENTION_H = parseInt(process.env.UPLOAD_RETENTION_HOURS || "24", 10);
function cleanupDir(dir) {
  const cutoff = Date.now() - RETENTION_H * 3600 * 1000;
  try {
    for (const f of fs.readdirSync(dir)) {
      const p = path.join(dir, f);
      try {
        const st = fs.statSync(p);
        if (st.isFile() && st.mtimeMs < cutoff) fs.unlinkSync(p);
      } catch {}
    }
  } catch {}
}
setInterval(() => {
  cleanupDir(UPLOADS_DIR);
  cleanupDir(RESULTS_DIR);
}, 60 * 60 * 1000);

// --- Catch-all (serve SPA) ---
app.get("*", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

// --- Server ---
const server = app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log("Public dir:", PUBLIC_DIR);
  console.log("Uploads dir:", UPLOADS_DIR);
  console.log("Results dir:", RESULTS_DIR);
});
server.requestTimeout = 300000;
server.headersTimeout = 320000;
