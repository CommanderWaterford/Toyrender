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
const { GoogleGenAI } = require("@google/genai");

// --- App init ---
const app = express();
const PORT = parseInt(process.env.PORT || "3060", 10);
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
function logGen(obj) {
  try {
    obj.ts = new Date().toISOString();
    genLogStream.write(JSON.stringify(obj) + "\n");
  } catch {}
}
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
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
      const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
      cb(null, file.fieldname + "-" + unique + path.extname(file.originalname));
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

// --- Auth routes ---
app.post(["/auth/register", "/api/auth/register"], async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ error: "email and password required" });

    const existing = await get("SELECT id FROM users WHERE email = ?", [
      email.toLowerCase(),
    ]);
    if (existing)
      return res.status(409).json({ error: "Email already registered" });

    const hash = await bcrypt.hash(password, 12);
    const r = await run(
      "INSERT INTO users (email, password_hash) VALUES (?,?)",
      [email.toLowerCase(), hash]
    );
    const userId = r.lastID;

    // Create credits row: no daily free, only starter "paid" credits
    await run(
      "INSERT INTO user_credits (user_id, free_remaining, free_renew_utc, paid_remaining) VALUES (?,?,?,?)",
      [userId, 0, nextUtcMidnightISO(), STARTER_CREDITS] // free bucket is unused (0); renew_at kept to satisfy NOT NULL
    );

    req.session.userId = userId;
    return res.json({ ok: true, user: await userById(userId) });
  } catch (e) {
    return res.status(500).json({ error: e.message || "register failed" });
  }
});

app.post(["/auth/login", "/api/auth/login"], async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password)
      return res.status(400).json({ error: "email and password required" });
    const user = await get("SELECT * FROM users WHERE email = ?", [
      email.toLowerCase(),
    ]);
    if (!user) return res.status(401).json({ error: "Invalid credentials" });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });
    req.session.userId = user.id;
    return res.json({ ok: true, user: await userById(user.id) });
  } catch (e) {
    return res.status(500).json({ error: e.message || "login failed" });
  }
});

app.post(["/auth/logout", "/api/auth/logout"], (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get(["/auth/me", "/api/auth/me"], async (req, res) => {
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
app.post(
  "/api/generate",
  ensureAuth,
  burstSlowdown,
  perUserGenerateLimiter,
  bodySizeGuard,
  upload.single("photo"),
  async (req, res) => {
    const userId = req.session.userId;
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
        }
      }

      // Log success
      await run("UPDATE gen_events SET status='success' WHERE req_id=?", [
        reqId,
      ]);

      // stream log
      logGen({
        event: "gen_success",
        reqId,
        duration_ms: Date.now() - t0,
        output: {
          image: outImagePath ? path.basename(outImagePath) : null,
          text_len: outText.trim().length,
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
      });

      return res.json({
        ok: true,
        text: outText.trim(),
        imageUrl: outImagePath
          ? "/results/" + path.basename(outImagePath)
          : null,
      });
    } catch (e) {
      // refund on failure
      try {
        await run("UPDATE gen_events SET status='error' WHERE req_id=?", [
          reqId,
        ]);
      } catch {}
      try {
        await refundCredit(userId, 1, "free");
      } catch {}
      console.error("Generation error:", e?.message || e);
      return res.status(e?.status || 500).json({
        ok: false,
        status: e?.status || 500,
        error: e?.message || "Generation failed",
        reason: e?.reason || null,
        details: e?.error?.details || null,
      });
    } finally {
      if (inputPath) fs.unlink(inputPath, () => {}); // disk hygiene: always remove upload
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
