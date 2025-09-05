// --- Imports ---
require("dotenv").config({ path: "/var/www/toyrender.com/.env" });
console.log(
  "API Key loaded:",
  process.env.GEMINI_API_KEY
    ? "Yes (length: " + process.env.GEMINI_API_KEY.length + ")"
    : "No"
);

const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const helmet = require("helmet");
const crypto = require("crypto");
const sharp = require("sharp");
const rateLimit = require("express-rate-limit");
const Bottleneck = require("bottleneck"); // keep if not already required at top
const limiter = new Bottleneck({ maxConcurrent: 1, minTime: 1500 });
const FIGURINE_PROMPT1 = `Create a 1/7 scale commercialized figurine of the characters in the picture, in a realistic style, in a real environment. The figurine is placed on a computer desk. The figurine has a round transparent acrylic base, with no text on the base. The content on the computer screen is a 3D modeling process of this figurine. Next to the computer screen is a toy packaging box, designed in a style reminiscent of high-quality collectible figures, printed with original artwork. The packaging features two-dimensional flat illustrations.`;

const { GoogleGenAI } = require("@google/genai");

// --- App Initialization ---
const app = express();
const PORT = process.env.PORT || 3060;

app.set("trust proxy", 1);

// --- Security Middleware (Modified for proper static file serving) ---
app.use(
  helmet({
    contentSecurityPolicy: false, // Disable CSP for now to avoid blocking scripts
  })
);

const corsOptions = {
  origin: process.env.CORS_ORIGIN || "*",
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type"],
};
app.use(cors(corsOptions));

function parseQuotaViolations(err) {
  const details = err?.error?.details || [];
  const qf = details.find((d) => (d["@type"] || "").includes("QuotaFailure"));
  const viol = qf?.violations || [];
  const ids = viol.map((v) => v.quotaId || "");
  return {
    violations: viol,
    isDaily: ids.some((id) => id.includes("PerDay")),
    isPerMinute: ids.some((id) => id.includes("PerMinutePerProjectPerModel")),
    isInputTokensPerMinute: ids.some((id) =>
      id.toLowerCase().includes("inputtokenspermodelperminute")
    ),
  };
}

function retryDelayMs(err, def = 30000) {
  const details = err?.error?.details || [];
  const ri = details.find((d) => (d["@type"] || "").includes("RetryInfo"));
  const sec = parseInt((ri?.retryDelay || "").match(/(\d+)s/)?.[1] || "", 10);
  return Number.isFinite(sec) ? sec * 1000 : def;
}

// Retry ONLY when it's a per-minute issue; bail fast on daily cap
async function withBackoff(fn, tries = 2) {
  for (let i = 0; i < tries; i++) {
    try {
      return await fn();
    } catch (e) {
      if (e?.status !== 429) throw e;
      const q = parseQuotaViolations(e);
      console.warn("429 quota:", q);
      if (q.isDaily) {
        // daily cap can't be retried
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
// --- Rate Limiting ---
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again in 15 minutes." },
});

// Apply rate limiter ONLY to API routes
app.use("/api/", apiLimiter);

// --- Body Parser ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- Static Files (IMPORTANT: Must come BEFORE API routes) ---
// app.use(express.static(path.join(__dirname, "public")));
app.use(express.static(path.join(__dirname)));

// --- Multer Configuration ---
// Debug first - add this at the top of your server file
console.log("Current directory:", __dirname);
console.log("Process CWD:", process.cwd());
const publicDir = __dirname; // Already in public
const uploadsDir = path.join(publicDir, "uploads");
const resultsDir = path.join(publicDir, "results");

if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
if (!fs.existsSync(resultsDir)) fs.mkdirSync(resultsDir, { recursive: true });

const MAX_SIZE = parseInt(process.env.MAX_FILE_SIZE_MB || 10) * 1024 * 1024;
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => {
      const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
      cb(
        null,
        file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname)
      );
    },
  }),
  limits: { fileSize: MAX_SIZE },
  fileFilter: (req, file, cb) => {
    const allowedMimes = ["image/jpeg", "image/png", "image/webp"];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(
        new Error("Invalid file type. Only JPEG, PNG, and WebP are allowed."),
        false
      );
    }
  },
});

// --- Google Gemini AI Initialization ---
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

console.log(
  "GEMINI_KEY_SHA256_8:",
  crypto
    .createHash("sha256")
    .update(process.env.GEMINI_API_KEY || "")
    .digest("hex")
    .slice(0, 8)
);

// Helper function
function fileToGenerativePart(buffer, mimeType) {
  return {
    inlineData: {
      data: buffer.toString("base64"),
      mimeType,
    },
  };
}

function timeout(ms) {
  return new Promise((_, rej) =>
    setTimeout(() => rej(new Error("Request timed out")), ms)
  );
}

// --- API Routes (IMPORTANT: Must come BEFORE catch-all route) ---
app.post("/api/generate", upload.single("photo"), async (req, res) => {
  console.log("=== /api/generate POST received ===");

  if (!req.file) {
    console.log("No file in request");
    return res.status(400).json({ error: "No file uploaded" });
  }

  try {
    // ⭐ CHANGE: use the uploaded file (not Example1.jpg) and downscale to cut input-tokens/min

    const inputPath = req.file.path;
    const raw = fs.readFileSync(inputPath);

    // Try to use sharp; if unavailable, fall back to original bytes
    let resizedBuf = raw;
    try {
      // lazy require guards against “sharp is not defined” if the top import didn’t load
      const s = sharp || require("sharp");
      resizedBuf = await s(raw)
        .resize({
          width: 1280,
          height: 1280,
          fit: "inside",
          withoutEnlargement: true,
        })
        .jpeg({ quality: 80 })
        .toBuffer();
    } catch (e) {
      console.warn(
        "sharp unavailable/failed, using original image:",
        e.message
      );
    }

    // ⭐ CHANGE: correct mime → we produced JPEG

    const prompt =
      (req.body.prompt && req.body.prompt.trim()) || FIGURINE_PROMPT1;

    const parts = [
      { text: prompt },
      {
        inlineData: {
          mimeType: "image/jpeg",
          data: resizedBuf.toString("base64"),
        },
      },
    ];

    // ⭐ CHANGE: call model with throttle + backoff; send a JSON response
    const response = await limiter.schedule(() =>
      withBackoff(() =>
        ai.models.generateContent({
          model: "gemini-2.5-flash-image-preview",
          contents: [{ role: "user", parts }],
        })
      )
    );

    // Handle response (text or generated image)
    const cand = response?.candidates?.[0]?.content?.parts || [];
    let outImagePath = null;
    let outText = "";

    for (const part of cand) {
      if (part.text) outText += part.text + "\n";
      else if (part.inlineData?.data) {
        const buffer = Buffer.from(part.inlineData.data, "base64");
        const fname = `gemini-output-${Date.now()}.png`;
        outImagePath = path.join(resultsDir, fname);
        fs.writeFileSync(outImagePath, buffer);
      }
    }

    return res.json({
      ok: true,
      text: outText.trim(),
      imageUrl: outImagePath ? "/results/" + path.basename(outImagePath) : null,
    });
  } catch (e) {
    console.error("Generation error:", e?.message || e);
    // Pass through 429 so the client can show a clear message
    return res.status(e?.status || 500).json({
      ok: false,
      status: e?.status || 500,
      error: e?.message || "Generation failed",
      reason: e?.reason || null, // "daily" when daily cap
      details: e?.error?.details || null,
    });
  }
});

app.get("/api/probe-image", async (_req, res) => {
  try {
    // 1x1 transparent PNG
    const onePx =
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNgYAAAAAMAASsJTYQAAAAASUVORK5CYII=";

    const r = await ai.models.generateContent({
      model: "gemini-2.5-flash-image-preview",
      contents: [
        {
          role: "user",
          parts: [
            { text: "Generate a tiny sticker-style icon based on this pixel." },
            { inlineData: { mimeType: "image/png", data: onePx } },
          ],
        },
      ],
    });

    res.json({
      ok: true,
      got_candidates: Array.isArray(r?.candidates),
    });
  } catch (e) {
    res.status(e?.status || 500).json({
      ok: false,
      status: e?.status || 500,
      error: e?.message || "probe-image failed",
      details: e?.error?.details || null,
    });
  }
});

// --- Test Route ---
app.get("/api/probe", async (_req, res) => {
  try {
    const r = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: [{ role: "user", parts: [{ text: "ping" }] }],
    });
    res.json({ ok: true, message: "probe ok" });
  } catch (e) {
    res.status(e?.status || 500).json({
      ok: false,
      status: e?.status,
      error: e?.message,
      details: e?.error?.details || null,
    });
  }
});

// --- Catch-all route (MUST be LAST) ---
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// --- Error Handling Middleware ---
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something went wrong!" });
});

// --- Server Startup ---
const server = app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
server.requestTimeout = 300000; // 300s
server.headersTimeout = 320000; // a bit higher than requestTimeout
