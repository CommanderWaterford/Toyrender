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
const rateLimit = require("express-rate-limit");
const { GoogleGenerativeAI } = require("@google/generative-ai");
const { GoogleGenAI, Modality } = require("@google/genai");

// --- App Initialization ---
const app = express();
const PORT = process.env.PORT || 3060;

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
app.use(express.static(path.join(__dirname, "public")));

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
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// Helper function
function fileToGenerativePart(buffer, mimeType) {
  return {
    inlineData: {
      data: buffer.toString("base64"),
      mimeType,
    },
  };
}

// --- API Routes (IMPORTANT: Must come BEFORE catch-all route) ---
app.post("/api/generate", upload.single("photo"), async (req, res) => {
  console.log("=== /api/generate POST received ===");
  console.log(
    "Initializing Gemini with key:",
    process.env.GEMINI_API_KEY ? "Key present" : "KEY MISSING!"
  );

  if (!req.file) {
    console.log("No file in request");
    return res.status(400).json({ error: "No file uploaded" });
  }

  const inputPath = req.file.path;
  console.log("File received:", req.file.filename);
  // console.log("GEMINI_API_KEY:", process.env.GEMINI_API_KEY);

  try {
    // Initialize the Gemini model for image generation
    const model = new GoogleGenAI({});

    // Create a prompt for figurine generation
    // You can customize this prompt based on user preferences
    const prompt = `Create a high-quality, 1:7 scale collectible figurine in a clean studio setting. 
                    The figurine should be standing on a simple circular display base. 
                    Professional product photography style with soft lighting, 
                    detailed 3D render appearance, photorealistic quality. 
                    Anime/manga collectible figurine style.`;

    console.log("Sending request to Gemini API...");

    // Generate the image
    // const result = await model.generateContent(prompt);
    const response = await model.generateContent({
      model: "gemini-2.5-flash-image-preview",
      contents: prompt,
    });

    for (const part of response.candidates[0].content.parts) {
      if (part.text) {
        console.log(part.text);
      } else if (part.inlineData) {
        const imageData = part.inlineData.data;
        const buffer = Buffer.from(imageData, "base64");
        fs.writeFileSync("gemini-native-image.png", buffer);
        console.log("Image saved as gemini-native-image.png");
      }
    }

    // Check if response has candidates with content
    if (
      response.candidates &&
      response.candidates[0] &&
      response.candidates[0].content
    ) {
      for (const part of response.candidates[0].content.parts) {
        if (part.inlineData) {
          imageData = part.inlineData.data;
          break;
        }
      }
    }

    // Return the URL
    const resultUrl = `/results/${outputFilename}`;
    console.log("Sending response:", { imageUrl: resultUrl });

    res.json({ imageUrl: resultUrl });
  } catch (error) {
    console.error("Gemini API Error:", error);

    // Clean up uploaded file on error
    if (fs.existsSync(inputPath)) {
      fs.unlinkSync(inputPath);
    }

    // Provide detailed error message
    let errorMessage = "Failed to generate image.";
    if (error.message) {
      errorMessage += " " + error.message;
    }
    if (error.response) {
      errorMessage += " API Response: " + JSON.stringify(error.response);
    }

    return res.status(500).json({ error: errorMessage });
  }
});

// --- Test Route ---
app.get("/api/test", (req, res) => {
  res.json({ message: "API is working!" });
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
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
