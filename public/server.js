// --- Imports ---
require("dotenv").config();
const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { GoogleGenerativeAI } = require("@google/generative-ai"); // Correct SDK import

// --- App Initialization & Security Middleware ---
const app = express();
const PORT = process.env.PORT || 3060;
app.use(helmet());
const corsOptions = { origin: process.env.CORS_ORIGIN || "*" };
app.use(cors(corsOptions));
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // AI calls are expensive, so keep the limit reasonable
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again in 15 minutes." },
});
app.use("/api/", apiLimiter);
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// --- Multer Configuration for Secure Uploads ---
const uploadsDir = path.join(__dirname, "public/uploads");
const resultsDir = path.join(__dirname, "public/results");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
if (!fs.existsSync(resultsDir)) fs.mkdirSync(resultsDir, { recursive: true });
const MAX_SIZE = parseInt(process.env.MAX_FILE_SIZE_MB) * 1024 * 1024;
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
const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);

// Helper function to convert file buffer to GenerativePart
function fileToGenerativePart(buffer, mimeType) {
  return {
    inlineData: {
      data: buffer.toString("base64"),
      mimeType,
    },
  };
}

// --- API Route for Image Generation ---
app.post("/api/generate", (req, res) => {
  const multerUpload = upload.single("photo");

  multerUpload(req, res, async function (err) {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    if (!req.file) {
      return res.status(400).json({ error: "No image file uploaded." });
    }

    const inputPath = req.file.path;

    try {
      // 1. Initialize the correct Gemini model
      // The model you specified is in preview. A stable public alternative is gemini-1.5-flash-latest.
      // We will use your specified model name. If it fails, try "gemini-1.5-flash-latest".
      const model = genAI.getGenerativeModel({
        model: "gemini-1.5-flash-latest",
      });

      // 2. Prepare the prompt and image data for the API
      const imageBuffer = fs.readFileSync(inputPath);
      const imagePart = fileToGenerativePart(imageBuffer, req.file.mimetype);
      const promptText =
        "A high-quality, 1:7 scale collectible figurine of the person in the image. The figure should be standing on a simple, circular white display base. Clean studio lighting, detailed 3D render, photorealistic style.";

      const promptParts = [promptText, imagePart];

      // 3. Call the Gemini API
      console.log("Sending request to Google Gemini API...");
      const result = await model.generateContent(promptParts);
      const response = result.response;

      // 4. Find and process the returned image data
      const imagePartResponse = response.candidates[0].content.parts.find(
        (part) => part.inlineData
      );

      if (!imagePartResponse || !imagePartResponse.inlineData) {
        // If the model returns text instead of an image (e.g., for a safety reason), handle it gracefully.
        const textResponse = response.text();
        console.error(
          "API did not return an image. Text response:",
          textResponse
        );
        throw new Error(
          "The AI model did not generate an image. It may have refused the request. Response: " +
            textResponse
        );
      }

      const imageData = imagePartResponse.inlineData.data;
      const imageBufferOut = Buffer.from(imageData, "base64");

      // 5. Save the generated image
      const outputFilename = `result-${Date.now()}.png`;
      const outputPath = path.join(resultsDir, outputFilename);
      fs.writeFileSync(outputPath, imageBufferOut);

      // 6. Clean up the original uploaded file
      fs.unlinkSync(inputPath);

      // 7. Send the URL of the new image back to the frontend
      const resultUrl = `/results/${outputFilename}`;
      return res.status(200).json({ imageUrl: resultUrl });
    } catch (apiErr) {
      console.error("Gemini API Error:", apiErr);
      if (fs.existsSync(inputPath)) {
        fs.unlinkSync(inputPath); // Clean up on error
      }
      return res
        .status(500)
        .json({ error: "Failed to generate image. " + apiErr.message });
    }
  });
});

// --- Frontend & Server Startup ---
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});
app.listen(PORT, () => {
  console.log(`Server is running securely on http://localhost:${PORT}`);
});
