import 'dotenv/config';
import express, { Request, Response } from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import { createServer as createViteServer } from "vite";
import dotenv from "dotenv";

import authRoutes from "./src/backend/routes/authRoutes.ts";
import aadhaarRoutes from "./src/backend/routes/aadhaarRoutes.ts";
import digilockerRoutes from "./src/backend/routes/digilockerRoutes.ts";
import userRoutes from "./src/backend/routes/userRoutes.ts";
import documentRoutes from "./src/backend/routes/documentRoutes.ts";
import schemeRoutes from "./src/backend/routes/schemeRoutes.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables
dotenv.config({ path: path.resolve(__dirname, "../.env") });
dotenv.config();

export async function createApp() {
  // Create Express application
  const app = express();

  const PORT = Number(process.env.PORT) || 3000;

  // -------------------------------------------------------------
  // MIDDLEWARE
  // -------------------------------------------------------------

  app.use(
    cors({
      origin: true,
      credentials: true,
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    })
  );

  app.use(express.json({ limit: "15mb" }));
  app.use(express.urlencoded({ extended: true, limit: "15mb" }));

  // -------------------------------------------------------------
  // API ROUTES
  // -------------------------------------------------------------

  app.use("/api/auth", authRoutes);

  app.use("/api/aadhaar", aadhaarRoutes);

  app.use("/api/digilocker", digilockerRoutes);

  app.use("/api/users", userRoutes);

  // DOCUMENT ROUTES
  app.use("/api/documents", documentRoutes);

  app.use("/api/schemes", schemeRoutes);

  // -------------------------------------------------------------
  // HEALTH CHECK
  // -------------------------------------------------------------

  app.get("/api/health", (_req: Request, res: Response) => {
    res.status(200).json({
      status: "operational",
      service: "AI Citizen Benefit Assistant Backend",
      timestamp: new Date().toISOString(),
    });
  });

  // -------------------------------------------------------------
  // VITE / STATIC FILE SERVING
  // -------------------------------------------------------------

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      root: __dirname,
      configFile: path.join(__dirname, "vite.config.ts"),
      server: {
        middlewareMode: true,
      },
      appType: "spa",
    });

    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, "dist");

    app.use(express.static(distPath));

    app.get("*", (_req: Request, res: Response) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  return app;
}

// -------------------------------------------------------------
// START SERVER
// -------------------------------------------------------------

if (!process.env.VERCEL) {
  createApp().then((app) => {
    const PORT = Number(process.env.PORT) || 3000;

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on http://localhost:${PORT}`);
      console.log(`Document API: http://localhost:${PORT}/api/documents`);
    });
  });
}