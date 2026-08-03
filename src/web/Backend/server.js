// SPDX-License-Identifier: MIT
// Basic Express entrypoint for TsarChain web explorer backend

const path = require("node:path");
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
require("dotenv").config({ path: path.join(__dirname, ".env") });

const { getConfig } = require("./src/config/env");
const { createRateLimiter } = require("./src/utils/rateLimit");
const explorerRouter = require("./src/routes/explorer_routes");
const healthRouter = require("./src/routes/health");

const app = express();
app.set('trust proxy', true);
app.disable('x-powered-by');

const cfg = getConfig();
const allowedOrigins = cfg.allowedOrigins || ['http://localhost:3000'];

const corsOptions = {
  origin: function (origin, callback) {
    if (origin == null) {
      return callback(null, true);
    }

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS policy: Domain ini tidak diizinkan!'));
    }
  },
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

app.use(bodyParser.json());

const apiLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 120 });
app.use("/api", apiLimiter);

app.use("/api", healthRouter);
app.use("/api", explorerRouter);

app.use((err, _req, res, _next) => {
  // Fallback error handler so the client always gets JSON.
  console.error("[backend] unhandled error", err);
  res.status(500).json({ error: "internal_error", detail: err?.message || "Unexpected error" });
});

const server = app.listen(cfg.port, cfg.host, () => {
  console.log(`[backend] explorer API listening on ${cfg.host}:${cfg.port}`);
});

server.on("error", (err) => {
  if (err.code === "EADDRNOTAVAIL" || err.code === "EINVAL") {
    console.warn(`[backend] binding to ${cfg.host} failed (${err.code}), falling back to 0.0.0.0`);
    app.listen(cfg.port, "0.0.0.0");
  }
});
