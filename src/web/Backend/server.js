// SPDX-License-Identifier: MIT
// Basic Express entrypoint for TsarChain web explorer backend

const path = require("node:path");
const express = require("express");
const cors = require("cors");
require("dotenv").config({ path: path.join(__dirname, ".env") });

const { getConfig } = require("./src/config/env");
const { createRateLimiter } = require("./src/utils/rateLimit");
const explorerRouter = require("./src/routes/explorer_routes");
const healthRouter = require("./src/routes/health");

const app = express();
app.set('trust proxy', process.env.TRUST_PROXY || 'loopback');
app.disable('x-powered-by');

const cfg = getConfig();
const allowedOrigins = cfg.allowedOrigins || ['http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:5173'];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(null, false);
  },
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "10mb" }));

const apiLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 120 });
app.use("/api", apiLimiter);

app.use("/api", healthRouter);
app.use("/api", explorerRouter);

app.use((err, _req, res, _next) => {
  // Fallback error handler so the client always gets JSON.
  console.error("[backend] unhandled error", err);
  res.status(500).json({ error: "internal_error", detail: err?.message || "Unexpected error" });
});

const http = require("node:http");
const server = http.createServer(app);

server.on("error", (err) => {
  if (err.code === "EADDRNOTAVAIL" || err.code === "EINVAL") {
    console.warn(`[backend] binding to ${cfg.host} failed (${err.code}), retrying on 0.0.0.0:${cfg.port}`);
    server.close(() => {
      server.listen(cfg.port, "0.0.0.0");
    });
  } else {
    console.error("[backend] server listen error:", err);
  }
});

server.listen({
  port: cfg.port,
  host: cfg.host,
}, () => {
  console.log(`[backend] explorer API listening on ${cfg.host}:${cfg.port}`);
});
