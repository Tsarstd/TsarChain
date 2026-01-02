const fs = require("fs");
const path = require("path");
const router = require("express").Router();
const { ExplorerService } = require("../services/explorerService");
const { getConfig } = require("../config/env");
const { createRateLimiter } = require("../utils/rateLimit");
const { guessKind } = require("../utils/searchKind");

const cfg = getConfig();
const svc = new ExplorerService({ nodeHost: cfg.nodeHost, nodePort: cfg.nodePort });
const projectRoot = path.resolve(__dirname, "..", "..", "..", "..", "..");
const cacheDir = path.resolve(projectRoot, "data_user", "graffiti_cache");
const GRAFFITI_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const GRAFFITI_CACHE_SWEEP_MS = 15 * 60 * 1000;
let lastGraffitiCacheSweep = 0;

const searchLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 20 });
const graffitiMediaLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 40 });

const touchFile = (filePath) => {
  try {
    const now = new Date();
    fs.utimesSync(filePath, now, now);
  } catch (_err) {
  }
};

const cleanupGraffitiCache = () => {
  const now = Date.now();
  if (now - lastGraffitiCacheSweep < GRAFFITI_CACHE_SWEEP_MS) return;
  lastGraffitiCacheSweep = now;
  if (!fs.existsSync(cacheDir)) return;
  let entries;
  try {
    entries = fs.readdirSync(cacheDir);
  } catch (_err) {
    return;
  }
  for (const entry of entries) {
    const fullPath = path.join(cacheDir, entry);
    let stat;
    try {
      stat = fs.statSync(fullPath);
    } catch (_err) {
      continue;
    }
    if (!stat.isFile()) continue;
    if (now - stat.mtimeMs > GRAFFITI_CACHE_TTL_MS) {
      try {
        fs.unlinkSync(fullPath);
      } catch (_err) {
      }
    }
  }
};

const resolveCachePath = (cachePath) => {
  if (!cachePath) return null;
  if (path.isAbsolute(cachePath)) return cachePath;
  return path.resolve(projectRoot, cachePath);
};

const inferMediaType = (meta, filePath) => {
  const mime = meta?.mime || meta?.mime_type;
  if (mime) {
    if (String(mime).includes("video")) return "video/mp4";
    if (String(mime).includes("image")) return "image/jpeg";
  }
  const ext = path.extname(filePath || "").toLowerCase();
  if (ext === ".mp4") return "video/mp4";
  if (ext === ".jpg" || ext === ".jpeg") return "image/jpeg";
  return "application/octet-stream";
};

router.get("/network", async (_req, res, next) => {
  try {
    const snap = await svc.getNetwork();
    res.json({ status: "ok", data: snap });
  } catch (err) {
    next(err);
  }
});

router.get("/blocks", async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 10, 1), 500);
    const startRaw = req.query.start ?? req.query.start_height ?? req.query.height;
    const startHeight = 
      startRaw === undefined || startRaw === null || startRaw === ""
        ? null
        : Number(startRaw);
    
    // Parameter untuk prefer database
    const preferDatabase = req.query.prefer_database === 'true';
    
    const data = await svc.getBlockRange({ 
      startHeight, 
      limit,
      source: preferDatabase ? 'database' : 'auto'
    });
    
    res.json({ status: "ok", data });
  } catch (err) {
    next(err);
  }
});

router.get("/block/:id", async (req, res, next) => {
  try {
    const data = await svc.getBlock(req.params.id);
    res.json({ status: "ok", data });
  } catch (err) {
    next(err);
  }
});

router.get("/tx/:id", async (req, res, next) => {
  try {
    const data = await svc.getTx(req.params.id);
    res.json({ status: "ok", data });
  } catch (err) {
    next(err);
  }
});

router.get("/address/:addr", async (req, res, next) => {
  try {
    const data = await svc.getAddress(req.params.addr);
    res.json({ status: "ok", data });
  } catch (err) {
    next(err);
  }
});

router.get("/graffiti/:artId", async (req, res, next) => {
  try {
    const data = await svc.getGraffiti(req.params.artId);
    if (!data) {
      return res.status(404).json({ error: "not_found" });
    }
    res.json({ status: "ok", data });
  } catch (err) {
    next(err);
  }
});

router.get("/graffiti/:artId/media", graffitiMediaLimiter, async (req, res, next) => {
  try {
    cleanupGraffitiCache();
    const artId = req.params.artId;
    let filePath = null;
    if (fs.existsSync(cacheDir)) {
      for (const ext of [".jpg", ".jpeg", ".mp4", ".bin"]) {
        const candidate = path.join(cacheDir, `${artId}${ext}`);
        if (fs.existsSync(candidate)) {
          filePath = candidate;
          break;
        }
      }
    }
    let info = null;
    if (!filePath) {
      info = await svc.getGraffitiMediaInfo(artId);
      if (!info || info.status !== "ok" || !info.cache_path) {
        return res.status(404).json({ error: "media_not_found" });
      }
      filePath = resolveCachePath(info.cache_path);
    }
    if (!filePath || !fs.existsSync(filePath)) {
      return res.status(404).json({ error: "media_not_found" });
    }
    touchFile(filePath);
    const stat = fs.statSync(filePath);
    const size = stat.size;
    const type = inferMediaType(info?.meta, filePath);
    res.setHeader("Content-Type", type);
    res.setHeader("Cache-Control", "public, max-age=300");
    res.setHeader("Accept-Ranges", "bytes");

    const range = req.headers.range;
    if (range) {
      const match = /^bytes=(\d*)-(\d*)$/.exec(range);
      if (!match) {
        res.status(416);
        res.setHeader("Content-Range", `bytes */${size}`);
        return res.end();
      }
      let start = match[1] ? Number(match[1]) : 0;
      let end = match[2] ? Number(match[2]) : size - 1;
      if (Number.isNaN(start) || Number.isNaN(end) || start > end || start >= size) {
        res.status(416);
        res.setHeader("Content-Range", `bytes */${size}`);
        return res.end();
      }
      end = Math.min(end, size - 1);
      res.status(206);
      res.setHeader("Content-Range", `bytes ${start}-${end}/${size}`);
      res.setHeader("Content-Length", String(end - start + 1));
      const stream = fs.createReadStream(filePath, { start, end });
      stream.on("error", next);
      return stream.pipe(res);
    }

    res.setHeader("Content-Length", String(size));
    const stream = fs.createReadStream(filePath);
    stream.on("error", next);
    return stream.pipe(res);
  } catch (err) {
    next(err);
  }
});

router.get("/graffiti", async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 24, 1), 100);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    const data = await svc.getGraffitiPosts({ limit, offset });
    res.json({ status: "ok", data });
  } catch (err) {
    next(err);
  }
});

router.get("/search", searchLimiter, async (req, res, next) => {
  try {
    const query = (req.query.q || "").trim();
    if (!query) return res.status(400).json({ error: "missing_query" });
    const inferred = guessKind(query);
    const result = await svc.search(query);
    if (!result.data) {
      return res.status(404).json({ status: "not_found", kind: inferred });
    }
    res.json({ status: "ok", kind: result.kind, data: result.data });
  } catch (err) {
    next(err);
  }
});

router.post("/prefetch-blocks", async (_req, res, next) => {
  try {
    // Trigger prefetch di Python RPC client
    await rpcCall("prefetch_blocks", null, cfg.nodeHost, cfg.nodePort);
    res.json({ status: "ok", message: "Prefetch started" });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
