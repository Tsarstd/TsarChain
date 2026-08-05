const fs = require("node:fs");
const fsPromises = require("node:fs/promises");
const path = require("node:path");
const router = require("express").Router();
const { ExplorerService } = require("../services/explorerService");
const { getConfig } = require("../config/env");
const { createRateLimiter } = require("../utils/rateLimit");
const { guessKind, isHex64 } = require("../utils/searchKind");

const isArtId = (s) => /^graf[0-9a-fA-F]{60}$/.test(s || "");

const cfg = getConfig();
const svc = new ExplorerService({ nodeHost: cfg.nodeHost, nodePort: cfg.nodePort });
const projectRoot = path.resolve(__dirname, "..", "..", "..", "..", "..");
const cacheDir = path.resolve(projectRoot, "data", "web", "graffiti_cache");
const GRAFFITI_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const GRAFFITI_CACHE_SWEEP_MS = 15 * 60 * 1000;
let lastGraffitiCacheSweep = 0;

const searchLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 20 });
const graffitiMediaLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 40 });

const touchFile = async (filePath) => {
  try {
    const now = new Date();
    await fsPromises.utimes(filePath, now, now);
  } catch (err) {
    console.warn("Failed to touch file:", err);
  }
};

const cleanupGraffitiCache = async () => {
  const now = Date.now();
  if (now - lastGraffitiCacheSweep < GRAFFITI_CACHE_SWEEP_MS) return;
  lastGraffitiCacheSweep = now;
  try {
    await fsPromises.access(cacheDir);
  } catch {
    return;
  }
  let entries;
  try {
    entries = await fsPromises.readdir(cacheDir);
  } catch (err) {
    console.warn("Failed to read cache directory:", err);
    return;
  }
  for (const entry of entries) {
    const fullPath = path.join(cacheDir, entry);
    let stat;
    try {
      stat = await fsPromises.stat(fullPath);
    } catch (err) {
      console.warn("Failed to stat file:", err);
      continue;
    }
    if (!stat.isFile()) continue;
    if (now - stat.mtimeMs > GRAFFITI_CACHE_TTL_MS) {
      try {
        await fsPromises.unlink(fullPath);
      } catch (err) {
        console.warn("Failed to unlink file:", err);
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

const findCachedFile = async (artId) => {
  try {
    await fsPromises.access(cacheDir);
  } catch {
    return null;
  }
  for (const ext of [".jpg", ".jpeg", ".mp4", ".bin"]) {
    const candidate = path.join(cacheDir, `${artId}${ext}`);
    try {
      await fsPromises.access(candidate);
      return candidate;
    } catch {
      // file not found, continue
    }
  }
  return null;
};

const parseRangeHeader = (rangeHeader, size) => {
  if (!rangeHeader) return null;
  const match = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader);
  if (!match) {
    return { invalid: true };
  }
  const start = match[1] ? Number(match[1]) : 0;
  let end = match[2] ? Number(match[2]) : size - 1;
  if (Number.isNaN(start) || Number.isNaN(end) || start > end || start >= size) {
    return { invalid: true };
  }
  end = Math.min(end, size - 1);
  return { start, end };
};

router.get("/receipt", async (req, res, next) => {
  try {
    const txid = req.query.txid;
    if (!txid) {
      return res.status(400).json({ error: "missing_txid" });
    }
    if (!isHex64(txid)) {
      return res.status(400).json({ error: "invalid_txid" });
    }

    const data = await svc.getReceipt(txid);
    if (data.status === "error") {
      return res.status(400).json({ error: data.message });
    }
    
    res.json({ status: "ok", data });
  } catch (err) {
    next(err);
  }
});

router.get("/history_book", async (req, res, next) => {
  try {
    const address = req.query.address;
    if (!address) {
      return res.status(400).json({ error: "missing_address" });
    }
    if (!/^tsar[0-9a-zA-Z]{16,}$/.test(address)) {
      return res.status(400).json({ error: "invalid_address" });
    }

    const data = await svc.getHistoryBook(address);
    if (data.status === "error") {
      return res.status(400).json({ error: data.message });
    }
    
    res.json({ status: "ok", data });
  } catch (err) {
    next(err);
  }
});

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
    const id = req.params.id;
    const isHeight = /^\d{1,7}$/.test(id);
    if (!isHeight && !isHex64(id)) {
      return res.status(400).json({ error: "invalid_block_id" });
    }
    const data = await svc.getBlock(id);
    res.json({ status: "ok", data });
  } catch (err) {
    next(err);
  }
});

router.get("/tx/:id", async (req, res, next) => {
  try {
    const id = req.params.id;
    if (!isHex64(id)) {
      return res.status(400).json({ error: "invalid_txid" });
    }
    const data = await svc.getTx(id);
    res.json({ status: "ok", data });
  } catch (err) {
    next(err);
  }
});

router.get("/address/:addr", async (req, res, next) => {
  try {
    const addr = req.params.addr;
    if (!/^tsar[0-9a-zA-Z]{16,}$/.test(addr)) {
      return res.status(400).json({ error: "invalid_address" });
    }
    const data = await svc.getAddress(addr);
    res.json({ status: "ok", data });
  } catch (err) {
    next(err);
  }
});

router.get("/graffiti/:artId", async (req, res, next) => {
  try {
    const artId = req.params.artId;
    if (!isArtId(artId)) {
      return res.status(400).json({ error: "invalid_art_id" });
    }
    const data = await svc.getGraffiti(artId);
    if (!data) {
      return res.status(404).json({ error: "not_found" });
    }
    res.json({ status: "ok", data });
  } catch (err) {
    next(err);
  }
});

const STREAM_THRESHOLD_BYTES = 10 * 1024 * 1024;
const STREAM_CHUNK_BYTES = 4 * 1024 * 1024;

const serveLocalFile = async (req, res, next, filePath, meta = null) => {
  try {
    await fsPromises.access(filePath);
    touchFile(filePath).catch((err) => console.warn("Touch file error:", err));
    const stat = await fsPromises.stat(filePath);
    const size = stat.size;
    const type = inferMediaType(meta, filePath);
    res.setHeader("Content-Type", type);
    res.setHeader("Cache-Control", "public, max-age=300");
    res.setHeader("Accept-Ranges", "bytes");

    const range = parseRangeHeader(req.headers.range, size);
    if (range) {
      if (range.invalid) {
        res.status(416);
        res.setHeader("Content-Range", `bytes */${size}`);
        res.end();
        return true;
      }
      res.status(206);
      res.setHeader("Content-Range", `bytes ${range.start}-${range.end}/${size}`);
      res.setHeader("Content-Length", String(range.end - range.start + 1));
      const stream = fs.createReadStream(filePath, { start: range.start, end: range.end });
      stream.on("error", next);
      stream.pipe(res);
      return true;
    }

    res.setHeader("Content-Length", String(size));
    const stream = fs.createReadStream(filePath);
    stream.on("error", next);
    stream.pipe(res);
    return true;
  } catch (err) {
    console.warn("Failed to serve local cached file:", err);
    return false;
  }
};

const tryServeFromServiceCache = async (artId, req, res, next) => {
  const info = await svc.getGraffitiMediaInfo(artId);
  if (info?.status === "ok" && info?.cache_path) {
    const resolvedPath = resolveCachePath(info.cache_path);
    if (resolvedPath) {
      return await serveLocalFile(req, res, next, resolvedPath, info.meta);
    }
  }
  return false;
};

const streamGraffitiChunks = async (req, res, artId, totalSize, meta) => {
  const type = inferMediaType(meta, meta?.filename || artId);
  res.setHeader("Content-Type", type);
  res.setHeader("Cache-Control", "public, max-age=300");
  res.setHeader("Accept-Ranges", "bytes");

  let start = 0;
  let end = totalSize > 0 ? totalSize - 1 : 0;

  const range = totalSize > 0 ? parseRangeHeader(req.headers.range, totalSize) : null;
  if (range) {
    if (range.invalid) {
      res.status(416);
      res.setHeader("Content-Range", `bytes */${totalSize}`);
      return res.end();
    }
    start = range.start;
    end = range.end;
    res.status(206);
    res.setHeader("Content-Range", `bytes ${start}-${end}/${totalSize}`);
    res.setHeader("Content-Length", String(end - start + 1));
  } else if (totalSize > 0) {
    res.setHeader("Content-Length", String(totalSize));
  }

  let clientAborted = false;
  req.on("close", () => {
    clientAborted = true;
  });

  let currOffset = start;
  const targetEnd = totalSize > 0 ? end : Number.MAX_SAFE_INTEGER;

  while (currOffset <= targetEnd && !clientAborted) {
    const want = totalSize > 0
      ? Math.min(STREAM_CHUNK_BYTES, targetEnd - currOffset + 1)
      : STREAM_CHUNK_BYTES;

    const chunkResp = await svc.getGraffitiChunk(artId, currOffset, want);
    if (chunkResp?.status !== "ok" || !chunkResp?.data_b64) {
      break;
    }

    const buf = Buffer.from(chunkResp.data_b64, "base64");
    if (buf.length === 0) break;

    const canContinue = res.write(buf);
    currOffset += buf.length;

    if (!canContinue && !clientAborted) {
      await new Promise((resolve) => res.once("drain", resolve));
    }

    if (chunkResp.eof) break;
  }

  res.end();
};

router.get("/graffiti/:artId/media", graffitiMediaLimiter, async (req, res, next) => {
  try {
    cleanupGraffitiCache().catch((err) => console.warn("Cache cleanup error:", err));
    const artId = req.params.artId;
    if (!isArtId(artId)) {
      return res.status(400).json({ error: "invalid_art_id" });
    }

    const filePath = await findCachedFile(artId);
    if (filePath && (await serveLocalFile(req, res, next, filePath))) {
      return;
    }

    const metaResp = await svc.getGraffitiMediaMeta(artId);
    if (metaResp?.status !== "ok") {
      return res.status(404).json({ error: "media_not_found" });
    }

    const meta = metaResp.meta || {};
    const totalSize = Number(meta.size_bytes || meta.size || metaResp.size_bytes || 0);

    // Smart Caching: file size <= 10MB -> Full download to disk cache
    if (totalSize > 0 && totalSize <= STREAM_THRESHOLD_BYTES) {
      const served = await tryServeFromServiceCache(artId, req, res, next);
      if (served) return;
    }

    // File size > 10MB -> On-demand HTTP streaming (4MB chunks)
    await streamGraffitiChunks(req, res, artId, totalSize, meta);
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
