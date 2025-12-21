const router = require("express").Router();
const { ExplorerService } = require("../services/explorerService");
const { getConfig } = require("../config/env");
const { guessKind } = require("../utils/searchKind");

const cfg = getConfig();
const svc = new ExplorerService({ nodeHost: cfg.nodeHost, nodePort: cfg.nodePort });

router.get("/network", async (_req, res, next) => {
  try {
    const snap = await svc.getNetwork();
    res.json({ status: "ok", data: snap });
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
    res.json({ status: "ok", data });
  } catch (err) {
    next(err);
  }
});

router.get("/search", async (req, res, next) => {
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

module.exports = router;
