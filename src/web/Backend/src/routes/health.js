const router = require("express").Router();

router.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

module.exports = router;
