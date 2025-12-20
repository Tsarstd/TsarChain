const DEFAULT_API = "http://127.0.0.1:8787";
const SNAPSHOT_INTERVAL_MS = 30000;
const MIN_SNAPSHOT_INTERVAL_MS = 25000;
const STORAGE_THEME = "tsar_explorer_theme";

const el = {
  searchForm: document.getElementById("searchForm"),
  searchInput: document.getElementById("searchInput"),
  refreshOverview: document.getElementById("refreshOverview"),
  loadLatest: document.getElementById("loadLatest"),
  clearResults: document.getElementById("clearResults"),
  overview: document.getElementById("overview"),
  snapshotPrimary: document.getElementById("snapshotPrimary"),
  snapshotSecondary: document.getElementById("snapshotSecondary"),
  snapshotStamp: document.getElementById("snapshotStamp"),
  results: document.getElementById("results"),
  status: document.getElementById("status"),
};

const state = {
  apiBase: DEFAULT_API,
  theme: "kremlin",
  info: null,
  snapshot: null,
  snapshotInflight: false,
  lastSnapshotTs: 0,
};

function setStatus(message, level = "info") {
  el.status.textContent = `Status: ${message}`;
  el.status.classList.remove("success", "error");
  if (level === "success") el.status.classList.add("success");
  if (level === "error") el.status.classList.add("error");
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function pick(...vals) {
  for (const v of vals) {
    if (v !== undefined && v !== null && v !== "") return v;
  }
  return null;
}

function pickNested(obj, ...paths) {
  for (const path of paths) {
    let cur = obj;
    let ok = true;
    for (const key of path) {
      if (!cur || typeof cur !== "object" || !(key in cur)) {
        ok = false;
        break;
      }
      cur = cur[key];
    }
    if (ok && cur !== null && cur !== undefined && cur !== "") return cur;
  }
  return null;
}

function buildUrl(path) {
  return `${state.apiBase}${path}`;
}

async function fetchJson(path) {
  const res = await fetch(buildUrl(path), {
    headers: { Accept: "application/json" },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || (data && data.error)) {
    throw new Error((data && data.error) || res.statusText);
  }
  return data;
}

function formatTimestamp(ts) {
  const v = Number(ts);
  if (!Number.isFinite(v) || v <= 0) return "-";
  const d = new Date(v * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(
    d.getDate()
  )} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function formatBytes(bytes) {
  const val = Number(bytes);
  if (!Number.isFinite(val) || val <= 0) return "0 bytes";
  const units = ["bytes", "KB", "MB", "GB", "TB"];
  let size = val;
  let idx = 0;
  while (size >= 1024 && idx < units.length - 1) {
    size /= 1024;
    idx += 1;
  }
  return idx === 0 ? `${Math.round(size)} ${units[idx]}` : `${size.toFixed(2)} ${units[idx]}`;
}

function formatNum(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "-";
  return n.toLocaleString("en-US");
}

function formatTsar(value) {
  if (value === null || value === undefined || value === "") {
    return "0.00000000 TSAR";
  }
  const cleaned = String(value).replace(/_/g, "").trim();
  if (/^-?\d+$/.test(cleaned)) {
    const big = BigInt(cleaned);
    const neg = big < 0n;
    const abs = neg ? -big : big;
    const whole = abs / 100000000n;
    const frac = abs % 100000000n;
    const wholeStr = whole.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    const fracStr = frac.toString().padStart(8, "0");
    return `${neg ? "-" : ""}${wholeStr}.${fracStr} TSAR`;
  }
  const num = Number(cleaned);
  if (!Number.isFinite(num)) return String(value);
  const neg = num < 0;
  const sat = Math.abs(Math.trunc(num));
  const whole = Math.floor(sat / 1e8);
  const frac = String(sat % 1e8).padStart(8, "0");
  return `${neg ? "-" : ""}${whole.toLocaleString()}.${frac} TSAR`;
}

function shortHash(value, n = 10) {
  const s = String(value || "");
  if (!s) return "-";
  if (s.length <= n * 2) return s;
  return `${s.slice(0, n)}...${s.slice(-n)}`;
}

function decodeHex(hex) {
  const h = (hex || "").toString().replace(/^0x/, "");
  if (!h || h.length % 2 !== 0 || /[^0-9a-f]/i.test(h)) return "";
  try {
    let out = "";
    for (let i = 0; i < h.length; i += 2) {
      out += String.fromCharCode(parseInt(h.slice(i, i + 2), 16));
    }
    return out;
  } catch {
    return "";
  }
}

function formatHashrate(hps) {
  const v = Number(hps);
  if (!Number.isFinite(v)) return "-";
  if (v >= 1e12) return `${(v / 1e12).toFixed(3)} TH/s`;
  if (v >= 1e9) return `${(v / 1e9).toFixed(3)} GH/s`;
  if (v >= 1e6) return `${(v / 1e6).toFixed(3)} MH/s`;
  if (v >= 1e3) return `${(v / 1e3).toFixed(3)} kH/s`;
  return `${v.toFixed(0)} H/s`;
}

function formatLastUpdated(raw) {
  if (!raw) return "-";
  if (typeof raw === "number") return formatTimestamp(raw);
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return String(raw);
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
}

function kvRow(label, value, mono = false) {
  const v = value === null || value === undefined || value === "" ? "-" : value;
  return `
    <div class="kv-row">
      <span class="kv-key">${escapeHtml(label)}</span>
      <span class="kv-val ${mono ? "mono" : ""}">${escapeHtml(v)}</span>
    </div>
  `;
}

function renderOverview(info) {
  const rows = [
    kvRow("Network", info.network || "-"),
    kvRow("Height", info.height ?? "-", true),
    kvRow("Difficulty", info.difficulty ?? "-", true),
    kvRow("Target", info.target ?? "-", true),
    kvRow("Tip", shortHash(info.tip || "-"), true),
    kvRow("Peers", info.peers ?? "-", true),
    kvRow("Mempool", info.mempool ?? "-", true),
    kvRow("Mempool Bytes", info.mempool_bytes ?? "-", true),
  ];

  if (info.supply && typeof info.supply === "object") {
    rows.push(kvRow("Supply", formatTsar(info.supply.circulating_estimate)));
    rows.push(kvRow("Subsidy", formatTsar(info.supply.current_block_subsidy)));
  }

  el.overview.innerHTML = rows.join("");
}

function renderSnapshot(snap) {
  if (!el.snapshotPrimary || !el.snapshotSecondary) return;
  const ident = (snap && snap.identity) || {};
  const chain = (snap && snap.chain) || {};
  const supply = (snap && snap.supply) || {};
  const txs = (snap && snap.transactions) || {};
  const utxo = (snap && snap.utxo) || {};
  const graffiti = (snap && snap.graffiti) || {};
  const peersCount =
    snap.peers_count ??
    (snap.peers && (snap.peers.count ?? snap.peers.total ?? (Array.isArray(snap.peers) ? snap.peers.length : null)));

  const primary = [
    kvRow("Network ID", ident.network_id || ident.net_id || "-"),
    kvRow("Magic", ident.network_magic_hex || "-"),
    kvRow("Address Prefix", ident.address_prefix || "-"),
    kvRow("Peers", formatNum(peersCount), true),
    kvRow("Hashrate", formatHashrate(chain.est_network_hashrate_hps_window), true),
    kvRow("Avg Block Time", chain.avg_block_time_sec_window ? `${chain.avg_block_time_sec_window}s` : "-", true),
    kvRow("Mempool TX", formatNum(txs.mempool_txs ?? txs.mempool), true),
    kvRow("Mempool VBytes", formatNum(txs.mempool_vbytes_estimate), true),
  ];

  const secondary = [
    kvRow("Tip Height", formatNum(chain.tip_height ?? chain.total_blocks), true),
    kvRow("Tip Hash", chain.tip_hash || "-", true),
    kvRow("Difficulty", chain.tip_difficulty ?? "-", true),
    kvRow("Target", chain.tip_target_hex || "-", true),
    kvRow("Total Blocks", formatNum(chain.total_blocks), true),
    kvRow("Total TX", formatNum(txs.total_txs), true),
    kvRow("Coinbase Reward", formatTsar(chain.current_block_subsidy ?? supply.current_block_subsidy), true),
    kvRow("Supply", formatTsar(supply.circulating_estimate), true),
    kvRow("UTXO Set", formatNum(utxo.utxo_set_size ?? utxo.count), true),
    kvRow("Graffiti Posts", formatNum(graffiti.posts), true),
    kvRow("Graffiti Comments", formatNum(graffiti.comments), true),
    kvRow("Graffiti Storage", formatBytes(graffiti.total_graffiti_storage), true),
  ];

  el.snapshotPrimary.innerHTML = primary.join("");
  el.snapshotSecondary.innerHTML = secondary.join("");
  if (el.snapshotStamp) {
    el.snapshotStamp.textContent =
      snap && snap.last_updated ? `Update: ${formatLastUpdated(snap.last_updated)}` : "";
  }
}

function snapshotToOverview(snap) {
  const chain = (snap && snap.chain) || {};
  const supply = (snap && snap.supply) || {};
  const txs = (snap && snap.transactions) || {};
  const peers = snap && (snap.peers_count ?? snap.peers?.count ?? snap.peers?.total);
  return {
    network: snap?.identity?.network_id || snap?.net_id || snap?.network_id || "-",
    height: chain.tip_height ?? chain.total_blocks ?? snap?.height,
    difficulty: chain.tip_difficulty ?? chain.difficulty,
    target: chain.tip_target_hex ?? chain.target,
    tip: chain.tip_hash ?? snap?.tip,
    peers,
    mempool: txs.mempool_txs ?? txs.mempool,
    mempool_bytes: txs.mempool_bytes_estimate,
    supply: {
      circulating_estimate: supply.circulating_estimate,
      current_block_subsidy: chain.current_block_subsidy ?? supply.current_block_subsidy,
    },
  };
}

function renderCard(title, bodyHtml) {
  return `
    <div class="card reveal">
      <h3>${escapeHtml(title)}</h3>
      ${bodyHtml}
    </div>
  `;
}

function renderBlock(block) {
  const height = pick(block.height, block.index, pickNested(block, ["_meta", "height"])) ?? "Genesis";
  const blockId = pick(block.block_id, block.blockid, block.id, pickNested(block, ["_meta", "block_id"]));
  const hash = pick(block.hash, pickNested(block, ["_meta", "hash"]), block.block_hash);
  const prev = pick(block.prev_hash, block.prev_block_hash, block.previous_hash, pickNested(block, ["_meta", "prev_block_hash"]));
  const ts = pick(block.timestamp, block.time, pickNested(block, ["_meta", "timestamp"]));
  const nonce = pick(block.nonce, pickNested(block, ["_meta", "nonce"]));
  const bits = pick(block.bits, pickNested(block, ["_meta", "bits"]));
  const mroot = pick(block.merkle_root, pickNested(block, ["_meta", "merkle_root"]));
  const vbytes = pick(block.vbytes, pickNested(block, ["_meta", "vbytes"]));
  const txs = block.transactions || block.tx || block.txs || [];
  const graffiti = block.graffiti || [];
  const comments = block.comments || [];
  const graffitiCount = Array.isArray(graffiti) ? graffiti.length : 0;
  const commentsCount = Array.isArray(comments) ? comments.length : 0;

  const infoHtml = `
    <div class="kv-list">
      ${kvRow("Height", height, true)}
      ${kvRow("Timestamp", formatTimestamp(ts), true)}
      ${kvRow("Block ID", blockId || "-", true)}
      ${kvRow("Hash", hash || "-", true)}
      ${kvRow("Previous", prev || "-", true)}
      ${kvRow("Nonce", nonce ?? "-", true)}
      ${kvRow("Bits", bits ?? "-", true)}
      ${kvRow("Vbytes", vbytes || "-", true)}
      ${kvRow("Merkle Root", mroot || "-", true)}
      ${kvRow("Tx Count", txs.length, true)}
      ${kvRow("Graffiti", graffitiCount, true)}
      ${kvRow("Comments", commentsCount, true)}
    </div>
  `;

  const txList = txs.length
    ? `
      <div class="list">
        ${txs
          .map((t) => {
            const txid = t.txid || t.id || t.hash || t;
            const vin = (t.inputs || t.vin || []).length;
            const vout = (t.outputs || t.vout || []).length;
            return `
              <div class="list-item mono">
                ${kvRow("TxID", txid, true)}
                ${kvRow("Inputs", vin, true)}
                ${kvRow("Outputs", vout, true)}
              </div>
            `;
          })
          .join("")}
      </div>
    `
    : `<p class="mono">No transactions.</p>`;

  const graffitiHtml = graffiti.length || comments.length
    ? `
      <div class="list">
        ${graffiti
          .map((g) => {
            return `
              <div class="list-item">
                ${kvRow("SHA256", g.sha256, true)}
                ${kvRow("TxID", g.txid, true)}
                ${kvRow("Type", g.mime, true)}
                ${kvRow("Size", formatBytes(g.size), true)}
              </div>
            `;
          })
          .join("")}
        ${comments
          .map((c) => {
            return `
              <div class="list-item">
                ${kvRow("Art ID", c.art_id, true)}
                ${kvRow("Commenter", c.commenter, true)}
                ${kvRow("Comment", c.comment_text, true)}
              </div>
            `;
          })
          .join("")}
      </div>
    `
    : `<p class="mono">No graffiti activity.</p>`;

  el.results.innerHTML = [
    renderCard("Block Detail", infoHtml),
    renderCard("Transactions", txList),
    renderCard("Graffiti Activity", graffitiHtml),
  ].join("");
}

function renderTx(tx) {
  const statusRaw = tx.status || (Number(tx.confirmations || 0) > 0 ? "confirmed" : "unconfirmed");
  const statusTag = statusRaw.toLowerCase().startsWith("conf") ? "success" : "warn";
  const inputs = tx.inputs || tx.vin || [];
  const outputs = tx.outputs || tx.vout || [];

  const infoHtml = `
    <div class="kv-list">
      ${kvRow("TxID", tx.txid || "-", true)}
      ${kvRow("Status", statusRaw, true)}
      ${kvRow("Confirmations", tx.confirmations ?? tx.conf ?? "-", true)}
      ${kvRow("Block Height", tx.height ?? tx.block_height ?? "-", true)}
      ${kvRow("Fee", tx.fee ? formatTsar(tx.fee) : "-", true)}
      ${kvRow("Size", tx.vsize || tx.size || "-", true)}
      ${kvRow("Coinbase", tx.is_coinbase ? "true" : "false", true)}
    </div>
    <div style="margin-top: 10px;">
      <span class="tag ${statusTag}">${escapeHtml(statusRaw)}</span>
    </div>
  `;

  const inputHtml = inputs.length
    ? `
      <div class="list">
        ${inputs
          .map((i) => {
            const src = i.prev_txid || i.txid || i.tx || "-";
            const idx = i.vout ?? i.index ?? i.n ?? 0;
            const addr = i.address || i.addr || "";
            const amt = i.amount || i.value;
            return `
              <div class="list-item mono">
                <div>${escapeHtml(`${src}:${idx}`)}</div>
                ${addr ? `<div>${escapeHtml(addr)}</div>` : ""}
                ${amt !== undefined && amt !== null ? `<div>${escapeHtml(formatTsar(amt))}</div>` : ""}
              </div>
            `;
          })
          .join("")}
      </div>
    `
    : `<p class="mono">No inputs.</p>`;

  const outputHtml = outputs.length
    ? `
      <div class="list">
        ${outputs
          .map((o, idx) => {
            const addr = o.address || o.scriptpubkey_address || o.addr || "";
            const amt = o.amount || o.value || "-";
            return `
              <div class="list-item mono">
                <div>Out #${idx}</div>
                ${addr ? `<div>${escapeHtml(addr)}</div>` : ""}
                <div>${escapeHtml(formatTsar(amt))}</div>
              </div>
            `;
          })
          .join("")}
      </div>
    `
    : `<p class="mono">No outputs.</p>`;

  el.results.innerHTML = [
    renderCard("Transaction Detail", infoHtml),
    renderCard("Inputs", inputHtml),
    renderCard("Outputs", outputHtml),
  ].join("");
}

function renderAddress(addr) {
  const history = addr.history || [];
  const infoHtml = `
    <div class="kv-list">
      ${kvRow("Address", addr.address || "-", true)}
      ${kvRow("Spendable", formatTsar(addr.spendable), true)}
      ${kvRow("Immature", formatTsar(addr.immature), true)}
      ${kvRow("Pending", formatTsar(addr.pending), true)}
      ${kvRow("UTXOs", (addr.utxos || []).length, true)}
    </div>
  `;

  const historyHtml = history.length
    ? `
      <div class="list">
        ${history
          .slice(0, 200)
          .map((h) => {
            const status = h.status || "-";
            const tagClass = status.toLowerCase().startsWith("conf") ? "success" : "warn";
            return `
              <div class="list-item mono">
                <div>${escapeHtml(h.txid || h.id || "-")}</div>
                <div>${escapeHtml(formatTsar(h.amount || h.value || 0))}</div>
                <div class="tag ${tagClass}">${escapeHtml(status)}</div>
              </div>
            `;
          })
          .join("")}
      </div>
    `
    : `<p class="mono">No history.</p>`;

  el.results.innerHTML = [
    renderCard("Address Detail", infoHtml),
    renderCard("Recent Activity", historyHtml),
  ].join("");
}

function renderGraffiti(postResp, commentsResp) {
  const post = postResp.post && typeof postResp.post === "object" ? postResp.post : postResp;
  const artId = post.art_id || postResp.art_id || "-";
  const mime = (post.mime || post.mime_type || postResp.mime || "").toLowerCase();
  const size = post.size || post.size_bytes || 0;
  const stats = post.stats || {};
  const mediaUrl = buildUrl(`/api/graffiti/${encodeURIComponent(artId)}/file`);
  const isVideo =
    mime.includes("video") || (post.filename || "").toLowerCase().endsWith(".mp4");

  const infoHtml = `
    <div class="kv-list">
      ${kvRow("Art ID", artId, true)}
      ${kvRow("Creator", post.creator || "-", true)}
      ${kvRow("TxID", post.txid || "-", true)}
      ${kvRow("Block Height", post.block_height || "-", true)}
      ${kvRow("Mime", mime || "-", true)}
      ${kvRow("Size", formatBytes(size), true)}
      ${kvRow("Comments", stats.comments ?? 0, true)}
    </div>
  `;

  const mediaHtml = `
    <div class="media" data-media="true">
      ${
        isVideo
          ? `<video controls crossorigin="anonymous">
               <source src="${mediaUrl}" type="video/mp4" />
             </video>`
          : `<img src="${mediaUrl}" alt="Graffiti preview" crossorigin="anonymous" />`
      }
      <div class="fallback" hidden>Media tidak tersedia.</div>
    </div>
    <p class="mono" style="margin-top: 8px;">
      <a href="${mediaUrl}" target="_blank" rel="noopener">Open media</a>
    </p>
  `;

  let comments = [];
  if (Array.isArray(commentsResp)) comments = commentsResp;
  if (commentsResp && Array.isArray(commentsResp.comments)) comments = commentsResp.comments;

  const commentsHtml = comments.length
    ? `
      <div class="comment-grid">
        ${comments.map((c) => {
          const raw = c.comment_text || decodeHex(c.comment_hex || c.comment || "") || c.comment || "";
          const text = raw || "-";
          return `
            <div class="comment-card">
              <div class="mono">${escapeHtml(c.commenter || "-")}</div>
              <div>${escapeHtml(text)}</div>
              <div class="mono">Amount: ${escapeHtml(formatTsar(c.amount || 0))}</div>
              ${c.tip ? `<div class="mono">Tip: ${escapeHtml(formatTsar(c.tip))}</div>` : ""}
              <div class="mono">${escapeHtml(formatTimestamp(c.ts || 0))}</div>
            </div>
          `;
        }).join("")}
      </div>
    `
    : `<p class="mono">No comments.</p>`;

  el.results.innerHTML = [
    renderCard("Graffiti Detail", infoHtml),
    renderCard("Media Preview", mediaHtml),
    renderCard("Comments", commentsHtml),
  ].join("");

  wireMediaFallback();
}

function wireMediaFallback() {
  document.querySelectorAll("[data-media]").forEach((holder) => {
    const media = holder.querySelector("img, video");
    const fallback = holder.querySelector(".fallback");
    if (!media || !fallback) return;
    const showFallback = () => {
      fallback.hidden = false;
      media.style.display = "none";
    };
    media.addEventListener("error", showFallback, { once: true });
  });
}

async function loadOverview(silent = false) {
  try {
    if (!silent) setStatus("memuat overview...");
    const info = await fetchJson("/api/info");
    state.info = info;
    renderOverview(info);
    if (!silent) setStatus("overview siap.", "success");
  } catch (err) {
    setStatus(`gagal overview: ${err.message}`, "error");
  }
}

async function loadSnapshot(opts = { silent: false }) {
  const now = Date.now();
  if (state.snapshotInflight) return;
  if (now - state.lastSnapshotTs < MIN_SNAPSHOT_INTERVAL_MS) return;
  state.snapshotInflight = true;
  const { silent = false } = opts || {};
  try {
    if (!silent) setStatus("memuat snapshot...");
    const snap = await fetchJson("/api/info/snapshot");
    state.snapshot = snap;
    renderSnapshot(snap);
    const infoFromSnap = snapshotToOverview(snap);
    state.info = infoFromSnap;
    renderOverview(infoFromSnap);
    state.lastSnapshotTs = Date.now();
    if (!silent) setStatus("snapshot siap.", "success");
  } catch (err) {
    setStatus(`snapshot gagal: ${err.message}`, "error");
    // fallback ke overview ringan jika snapshot gagal
    try {
      await loadOverview(!silent);
    } catch {
      /* noop */
    }
  } finally {
    state.snapshotInflight = false;
  }
}

async function loadLatestBlock() {
  try {
    if (!state.info || !state.info.height) {
      await loadSnapshot({ silent: true });
    }
    const height = state.info ? state.info.height : null;
    if (!height) {
      return setStatus("height tidak tersedia.", "error");
    }
    setStatus(`memuat block #${height}...`);
    const blk = await fetchJson(`/api/block/${encodeURIComponent(height)}`);
    renderBlock(blk);
    setStatus(`block #${height} loaded.`, "success");
  } catch (err) {
    setStatus(`gagal load latest block: ${err.message}`, "error");
  }
}

async function searchInput(query) {
  const q = String(query || "").trim();
  if (!q) return;

  const isHex64 = /^[0-9a-f]{64}$/i.test(q);
  const isHeight = /^\d{1,9}$/.test(q);
  const isAddress = q.toLowerCase().startsWith("tsar") && q.length >= 20;
  const isArtId = q.toLowerCase().startsWith("graf") && q.length === 64;
  const qLower = q.toLowerCase();

  try {
    setStatus("mencari...");

    if (isArtId) {
      const [post, comments] = await Promise.all([
        fetchJson(`/api/graffiti/${encodeURIComponent(qLower)}`),
        fetchJson(`/api/graffiti/${encodeURIComponent(qLower)}/comments`),
      ]);
      renderGraffiti(post, comments);
      return setStatus("graffiti loaded.", "success");
    }

    if (isAddress) {
      const addr = await fetchJson(`/api/address/${encodeURIComponent(qLower)}`);
      renderAddress(addr);
      return setStatus("address loaded.", "success");
    }

    if (isHeight) {
      const blk = await fetchJson(`/api/block/${encodeURIComponent(q)}`);
      renderBlock(blk);
      return setStatus("block loaded.", "success");
    }

    if (isHex64) {
      try {
        const blk = await fetchJson(`/api/block/${encodeURIComponent(q)}`);
        renderBlock(blk);
        return setStatus("block loaded.", "success");
      } catch {
        const tx = await fetchJson(`/api/tx/${encodeURIComponent(q)}`);
        renderTx(tx);
        return setStatus("tx loaded.", "success");
      }
    }

    setStatus("input tidak dikenali.", "error");
  } catch (err) {
    setStatus(`gagal: ${err.message}`, "error");
  }
}

function applyTheme() {
  state.theme = "kremlin";
  document.body.setAttribute("data-theme", "kremlin");
  localStorage.setItem(STORAGE_THEME, "kremlin");
}

function init() {
  state.apiBase = DEFAULT_API;

  applyTheme();

  el.searchForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    searchInput(el.searchInput.value);
  });

  el.refreshOverview.addEventListener("click", () => {
    loadSnapshot();
  });
  el.loadLatest.addEventListener("click", loadLatestBlock);
  el.clearResults.addEventListener("click", () => {
    el.results.innerHTML = renderCard(
      "Result Clear",
      "<p>Masukkan query baru untuk melihat hasil.</p>"
    );
  });

  loadSnapshot();
}

init();
