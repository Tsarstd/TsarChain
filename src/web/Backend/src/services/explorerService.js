const { guessKind } = require("../utils/searchKind");
const { rpcCall } = require("../tsarRpcAdapter");

const pick = (obj, ...keys) => {
  if (!obj || typeof obj !== "object") return undefined;
  const meta = obj._meta && typeof obj._meta === "object" ? obj._meta : null;
  for (const key of keys) {
    if (obj[key] !== undefined && obj[key] !== null && obj[key] !== "") return obj[key];
    if (meta && meta[key] !== undefined && meta[key] !== null && meta[key] !== "") return meta[key];
  }
  return undefined;
};

const decodeCommentHex = (hex) => {
  if (!hex) return "";
  try {
    return Buffer.from(String(hex), "hex").toString("utf8");
  } catch (err) {
    return "";
  }
};

const normalizeBlock = (blk) => {
  if (!blk || typeof blk !== "object") return blk;
  const height = pick(blk, "height", "index");
  const hash = pick(blk, "hash");
  let blockId = pick(blk, "block_id");
  const prev = pick(blk, "prev_block_hash", "prev_hash", "previous_hash", "previousblockhash");
  const timestamp = pick(blk, "timestamp", "time");
  const difficulty = pick(blk, "difficulty");
  const sizeBytes = pick(blk, "size_bytes", "size");
  const chainwork = pick(blk, "chainwork");
  const bits = pick(blk, "bits");
  const version = pick(blk, "version");
  const merkleRoot = pick(blk, "merkle_root", "merkleroot");
  const nonce = pick(blk, "nonce");
  const txsRaw = blk.transactions || blk.tx || [];
  if (!blockId && Array.isArray(txsRaw) && txsRaw.length > 0) {
    const first = txsRaw[0];
    if (first && typeof first === "object") {
      blockId = first.block_id || blockId;
    }
  }
  const txs = Array.isArray(txsRaw)
    ? txsRaw.map((tx) => {
        if (typeof tx === "string") return { txid: tx, inputs: [], outputs: [] };
        if (!tx || typeof tx !== "object") return { txid: String(tx), inputs: [], outputs: [] };
        const txid = tx.txid || tx.id || tx.hash || "-";
        const inputs = tx.inputs || tx.vin || [];
        const outputs = tx.outputs || tx.vout || [];
        return {
          txid,
          inputs: Array.isArray(inputs) ? inputs : [],
          outputs: Array.isArray(outputs) ? outputs : [],
        };
      })
    : [];
  const graffiti = Array.isArray(blk.graffiti) ? blk.graffiti : [];
  const commentsRaw = Array.isArray(blk.comments) ? blk.comments : [];
  const comments = commentsRaw.map((c) => ({
    ...c,
    comment_text: c?.comment_text || decodeCommentHex(c?.comment || c?.comment_hex || ""),
  }));
  return {
    ...blk,
    height,
    hash,
    block_id: blockId,
    prev_block_hash: prev,
    timestamp,
    difficulty,
    size_bytes: sizeBytes,
    chainwork,
    bits,
    version,
    merkle_root: merkleRoot,
    nonce,
    transactions: txs,
    graffiti,
    comments,
  };
};

const normalizeBlockSummary = (blk) => {
  if (!blk || typeof blk !== "object") return blk;
  const height = pick(blk, "height", "index");
  const hash = pick(blk, "hash");
  const timestamp = pick(blk, "timestamp", "time");
  const sizeBytes = pick(blk, "size_bytes", "size");
  const txCountRaw =
    blk.tx_count ??
    (Array.isArray(blk.transactions)
      ? blk.transactions.length
      : Array.isArray(blk.tx)
        ? blk.tx.length
        : 0);
  const graffitiPosts = Number(blk.graffiti_posts ?? 0);
  const graffitiComments = Number(blk.graffiti_comments ?? 0);
  const graffitiCount = Number(
    blk.graffiti_count ?? graffitiPosts + graffitiComments
  );
  return {
    ...blk,
    height,
    hash,
    timestamp,
    size_bytes: sizeBytes,
    tx_count: Number(txCountRaw || 0),
    graffiti_posts: graffitiPosts,
    graffiti_comments: graffitiComments,
    graffiti_count: graffitiCount,
  };
};

const normalizeTx = (tx, fallbackTxid) => {
  if (!tx || typeof tx !== "object") return tx;
  let obj = tx;
  if (obj.tx && typeof obj.tx === "object") obj = obj.tx;
  if (obj.transaction && typeof obj.transaction === "object") obj = obj.transaction;

  const inputs = obj.inputs || obj.vin || [];
  const outputs = obj.outputs || obj.vout || [];
  const txid = obj.txid || obj.id || obj.hash || fallbackTxid;
  const confirmations = obj.confirmations || obj.conf || 0;
  const fee = obj.fee || obj.fees || 0;
  const height = obj.block_height || obj.height || "-";
  const size = obj.size || obj.vsize || obj.vbytes || "-";
  const vsize = obj.vsize || obj.vbytes || "-";
  const weight = obj.weight || "-";
  const timestamp = obj.timestamp || obj.time || null;
  const status = obj.status || (Number(confirmations || 0) > 0 ? "confirmed" : "unconfirmed");
  let isCoinbase = obj.is_coinbase;

  const normInputs = Array.isArray(inputs)
    ? inputs.map((inp) => ({
        txid: inp?.txid || inp?.prev_txid || inp?.tx || "",
        vout: inp?.vout ?? inp?.index ?? inp?.n ?? 0,
        address: inp?.address || inp?.addr || inp?.scriptpubkey_address || "",
        amount: inp?.amount ?? inp?.value ?? 0,
      }))
    : [];
  const normOutputs = Array.isArray(outputs)
    ? outputs.map((out) => ({
        address: out?.address || out?.scriptpubkey_address || "",
        amount: out?.amount ?? out?.value ?? 0,
      }))
    : [];

  if (isCoinbase === undefined && normInputs.length > 0) {
    const prev = String(normInputs[0]?.txid || "");
    isCoinbase = prev === "0".repeat(64) || Boolean(inputs?.[0]?.coinbase);
  }

  return {
    ...obj,
    txid,
    confirmations,
    fee,
    block_height: height,
    size,
    vsize,
    weight,
    timestamp,
    status,
    is_coinbase: Boolean(isCoinbase),
    inputs: normInputs,
    outputs: normOutputs,
  };
};

const normalizeAddress = (addr) => {
  if (!addr || typeof addr !== "object") return addr;
  const utxos = Array.isArray(addr.utxos) ? addr.utxos : [];
  const balance = addr.balance ?? utxos.reduce((sum, u) => sum + Number(u.amount || 0), 0);
  return {
    ...addr,
    balance,
    utxos,
    history: Array.isArray(addr.history) ? addr.history : [],
  };
};

const normalizeGraffitiPost = (post) => {
  if (!post || typeof post !== "object") return post;
  const artId = post.art_id || post.artId;
  return {
    ...post,
    art_id: artId,
    preview_url: artId ? `/api/graffiti/${artId}/media` : null,
  };
};

const normalizeGraffitiDetail = (payload) => {
  if (!payload || typeof payload !== "object") return null;
  const postSource = payload.post || payload;
  if (!postSource || typeof postSource !== "object") return null;
  const post = normalizeGraffitiPost(postSource);
  if (!post?.art_id) return null;
  const commentsRaw = payload.comments || post?.comments || [];
  const comments = Array.isArray(commentsRaw)
    ? commentsRaw.map((c) => ({
        ...c,
        comment_text: c?.comment_text || decodeCommentHex(c?.comment || c?.comment_hex || ""),
      }))
    : [];
  return { ...post, comments };
};

class ExplorerService {
  constructor(options = {}) {
    this.nodeHost = options.nodeHost;
    this.nodePort = options.nodePort;
  }

  async getNetwork() {
    const res = await rpcCall("network", null, this.nodeHost, this.nodePort);
    return res;
  }

  async getBlock(id) {
    const blk = await rpcCall("block", id, this.nodeHost, this.nodePort);
    return normalizeBlock(blk);
  }

  async getTx(id) {
    const tx = await rpcCall("tx", id, this.nodeHost, this.nodePort);
    return normalizeTx(tx, id);
  }

  async getAddress(addr) {
    const info = await rpcCall("address", addr, this.nodeHost, this.nodePort);
    return normalizeAddress(info);
  }

  async getGraffiti(artId) {
    const resp = await rpcCall("graffiti", artId, this.nodeHost, this.nodePort);
    if (!resp) return null;
    return normalizeGraffitiDetail(resp);
  }

  async getGraffitiPosts({ limit = 24, offset = 0 } = {}) {
    const payload = JSON.stringify({ limit, offset });
    const resp = await rpcCall("graffiti_posts", payload, this.nodeHost, this.nodePort);
    const items = Array.isArray(resp?.posts)
      ? resp.posts.map(normalizeGraffitiPost).filter((item) => item?.art_id)
      : [];
    return {
      items,
      limit: resp?.limit ?? limit,
      offset: resp?.offset ?? offset,
      nextOffset: offset + items.length,
      hasMore: items.length >= (resp?.limit ?? limit),
    };
  }

  async getGraffitiMediaInfo(artId) {
    const payload = JSON.stringify({ art_id: artId });
    return rpcCall("graffiti_file", payload, this.nodeHost, this.nodePort);
  }

  async getBlockRange({ startHeight = null, limit = 10, source = 'auto' } = {}) {
    const payload = {
      limit: Number(limit || 10),
    };
    
    if (startHeight !== null && startHeight !== undefined) {
      payload.start_height = Number(startHeight);
    }
    
    // Tambahkan parameter source untuk backend
    if (source === 'database') {
      payload.use_database = true;
      payload.prefer_cache = true;
    }
    
    const resp = await rpcCall("block_range", payload, this.nodeHost, this.nodePort);
    const items = Array.isArray(resp?.items)
      ? resp.items.map(normalizeBlockSummary)
      : [];
      
    return {
      items,
      limit: resp?.limit ?? payload.limit,
      startHeight: resp?.start_height ?? payload.start_height ?? null,
      tipHeight: resp?.tip_height ?? null,
      nextHeight: resp?.next_height ?? resp?.nextHeight ?? null,
      hasMore: Boolean(resp?.has_more ?? resp?.hasMore),
    };
  }

  async search(query) {
    const kind = guessKind(query);
    if (kind === "unknown") {
      return { kind, data: null };
    }
    
    if (kind === "txid_hash" || kind === "block_hash") {
      // Seacrh TxID First
      try {
        const txData = await this.getTx(query);
        if (txData && txData.txid) {
          return { kind: "tx", data: txData };
        }
      } catch (err) {
      }
      
      // If TxID not found, find blockhash
      try {
        const blockData = await this.getBlock(query);
        if (blockData && blockData.hash) {
          return { kind: "block", data: blockData };
        }
      } catch (err) {
      }
      
      // Txid & blockhash not found
      return { kind: "unknown", data: null };
    }

    switch (kind) {
      case "block_height":
        return { kind: "block", data: await this.getBlock(query) };
      case "address":
        return { kind: "address", data: await this.getAddress(query) };
      case "art_id":
        return { kind: "graffiti", data: await this.getGraffiti(query) };
      default:
        return { kind: "unknown", data: null };
    }
  }
}

module.exports = { ExplorerService };
