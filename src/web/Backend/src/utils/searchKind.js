const ART_ID_PREFIX = "graf";
const ART_ID_TOTAL_LEN = 64;

const isHex64 = (s) => /^[0-9a-fA-F]{64}$/.test(s || "");

function guessKind(raw) {
  const q = (raw || "").trim();
  if (!q) return "unknown";

  const lower = q.toLowerCase();
  if (lower.startsWith(ART_ID_PREFIX)) return "art_id";
  if (lower.startsWith("tsar") && q.length >= 20) return "address";
  if (/^\d{1,7}$/.test(q)) return "block_height";
  
  if (isHex64(q)) {
    return "hash64";
  }
  
  return "unknown";
}

module.exports = { guessKind, isHex64, ART_ID_PREFIX, ART_ID_TOTAL_LEN };