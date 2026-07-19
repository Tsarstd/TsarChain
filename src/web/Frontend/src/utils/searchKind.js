const ART_ID_PREFIX = "graf";
const ART_ID_TOTAL_LEN = 64;

export const isHex64 = (s) => /^[0-9a-fA-F]{64}$/.test(s || "");

export function guessKind(raw) {
  const q = (raw || "").trim();
  if (!q) return "unknown";

  if (q.startsWith(ART_ID_PREFIX) && q.length === ART_ID_TOTAL_LEN) return "art_id";
  if (q.startsWith("tsar") && q.length >= 20) return "address";
  if (/^\d{1,7}$/.test(q)) return "block_height";
  
  if (isHex64(q)) {
    return "txid_hash";
  }
  
  return "unknown";
}
