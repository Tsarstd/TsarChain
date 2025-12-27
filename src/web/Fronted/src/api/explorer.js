const handleJson = async (resp) => {
  const json = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const reason = json.error || json.status || "request_failed";
    throw new Error(reason);
  }
  return json;
};

export const searchExplorer = async (query) => {
  const resp = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
  return handleJson(resp);
};

export const fetchNetwork = async () => {
  const resp = await fetch("/api/network");
  return handleJson(resp);
};

export const fetchByKind = async (kind, id) => {
  const map = {
    block: `/api/block/${encodeURIComponent(id)}`,
    tx: `/api/tx/${encodeURIComponent(id)}`,
    address: `/api/address/${encodeURIComponent(id)}`,
    graffiti: `/api/graffiti/${encodeURIComponent(id)}`,
  };
  const url = map[kind];
  if (!url) throw new Error("unknown_kind");
  const resp = await fetch(url);
  return handleJson(resp);
};

export const fetchGraffitiList = async ({ limit = 24, offset = 0 } = {}) => {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  });
  const resp = await fetch(`/api/graffiti?${params.toString()}`);
  return handleJson(resp);
};

export const fetchGraffitiDetail = async (artId) => {
  const resp = await fetch(`/api/graffiti/${encodeURIComponent(artId)}`);
  return handleJson(resp);
};

export const graffitiMediaUrl = (artId) => `/api/graffiti/${encodeURIComponent(artId)}/media`;

export const fetchBlockRange = async ({ startHeight, limit = 10 } = {}) => {
  const params = new URLSearchParams({
    limit: String(limit),
  });
  if (startHeight !== null && startHeight !== undefined) {
    params.set("start", String(startHeight));
  }
  const resp = await fetch(`/api/blocks?${params.toString()}`);
  return handleJson(resp);
};
