const handleJson = async (resp) => {
  const json = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const reason = json.error || json.status || "request_failed";
    throw new Error(reason);
  }
  return json;
};

export const searchExplorer = async (query, signal) => {
  const resp = await fetch(`/api/search?q=${encodeURIComponent(query)}`, { signal });
  return handleJson(resp);
};

export const fetchNetwork = async (signal) => {
  const resp = await fetch("/api/network", { signal });
  return handleJson(resp);
};

export const fetchByKind = async (kind, id, signal) => {
  const map = {
    block: `/api/block/${encodeURIComponent(id)}`,
    block_hash: `/api/block/${encodeURIComponent(id)}`,
    block_height: `/api/block/${encodeURIComponent(id)}`,
    tx: `/api/tx/${encodeURIComponent(id)}`,
    txid_hash: `/api/tx/${encodeURIComponent(id)}`,
    address: `/api/address/${encodeURIComponent(id)}`,
    graffiti: `/api/graffiti/${encodeURIComponent(id)}`,
    art_id: `/api/graffiti/${encodeURIComponent(id)}`,
  };
  const url = map[kind];
  if (!url) throw new Error("unknown_kind");
  const resp = await fetch(url, { signal });
  return handleJson(resp);
};

export const fetchReceipt = async (txid, signal) => {
  const resp = await fetch(`/api/receipt?txid=${encodeURIComponent(txid)}`, { signal });
  return handleJson(resp);
};

export const fetchHistoryBook = async (address, signal) => {
  const resp = await fetch(`/api/history_book?address=${encodeURIComponent(address)}`, { signal });
  return handleJson(resp);
};

export const fetchGraffitiList = async ({ limit = 24, offset = 0 } = {}, signal) => {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  });
  const resp = await fetch(`/api/graffiti?${params.toString()}`, { signal });
  return handleJson(resp);
};

export const fetchGraffitiDetail = async (artId, signal) => {
  const resp = await fetch(`/api/graffiti/${encodeURIComponent(artId)}`, { signal });
  return handleJson(resp);
};

export const graffitiMediaUrl = (artId) => `/api/graffiti/${encodeURIComponent(artId)}/media`;

export const fetchBlockRange = async (params = {}, signal) => {
  const { startHeight, limit = 200, source = 'database' } = params;
  
  const queryParams = new URLSearchParams({
    limit: limit.toString(),
  });
  
  if (startHeight !== null && startHeight !== undefined) {
    queryParams.append('start_height', startHeight.toString());
  }
  
  if (source === 'database') {
    queryParams.append('prefer_database', 'true');
  }
  
  const response = await fetch(`/api/blocks?${queryParams.toString()}`, { signal });
  
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  
  return response.json();
};
