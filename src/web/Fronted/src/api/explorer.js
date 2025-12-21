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
