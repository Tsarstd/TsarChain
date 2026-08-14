const HISTORY_KEY = "tsar_search_history";

export const getSearchHistory = () => {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    console.warn("Read search history error:", e);
    return [];
  }
};

export const saveSearchHistory = (query) => {
  if (!query || typeof query !== "string" || !query.trim()) return [];
  const cleaned = query.trim();
  try {
    const prev = getSearchHistory();
    const updated = [cleaned, ...prev.filter((item) => item.toLowerCase() !== cleaned.toLowerCase())].slice(0, 8);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
    return updated;
  } catch (e) {
    console.warn("Save search history error:", e);
    return [];
  }
};

export const clearSearchHistory = () => {
  try {
    localStorage.removeItem(HISTORY_KEY);
  } catch (e) {
    console.warn("Clear history error:", e);
  }
};

export const removeSearchHistoryItem = (item) => {
  try {
    const prev = getSearchHistory();
    const updated = prev.filter((h) => h !== item);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
    return updated;
  } catch (err) {
    console.warn("Remove history item error:", err);
    return [];
  }
};
