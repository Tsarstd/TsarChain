import { useState, useEffect } from "react";
import PropTypes from "prop-types";
import SearchResultPanel from "./SearchResults";
import { IoClose, IoTrashOutline, IoTimeOutline } from "react-icons/io5";

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

const SearchOverlay = ({ open, status, kind, result, message, onSearchClick, onClose }) => {
  const [history, setHistory] = useState([]);
  const [activeFilter] = useState("all");

  useEffect(() => {
    if (open) {
      setHistory(getSearchHistory());
    }
  }, [open, status]);

  // Handle ESC key
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Escape" && open) {
        onClose();
      }
    };
    globalThis.addEventListener("keydown", handleKeyDown);
    return () => globalThis.removeEventListener("keydown", handleKeyDown);
  }, [open, onClose]);

  const handleClearHistory = () => {
    try {
      localStorage.removeItem(HISTORY_KEY);
      setHistory([]);
    } catch (e) {
      console.warn("Clear history error:", e);
    }
  };

  const handleRemoveHistoryItem = (item, e) => {
    e.stopPropagation();
    try {
      const updated = history.filter((h) => h !== item);
      localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
      setHistory(updated);
    } catch (err) {
      console.warn("Remove history item error:", err);
    }
  };

  if (!open) return null;

  // Filter display kind match
  const getFilteredKind = (filter, currentKind) => {
    if (filter === "all" || filter === currentKind) {
      return currentKind;
    }
    return "filtered_mismatch";
  };
  const filteredKind = getFilteredKind(activeFilter, kind);

  return (
    <dialog className="search-overlay" open aria-modal="true" aria-label="Search Results">
      <div className="search-overlay__panel glass-panel">
        <div className="search-overlay__header">
          <div className="search-overlay__title-group">
            <h3 className="search-overlay__title">Search Explorer</h3>
            {kind && kind !== "unknown" && (
              <span className="search-kind-badge">Type: {kind.toUpperCase()}</span>
            )}
          </div>
          <button className="btn-ghost" type="button" onClick={onClose} aria-label="Close search overlay" title="Close (ESC)">
            <IoClose />
          </button>
        </div>

        {/* Search History Section */}
        {history.length > 0 && (
          <div className="search-history-section">
            <div className="search-history-header">
              <span className="search-history-title">
                <IoTimeOutline /> Recent Searches
              </span>
              <button
                type="button"
                className="clear-history-btn"
                onClick={handleClearHistory}
                title="Clear recent search history"
              >
                <IoTrashOutline /> Clear History
              </button>
            </div>
            <div className="search-history-chips">
              {history.map((item) => (
                <div key={item} className="search-chip">
                  <button
                    type="button"
                    className="chip-btn"
                    onClick={() => onSearchClick(item)}
                    title={`Search for ${item}`}
                  >
                    {item}
                  </button>
                  <button
                    type="button"
                    className="chip-remove"
                    onClick={(e) => handleRemoveHistoryItem(item, e)}
                    title="Remove item"
                    aria-label={`Remove ${item} from search history`}
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {filteredKind === "filtered_mismatch" ? (
          <div className="result-empty" style={{ margin: "20px 0" }}>
            No results under filter <strong>{activeFilter.toUpperCase()}</strong>. Detected result type is <strong>{kind?.toUpperCase()}</strong>. Switch to <strong>ALL</strong> or <strong>{kind?.toUpperCase()}</strong> tab to view.
          </div>
        ) : (
          <SearchResultPanel
            status={status}
            result={result}
            kind={kind}
            message={message}
            onSearchClick={onSearchClick}
          />
        )}
      </div>
    </dialog>
  );
};

SearchOverlay.propTypes = {
  open: PropTypes.bool.isRequired,
  status: PropTypes.oneOf(["idle", "loading", "done", "error"]),
  kind: PropTypes.string,
  result: PropTypes.object,
  message: PropTypes.string,
  onSearchClick: PropTypes.func,
  onClose: PropTypes.func.isRequired,
};

SearchOverlay.defaultProps = {
  status: "idle",
  kind: "",
  result: null,
  message: "",
  onSearchClick: () => {},
};

export default SearchOverlay;