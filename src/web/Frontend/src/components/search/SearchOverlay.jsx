import { useState, useEffect } from "react";
import PropTypes from "prop-types";
import SearchResultPanel from "./SearchResults";
import { IoClose, IoTrashOutline, IoTimeOutline } from "react-icons/io5";
import { getSearchHistory, clearSearchHistory, removeSearchHistoryItem } from "../../utils/searchHistory";

const SearchOverlay = ({
  open,
  status = "idle",
  kind = "",
  result = null,
  message = "",
  onSearchClick = () => {},
  onClose,
}) => {
  const [historyKey, setHistoryKey] = useState(0);

  // Handle ESC key
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Escape" && open && onClose) {
        onClose();
      }
    };
    globalThis.addEventListener("keydown", handleKeyDown);
    return () => globalThis.removeEventListener("keydown", handleKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  const history = getSearchHistory();

  const handleClearHistory = () => {
    clearSearchHistory();
    setHistoryKey((k) => k + 1);
  };

  const handleRemoveHistoryItem = (item, e) => {
    e.stopPropagation();
    removeSearchHistoryItem(item);
    setHistoryKey((k) => k + 1);
  };

  return (
    <dialog className="search-overlay" open aria-modal="true" aria-label="Search Results" key={historyKey}>
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

        <SearchResultPanel
          status={status}
          result={result}
          kind={kind}
          message={message}
          onSearchClick={onSearchClick}
        />
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

export default SearchOverlay;