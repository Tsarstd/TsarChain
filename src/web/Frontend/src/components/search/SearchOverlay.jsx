import { useEffect } from "react";
import PropTypes from "prop-types";
import SearchResultPanel from "./SearchResults";
import { IoClose } from "react-icons/io5";

const SearchOverlay = ({
  open,
  status = "idle",
  kind = "",
  result = null,
  message = "",
  onSearchClick = () => {},
  onClose,
}) => {
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

  return (
    <dialog
      className="search-overlay"
      open
      aria-modal="true"
      aria-label="Search Results"
      onClick={(e) => {
        if (e.target === e.currentTarget && onClose) {
          onClose();
        }
      }}
    >
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