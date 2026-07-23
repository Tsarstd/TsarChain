import PropTypes from "prop-types";
import SearchResultPanel from "./SearchResults";
import { IoClose } from "react-icons/io5";

const SearchOverlay = ({ open, status, kind, result, message, onSearchClick, onClose }) => {
  if (!open) return null;
  return (
    <dialog className="search-overlay" open>
      <div className="search-overlay__panel glass-panel">
        <div className="search-overlay__header">
          <button className="btn-ghost" type="button" onClick={onClose} aria-label="Close search overlay">
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

SearchOverlay.defaultProps = {
  status: "idle",
  kind: "",
  result: null,
  message: "",
  onSearchClick: () => {},
};

export default SearchOverlay;