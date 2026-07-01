import PropTypes from "prop-types"; // ← tambahkan ini
import SearchResultPanel from "./SearchResults";
import { IoClose } from "react-icons/io5";

const SearchOverlay = ({ open, status, kind, result, message, onSearchClick, onClose }) => {
  if (!open) return null;
  return (
    <div className="search-overlay" role="dialog" aria-modal="true">
      <div className="search-overlay__panel">
        <div className="search-overlay__header">
          <button className="btn-ghost" type="button" onClick={onClose}>
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
    </div>
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