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

export default SearchOverlay;
