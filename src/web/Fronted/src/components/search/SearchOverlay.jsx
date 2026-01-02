import SearchResultPanel from "./SearchResults";

const SearchOverlay = ({ open, status, kind, result, message, onSearchClick, onClose }) => {
  if (!open) return null;
  return (
    <div className="search-overlay" role="dialog" aria-modal="true">
      <div className="search-overlay__panel">
        <div className="search-overlay__header">
          <div>
            <h3>Search Result</h3>
          </div>
          <button className="btn-ghost" type="button" onClick={onClose}>
            Close
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
