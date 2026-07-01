import { useMemo } from "react";
import PropTypes from "prop-types";
import { ResultBlock } from "./category/SearchBlock";
import { ResultTx } from "./category/SearchTxid";
import { ResultAddress } from "./category/SeacrhAddress";
import { ResultGraffiti } from "./category/SearchGraffiti";


export const ClickableValue = ({ value, onSearchClick, className = "", info, children }) => {
  const displayValue = children || value;
  
  if (!value || value === "-" || !onSearchClick) {
    return <span className={className}>{displayValue}</span>;
  }
  
  const finalClassName = `value muted ${className}`.trim();

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onSearchClick(value);
    }
  };
  
  return (
    <span
      className={finalClassName}
      role="button"
      tabIndex={0}
      style={{
        cursor: "pointer",
        color: "#5e9de6ff",
        transition: "color 0.2s",
        alignSelf: "baseline",
      }}
      onClick={() => onSearchClick(value)}
      onKeyDown={handleKeyDown}
      data-tooltip={info}
      onMouseEnter={(e) => e.target.style.color = "#4d7fb7ff"}
      onMouseLeave={(e) => e.target.style.color = "#5e9de6ff"}
    >
      {displayValue}
    </span>
  );
};

const SearchResultPanel = ({ status, result, kind, message, onSearchClick }) => {
  const body = useMemo(() => {
    if (status === "loading")
      return <div className="result-empty">Searching...</div>;
    if (status === "error")
      return (
        <div className="result-empty">{message || "An error occurred, please try again.."}</div>
      );
    if (!result)
      return (
        <div className="result-empty">There is no result for this query.</div>
      );
    if (kind === "block" || kind === "block_height" || kind === "block_hash")
      return <ResultBlock data={result} onSearchClick={onSearchClick} />;
    if (kind === "tx" || kind === "txid_hash")
      return <ResultTx data={result} onSearchClick={onSearchClick} />;
    if (kind === "address") return <ResultAddress data={result} onSearchClick={onSearchClick} />;
    if (kind === "graffiti" || kind === "art_id")
      return <ResultGraffiti data={result} onSearchClick={onSearchClick} />;
    return <div className="result-empty">Search type not recognized.</div>;
  }, [status, result, kind, message, onSearchClick]);

  return body;
};

SearchResultPanel.propTypes = {
  status: PropTypes.oneOf(["idle", "loading", "done", "error"]),
  result: PropTypes.object,
  kind: PropTypes.string,
  message: PropTypes.string,
  onSearchClick: PropTypes.func.isRequired,
};

export { ResultBlock };
export { ResultGraffiti };
export default SearchResultPanel;
