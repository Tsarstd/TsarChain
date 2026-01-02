import { useMemo } from "react";
import { ResultBlock } from "./category/SearchBlock";
import { ResultTx } from "./category/SearchTxid";
import { ResultAddress } from "./category/SeacrhAddress";
import { ResultGraffiti } from "./category/SearchGraffiti";
import "./search.css";


export const ClickableValue = ({ value, onSearchClick, className = "", children }) => {
  const displayValue = children || value;
  
  if (!value || value === "-" || !onSearchClick) {
    return <span className={className}>{displayValue}</span>;
  }
  
  return (
    <span
      className={`clickable-value ${className}`}
      style={{
        cursor: "pointer",
        color: "#5e9de6ff",
        transition: "color 0.2s"
      }}
      onClick={() => {
        onSearchClick(value);
      }}
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

export { ResultBlock };
export { ResultGraffiti };
export default SearchResultPanel;
