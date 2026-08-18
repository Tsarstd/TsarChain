import { useState, useMemo } from "react";
import PropTypes from "prop-types";
import { FaCopy, FaCheck } from "react-icons/fa";
import { ResultBlock } from "./category/SearchBlock";
import { ResultTx } from "./category/SearchTxid";
import { ResultAddress } from "./category/SearchAddress";
import { ResultGraffiti } from "./category/SearchGraffiti";
import { SkeletonSearch } from "../common/SkeletonLoader";
import { copyText } from "../../utils/clipboard";

export const ClickableValue = ({
  value,
  onSearchClick,
  className = "",
  info,
  style,
  isCopyable = true,
  children
}) => {
  const [copied, setCopied] = useState(false);
  const displayValue = children || value;

  if (!value || value === "-") {
    return <span className={className} style={style}>{displayValue}</span>;
  }

  const handleCopy = async (e) => {
    e.stopPropagation();
    if (!value || value === "-") return;
    const success = await copyText(value);
    if (success) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const finalClassName = `value ${className}`.replace(/\bmuted\b/g, '').replace(/\s+/g, ' ').trim();
  const currentTooltip = copied ? "Copied!" : info;
  const showCopyBtn = isCopyable && value && value !== "-";

  return (
    <span className="clickable-value-container" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', maxWidth: '100%', ...style }}>
      {onSearchClick ? (
        <a
          href={`/?search=${encodeURIComponent(value)}`}
          className={`clickable-link ${finalClassName}`}
          onClick={(e) => {
            if (e.ctrlKey || e.metaKey || e.shiftKey || e.button === 1) {
              return;
            }
            e.preventDefault();
            onSearchClick(value);
          }}
          data-tooltip={currentTooltip || undefined}
        >
          {displayValue}
        </a>
      ) : (
        <span
          className={finalClassName}
          data-tooltip={currentTooltip || undefined}
        >
          {displayValue}
        </span>
      )}

      {showCopyBtn && (
        <button
          type="button"
          className="copy-btn-inline"
          onClick={handleCopy}
          aria-label="Copy to clipboard"
          data-tooltip={copied ? "Copied!" : "Copy"}
        >
          {copied ? (
            <FaCheck style={{ color: "#10b981", fontSize: "11px" }} />
          ) : (
            <FaCopy style={{ fontSize: "11px", opacity: 0.6 }} />
          )}
        </button>
      )}
    </span>
  );
};

ClickableValue.propTypes = {
  value: PropTypes.string,
  onSearchClick: PropTypes.func,
  className: PropTypes.string,
  info: PropTypes.string,
  style: PropTypes.object,
  isCopyable: PropTypes.bool,
  children: PropTypes.node,
};

const SearchResultPanel = ({ status, result, kind, message, onSearchClick }) => {
  const body = useMemo(() => {
    if (status === "loading")
      return <SkeletonSearch />;
    if (status === "error")
      return (
        <div className="result-empty">{message || "An error occurred, please try again.."}</div>
      );
    if (!result)
      return (
        <div className="result-empty">There is no result for this query.</div>
      );
    if (kind === "block" || kind === "block_height" || kind === "block_hash" || (kind === "hash64" && result?.hash))
      return <ResultBlock data={result} onSearchClick={onSearchClick} />;
    if (kind === "tx" || kind === "txid_hash" || (kind === "hash64" && result?.txid))
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
