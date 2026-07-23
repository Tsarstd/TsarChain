import { useState, useMemo } from "react";
import PropTypes from "prop-types";
import { FaCopy, FaCheck } from "react-icons/fa";
import { ResultBlock } from "./category/SearchBlock";
import { ResultTx } from "./category/SearchTxid";
import { ResultAddress } from "./category/SeacrhAddress";
import { ResultGraffiti } from "./category/SearchGraffiti";
import { SkeletonSearch } from "../common/SkeletonLoader";

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

  const handleCopy = (e) => {
    e.stopPropagation();
    if (!value || value === "-") return;
    try {
      if (navigator.clipboard?.writeText) {
        navigator.clipboard.writeText(value);
      } else {
        const textArea = document.createElement("textarea");
        textArea.value = value;
        textArea.style.position = "fixed";
        textArea.style.left = "-999999px";
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand("copy");
        textArea.remove();
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Copy failed", err);
    }
  };

  const finalClassName = `value muted ${className}`.trim();
  const currentTooltip = copied ? "Copied!" : info;
  const showCopyBtn = isCopyable && value && value !== "-";

  return (
    <span className="clickable-value-container" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', maxWidth: '100%', ...style }}>
      {onSearchClick ? (
        <button
          className={finalClassName}
          type="button"
          style={{
            cursor: "pointer",
            color: "#5e9de6ff",
            transition: "color 0.2s",
            alignSelf: "baseline",
            background: "none",
            border: "none",
            padding: 0,
            font: "inherit",
            textAlign: "inherit",
            display: "inline",
          }}
          onClick={() => onSearchClick(value)}
          data-tooltip={currentTooltip || undefined}
          onMouseEnter={(e) => (e.currentTarget.style.color = "#4d7fb7ff")}
          onMouseLeave={(e) => (e.currentTarget.style.color = "#5e9de6ff")}
        >
          {displayValue}
        </button>
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
