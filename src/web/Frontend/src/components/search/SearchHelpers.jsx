import { useState, useEffect } from "react";
import { ClickableValue } from "./SearchResults";
import { formatHashForDisplay, getMaxCharsPerLine } from "../../utils/format";
import { copyText } from "../../utils/clipboard";
export { useScrambleText } from "../../utils/useScrambleText";

// ---------- Hook untuk deteksi mobile ----------
export const useMobile = () => {
  const [isMobile, setIsMobile] = useState(false);
  const [maxCharsPerLine, setMaxCharsPerLine] = useState(getMaxCharsPerLine());

  useEffect(() => {
    const checkMobile = () => {
      const mobile = (globalThis.window?.innerWidth ?? 1200) <= 768;
      setIsMobile(mobile);
      setMaxCharsPerLine(getMaxCharsPerLine());
    };
    checkMobile();
    globalThis.addEventListener('resize', checkMobile);
    return () => globalThis.removeEventListener('resize', checkMobile);
  }, []);

  return { isMobile, maxCharsPerLine };
};

// ---------- Hook yang mengembalikan fungsi render dengan closure ----------
export const useRenderHelpers = () => {
  const { isMobile, maxCharsPerLine } = useMobile();

  const renderHash = (hash, className = "", isCopyable = true) => {
    if (!hash) {
      return <span className={`value ${className}`}>-</span>;
    }
    const display = isMobile ? formatHashForDisplay(hash, maxCharsPerLine) : hash;
    if (!isCopyable) {
      return (
        <span className={`value ${className}`.trim()} style={isMobile ? { whiteSpace: 'pre-wrap' } : undefined}>
          {display}
        </span>
      );
    }
    return (
      <ClickableValue
        value={hash}
        className={className}
        info={hash}
        isCopyable={true}
        style={isMobile ? { whiteSpace: 'pre-wrap' } : undefined}
      >
        {display}
      </ClickableValue>
    );
  };

  const renderClickableHash = (value, onSearchClick, info, displayValue = null, isCopyable = true) => {
    if (!value) {
      return <span className="value">-</span>;
    }
    const display = displayValue || value;
    if (isMobile) {
      const formattedHash = formatHashForDisplay(display, maxCharsPerLine);
      return (
        <ClickableValue
          value={value}
          onSearchClick={onSearchClick}
          className="value hash-multiline"
          info={info}
          isCopyable={isCopyable}
          style={{ whiteSpace: 'pre-wrap' }}
        >
          {formattedHash}
        </ClickableValue>
      );
    }
    return (
      <ClickableValue
        value={value}
        onSearchClick={onSearchClick}
        className="value"
        info={info}
        isCopyable={isCopyable}
      >
        {display}
      </ClickableValue>
    );
  };

  return { renderHash, renderClickableHash };
};

// ---------- Fungsi copy ke clipboard terpusat ----------
export const copyToClipboard = async (text, setCopyStatus) => {
  const success = await copyText(text);
  if (setCopyStatus) {
    setCopyStatus(success ? "Copied!" : "Failed!");
    setTimeout(() => setCopyStatus(""), 2000);
  }
};