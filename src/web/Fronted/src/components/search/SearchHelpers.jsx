import { useState, useEffect } from "react";
import { ClickableValue } from "./SearchResults";
import { formatHashForDisplay, getMaxCharsPerLine } from "../../utils/format";

// ---------- Hook untuk deteksi mobile ----------
export const useMobile = () => {
  const [isMobile, setIsMobile] = useState(false);
  const [maxCharsPerLine, setMaxCharsPerLine] = useState(getMaxCharsPerLine());

  useEffect(() => {
    const checkMobile = () => {
      const mobile = window.innerWidth <= 768;
      setIsMobile(mobile);
      setMaxCharsPerLine(getMaxCharsPerLine());
    };
    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, []);

  return { isMobile, maxCharsPerLine };
};

// ---------- Hook yang mengembalikan fungsi render dengan closure ----------
export const useRenderHelpers = () => {
  const { isMobile, maxCharsPerLine } = useMobile();

  const renderHash = (hash, className = "") => {
    if (!hash) return "-";
    if (isMobile) {
      const formattedHash = formatHashForDisplay(hash, maxCharsPerLine);
      return (
        <span className={`value hash-multiline ${className}`} style={{ whiteSpace: 'pre-wrap' }}>
          {formattedHash}
        </span>
      );
    }
    return <span className={`value ${className}`}>{hash}</span>;
  };

  const renderClickableHash = (value, onSearchClick, info, displayValue = null) => {
    if (!value) return "-";
    const display = displayValue || value;
    if (isMobile) {
      const formattedHash = formatHashForDisplay(display, maxCharsPerLine);
      return (
        <ClickableValue
          value={value}
          onSearchClick={onSearchClick}
          className="value muted hash-multiline"
          info={info}
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
        className="value muted"
        info={info}
      >
        {display}
      </ClickableValue>
    );
  };

  return { renderHash, renderClickableHash };
};

// ---------- Fungsi copy ke clipboard ----------
export const copyToClipboard = async (text, setCopyStatus) => {
  if (!text) return;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.left = '-999999px';
      textArea.style.top = '-999999px';
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      const successful = document.execCommand('copy');
      if (!successful) throw new Error('Fallback copy failed');
      document.body.removeChild(textArea);
    }
    setCopyStatus("Copied!");
    setTimeout(() => setCopyStatus(""), 2000);
  } catch (err) {
    console.error('Failed to copy:', err);
    try {
      prompt('Copy this:', text);
      setCopyStatus("Use prompt to copy");
    } catch {
      setCopyStatus("Failed!");
    }
    setTimeout(() => setCopyStatus(""), 2000);
  }
};