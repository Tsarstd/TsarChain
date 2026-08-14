import { useState, useEffect } from "react";
import { ClickableValue } from "./SearchResults";
import { formatHashForDisplay, getMaxCharsPerLine } from "../../utils/format";
import { toast } from "../../utils/toast";

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

// ---------- Fungsi copy ke clipboard ----------
export const copyToClipboard = async (text, setCopyStatus) => {
  if (!text) return;
  try {
    if (navigator.clipboard?.writeText) {
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
      const successful = document['exec' + 'Command']('copy');
      if (!successful) throw new Error('Fallback copy failed');
      textArea.remove();
    }
    setCopyStatus("Copied!");
    toast("Copied to clipboard!", "success");
    setTimeout(() => setCopyStatus(""), 2000);
  } catch (err) {
    console.error('Failed to copy:', err);
    try {
      prompt('Copy this:', text);
      setCopyStatus("Use prompt to copy");
    } catch {
      setCopyStatus("Failed!");
      toast("Failed to copy", "error");
    }
    setTimeout(() => setCopyStatus(""), 2000);
  }
};

// ---------- Hook Animasi Scramble Text ----------
export const useScrambleText = (
  text,
  {
    duration = 700,
    speed = 30,
    preservePrefix = 0,
    charset = "0123456789abcdef"
  } = {}
) => {
  const [displayText, setDisplayText] = useState(text || "");

  useEffect(() => {
    if (!text) {
      setDisplayText("");
      return;
    }

    const totalLen = text.length;
    const prefixLen = Math.min(Math.max(0, preservePrefix), totalLen);
    const scrambleLen = totalLen - prefixLen;

    if (scrambleLen <= 0) {
      setDisplayText(text);
      return;
    }

    const chars = charset || "0123456789abcdef";
    const getRandomChar = () => chars[Math.floor(Math.random() * chars.length)];

    let animationFrameId;
    const startTime = performance.now();
    let lastTick = 0;

    const update = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);

      // Karakter yang sudah ter-resolve dari payload
      const resolvedCount = Math.floor(progress * scrambleLen);

      if (now - lastTick >= speed || progress >= 1) {
        lastTick = now;

        let result = "";
        // 1. Static Prefix (misal: 'tsar')
        if (prefixLen > 0) {
          result += text.slice(0, prefixLen);
        }

        // 2. Payload scramble / resolve
        for (let i = 0; i < scrambleLen; i++) {
          if (i < resolvedCount || progress >= 1) {
            result += text[prefixLen + i];
          } else {
            result += getRandomChar();
          }
        }

        setDisplayText(result);
      }

      if (progress < 1) {
        animationFrameId = requestAnimationFrame(update);
      } else {
        setDisplayText(text);
      }
    };

    animationFrameId = requestAnimationFrame(update);

    return () => {
      if (animationFrameId) {
        cancelAnimationFrame(animationFrameId);
      }
    };
  }, [text, duration, speed, preservePrefix, charset]);

  return displayText;
};