import { useState, useEffect, useCallback, useRef } from "react";

const DEFAULT_CHARS = "ABCDEF0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`";

const getRandomChar = (charset) => {
  const chars = charset || DEFAULT_CHARS;
  return chars[Math.floor(Math.random() * chars.length)];
};

export const useScrambleText = (targetText, options = {}) => {
  const {
    speed = 25,
    duration = 700,
    scrambleDuration,
    preservePrefix = 0,
    charset = DEFAULT_CHARS,
    trigger = true,
  } = options;

  const totalDuration = scrambleDuration || duration;
  const [displayText, setDisplayText] = useState(targetText || "");
  const [isScrambling, setIsScrambling] = useState(false);
  const animFrameRef = useRef(null);

  const runScramble = useCallback(() => {
    if (!targetText) {
      setDisplayText("");
      setIsScrambling(false);
      return;
    }

    if (animFrameRef.current) {
      cancelAnimationFrame(animFrameRef.current);
    }

    setIsScrambling(true);
    const totalLen = targetText.length;
    const prefixLen = Math.min(Math.max(0, preservePrefix), totalLen);
    const scrambleLen = totalLen - prefixLen;

    if (scrambleLen <= 0) {
      setDisplayText(targetText);
      setIsScrambling(false);
      return;
    }

    const startTime = performance.now();
    let lastTick = 0;

    const update = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / totalDuration, 1);
      const resolvedCount = Math.floor(progress * scrambleLen);

      if (now - lastTick >= speed || progress >= 1) {
        lastTick = now;

        let result = "";
        if (prefixLen > 0) {
          result += targetText.slice(0, prefixLen);
        }

        for (let i = 0; i < scrambleLen; i++) {
          const char = targetText[prefixLen + i];
          if (char === " " || char === "\n") {
            result += char;
          } else if (i < resolvedCount || progress >= 1) {
            result += char;
          } else {
            result += getRandomChar(charset);
          }
        }

        setDisplayText(result);
      }

      if (progress < 1) {
        animFrameRef.current = requestAnimationFrame(update);
      } else {
        setDisplayText(targetText);
        setIsScrambling(false);
        animFrameRef.current = null;
      }
    };

    animFrameRef.current = requestAnimationFrame(update);
  }, [targetText, preservePrefix, totalDuration, speed, charset]);

  useEffect(() => {
    if (!trigger || !targetText) {
      const rafId = requestAnimationFrame(() => {
        setDisplayText(targetText || "");
      });
      return () => cancelAnimationFrame(rafId);
    }
    const rafId = requestAnimationFrame(() => {
      runScramble();
    });
    return () => {
      cancelAnimationFrame(rafId);
      if (animFrameRef.current) {
        cancelAnimationFrame(animFrameRef.current);
      }
    };
  }, [trigger, targetText, runScramble]);

  return { displayText, isScrambling, replay: runScramble };
};

export default useScrambleText;
