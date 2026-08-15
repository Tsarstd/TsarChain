import { useState, useEffect, useCallback } from "react";

const CHARS = "ABCDEF0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`";

export const useScrambleText = (targetText, options = {}) => {
  const {
    speed = 25,
    scrambleDuration = 800,
    trigger = true,
  } = options;

  const [displayText, setDisplayText] = useState(targetText);
  const [isScrambling, setIsScrambling] = useState(false);

  const runScramble = useCallback(() => {
    if (!targetText) return () => {};
    setIsScrambling(true);

    const length = targetText.length;
    const startTime = Date.now();

    const interval = setInterval(() => {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / scrambleDuration, 1);
      const revealedLength = Math.floor(progress * length);

      let scrambled = "";
      for (let i = 0; i < length; i++) {
        if (targetText[i] === " " || targetText[i] === "\n") {
          scrambled += targetText[i];
        } else if (i < revealedLength) {
          scrambled += targetText[i];
        } else {
          scrambled += CHARS[Math.floor(Math.random() * CHARS.length)];
        }
      }

      setDisplayText(scrambled);

      if (progress >= 1) {
        clearInterval(interval);
        setDisplayText(targetText);
        setIsScrambling(false);
      }
    }, speed);

    return () => clearInterval(interval);
  }, [targetText, speed, scrambleDuration]);

  useEffect(() => {
    if (!trigger || !targetText) return;

    let isCancelled = false;
    Promise.resolve().then(() => {
      if (!isCancelled) setIsScrambling(true);
    });
    const length = targetText.length;
    const startTime = Date.now();

    const interval = setInterval(() => {
      if (isCancelled) return;
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / scrambleDuration, 1);
      const revealedLength = Math.floor(progress * length);

      let scrambled = "";
      for (let i = 0; i < length; i++) {
        if (targetText[i] === " " || targetText[i] === "\n") {
          scrambled += targetText[i];
        } else if (i < revealedLength) {
          scrambled += targetText[i];
        } else {
          scrambled += CHARS[Math.floor(Math.random() * CHARS.length)];
        }
      }

      setDisplayText(scrambled);

      if (progress >= 1) {
        clearInterval(interval);
        setDisplayText(targetText);
        setIsScrambling(false);
      }
    }, speed);

    return () => {
      isCancelled = true;
      clearInterval(interval);
      setIsScrambling(false);
    };
  }, [trigger, targetText, speed, scrambleDuration]);

  return { displayText, isScrambling, replay: runScramble };
};
