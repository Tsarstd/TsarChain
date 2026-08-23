import { useState, useEffect, useMemo, useCallback } from "react";
import PropTypes from "prop-types";
import { CrtContext } from "./useCrt";

const CRT_STORAGE_KEY = "tsar_crt_mode";

export const CrtProvider = ({ children }) => {
  const [isCrtEnabled, setIsCrtEnabled] = useState(() => {
    try {
      const saved = localStorage.getItem(CRT_STORAGE_KEY);
      if (saved !== null) {
        return saved === "true";
      }
      return true; // Default ON for Tsar Studio signature aesthetic
    } catch {
      return true;
    }
  });

  // Sync class on documentElement for global styling
  useEffect(() => {
    try {
      localStorage.setItem(CRT_STORAGE_KEY, String(isCrtEnabled));
    } catch (e) {
      console.warn("Could not save CRT preference to localStorage", e);
    }

    const root = document.documentElement;
    if (isCrtEnabled) {
      root.classList.add("crt-mode-active");
    } else {
      root.classList.remove("crt-mode-active");
    }
  }, [isCrtEnabled]);

  const toggleCrt = useCallback(() => {
    setIsCrtEnabled((prev) => !prev);
  }, []);

  const setCrt = useCallback((val) => {
    setIsCrtEnabled(Boolean(val));
  }, []);

  const value = useMemo(
    () => ({
      isCrtEnabled,
      toggleCrt,
      setCrtEnabled: setCrt,
    }),
    [isCrtEnabled, toggleCrt, setCrt]
  );

  return <CrtContext.Provider value={value}>{children}</CrtContext.Provider>;
};

CrtProvider.propTypes = {
  children: PropTypes.node.isRequired,
};

export default CrtProvider;
