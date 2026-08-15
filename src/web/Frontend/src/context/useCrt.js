import { createContext, useContext } from "react";

export const CrtContext = createContext({
  isCrtEnabled: true,
  toggleCrt: () => {},
  setCrtEnabled: () => {},
});

export const useCrt = () => {
  const context = useContext(CrtContext);
  if (!context) {
    throw new Error("useCrt must be used within a CrtProvider");
  }
  return context;
};

export default useCrt;
