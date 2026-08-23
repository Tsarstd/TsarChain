import { createContext, useContext } from "react";

export const ToastContext = createContext({
  showToast: () => {},
});

export const useToast = () => useContext(ToastContext);

let globalShowToast = null;

export const setGlobalShowToast = (fn) => {
  globalShowToast = fn;
};

export const toast = (message, type = "success") => {
  if (globalShowToast) {
    globalShowToast(message, type);
  }
};
