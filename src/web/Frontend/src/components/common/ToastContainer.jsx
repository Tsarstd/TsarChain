import { useState, useEffect, useCallback, useMemo } from "react";
import PropTypes from "prop-types";
import { FaCheckCircle, FaExclamationCircle, FaInfoCircle } from "react-icons/fa";
import { ToastContext, setGlobalShowToast } from "../../utils/toast";

let toastSeq = 0;
const generateId = () => {
  if (typeof globalThis.crypto?.randomUUID === "function") {
    return globalThis.crypto.randomUUID();
  }
  toastSeq += 1;
  return `toast_${Date.now()}_${toastSeq}`;
};

const ToastIcon = ({ type }) => {
  if (type === "error") {
    return <FaExclamationCircle />;
  }
  if (type === "info") {
    return <FaInfoCircle />;
  }
  return <FaCheckCircle />;
};

ToastIcon.propTypes = {
  type: PropTypes.string,
};

export const ToastProvider = ({ children }) => {
  const [toasts, setToasts] = useState([]);

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const showToast = useCallback((message, type = "success") => {
    const id = generateId();
    setToasts((prev) => [...prev, { id, message, type }]);

    setTimeout(() => {
      removeToast(id);
    }, 2800);
  }, [removeToast]);

  useEffect(() => {
    setGlobalShowToast(showToast);
    return () => {
      setGlobalShowToast(null);
    };
  }, [showToast]);

  const contextValue = useMemo(() => ({ showToast }), [showToast]);

  return (
    <ToastContext.Provider value={contextValue}>
      {children}
      <div className="toast-container" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast-item toast-${t.type}`}>
            <div className="toast-icon">
              <ToastIcon type={t.type} />
            </div>
            <div className="toast-message">{t.message}</div>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
};

ToastProvider.propTypes = {
  children: PropTypes.node.isRequired,
};

export default ToastProvider;
