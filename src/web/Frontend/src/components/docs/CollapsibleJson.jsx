import { useState } from "react";
import PropTypes from "prop-types";
import { motion, AnimatePresence } from "motion/react";
import { 
  RiCodeSSlashLine, 
  RiEyeLine, 
  RiEyeOffLine, 
  RiFileCopyLine, 
  RiCheckLine 
} from "react-icons/ri";

const CollapsibleJson = ({ title, subtitle, code, defaultOpen = false }) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  const [copied, setCopied] = useState(false);

  const handleCopy = (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="doc-collapsible-json">
      <div className="doc-collapsible-header">
        <button
          type="button"
          className="doc-collapsible-trigger"
          onClick={() => setIsOpen((prev) => !prev)}
          aria-expanded={isOpen}
        >
          <div className="doc-collapsible-icon-badge">
            <RiCodeSSlashLine size={18} />
          </div>
          <div className="doc-collapsible-title-wrap">
            <div className="doc-collapsible-title">{title}</div>
            {subtitle && <div className="doc-collapsible-subtitle">{subtitle}</div>}
          </div>
        </button>

        <div className="doc-collapsible-actions">
          <button
            type="button"
            className="doc-btn-copy"
            onClick={handleCopy}
            title="Copy JSON payload"
          >
            {copied ? <RiCheckLine size={15} color="#22c55e" /> : <RiFileCopyLine size={15} />}
            <span>{copied ? "Copied!" : "Copy"}</span>
          </button>

          <button
            type="button"
            className="doc-toggle-badge"
            onClick={() => setIsOpen((prev) => !prev)}
            aria-expanded={isOpen}
          >
            {isOpen ? <RiEyeOffLine size={15} /> : <RiEyeLine size={15} />}
            <span>{isOpen ? "Hide Preview" : "Show Preview"}</span>
          </button>
        </div>
      </div>

      <AnimatePresence initial={false}>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: "easeInOut" }}
            className="doc-collapsible-body"
          >
            <pre className="doc-code-block">
              <code>{code}</code>
            </pre>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

CollapsibleJson.propTypes = {
  title: PropTypes.string.isRequired,
  subtitle: PropTypes.string,
  code: PropTypes.string.isRequired,
  defaultOpen: PropTypes.bool,
};

export default CollapsibleJson;
