import { useState } from "react";
import PropTypes from "prop-types";
import { 
  RiDownloadLine, 
  RiExternalLinkLine, 
  RiTranslate2, 
  RiShareLine,
  RiCheckLine
} from "react-icons/ri";

const DocHeader = ({ 
  docMeta, 
  activeLang, 
  onLangChange, 
  downloadInfo, 
  tagline,
  author 
}) => {
  const [copiedLink, setCopiedLink] = useState(false);

  const handleCopyLink = () => {
    const url = globalThis.location.href;
    navigator.clipboard.writeText(url);
    setCopiedLink(true);
    setTimeout(() => setCopiedLink(false), 2000);
  };

  const activeDownload = downloadInfo ? (downloadInfo[activeLang] || downloadInfo.en) : null;

  return (
    <header className="doc-content-header">
      <div className="doc-breadcrumbs">
        <span className="doc-breadcrumb-item">Docs</span>
        <span className="doc-breadcrumb-sep">/</span>
        <span className="doc-breadcrumb-item doc-breadcrumb-category">{docMeta.category}</span>
        <span className="doc-breadcrumb-sep">/</span>
        <span className="doc-breadcrumb-item active">{docMeta.title}</span>
      </div>

      <div className="doc-title-row">
        <div className="doc-title-col">
          <div className="doc-title-badge-wrap">
            <h1 className="doc-main-title">{docMeta.title}</h1>
            {docMeta.badge && <span className="doc-header-badge">{docMeta.badge}</span>}
          </div>
          {docMeta.subtitle && <p className="doc-subtitle">{docMeta.subtitle}</p>}
          {tagline && <p className="doc-tagline">&ldquo;{tagline}&rdquo;</p>}
          {author && <div className="doc-author-meta">{author}</div>}
        </div>

        {/* Action Toolbar */}
        <div className="doc-actions-col">
          {/* Language Switcher (EN | ID) for multilingual docs */}
          {docMeta.hasMultilingual && (
            <div className="doc-lang-switcher">
              <div className="doc-lang-switcher-label">
                <RiTranslate2 size={15} />
                <span>Lang</span>
              </div>
              <div className="doc-lang-pills">
                <button
                  type="button"
                  className={`doc-lang-pill ${activeLang === "en" ? "active" : ""}`}
                  onClick={() => onLangChange("en")}
                >
                  EN
                </button>
                <span className="doc-lang-divider">|</span>
                <button
                  type="button"
                  className={`doc-lang-pill ${activeLang === "id" ? "active" : ""}`}
                  onClick={() => onLangChange("id")}
                >
                  ID
                </button>
              </div>
            </div>
          )}

          {/* Download Official Document Button */}
          {activeDownload && (
            <a
              href={activeDownload.url}
              target="_blank"
              rel="noopener noreferrer"
              className="doc-btn-download"
              title={`Download ${activeDownload.label} (Google Drive)`}
            >
              <RiDownloadLine size={16} />
              <span>Download PDF</span>
              <RiExternalLinkLine size={13} className="doc-btn-ext-icon" />
            </a>
          )}

          {/* Quick Share Link */}
          <button
            type="button"
            className="doc-btn-share"
            onClick={handleCopyLink}
            title="Copy link to this document"
          >
            {copiedLink ? <RiCheckLine size={16} color="#22c55e" /> : <RiShareLine size={16} />}
          </button>
        </div>
      </div>
    </header>
  );
};

DocHeader.propTypes = {
  docMeta: PropTypes.shape({
    title: PropTypes.string.isRequired,
    subtitle: PropTypes.string,
    category: PropTypes.string.isRequired,
    badge: PropTypes.string,
    hasMultilingual: PropTypes.bool,
  }).isRequired,
  activeLang: PropTypes.string.isRequired,
  onLangChange: PropTypes.func.isRequired,
  downloadInfo: PropTypes.object,
  tagline: PropTypes.string,
  author: PropTypes.string,
};

export default DocHeader;
