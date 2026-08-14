import { useState, useEffect } from "react";
import PropTypes from "prop-types";
import { useSearchParams } from "react-router-dom";
import { RiMenuUnfoldLine } from "react-icons/ri";

import DocSidebar from "../components/docs/DocSidebar";
import DocHeader from "../components/docs/DocHeader";
import DocContentRenderer from "../components/docs/DocContentRenderer";
import DocTableOfContents from "../components/docs/DocTableOfContents";
import { getDocData, getDocById } from "../docs";

const Documentation = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  // Derive state directly from URL search params (single source of truth)
  const activeDocId = searchParams.get("doc") || "grungepaper";
  const activeLang = searchParams.get("lang") === "id" ? "id" : "en";

  const handleSelectDoc = (id) => {
    const newParams = new URLSearchParams(searchParams);
    newParams.set("doc", id);
    setSearchParams(newParams);
    globalThis.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleLangChange = (lang) => {
    const newParams = new URLSearchParams(searchParams);
    newParams.set("lang", lang);
    setSearchParams(newParams);
  };

  const docMeta = getDocById(activeDocId);
  const docData = getDocData(activeDocId);

  // Extract TOC items for right rail
  const tocItems = docData.type === "about"
    ? (activeLang === "id" ? docData.data.id_lang?.toc : docData.data.en?.toc)
    : docData.data.toc;

  const currentContent = docData.type === "about"
    ? (activeLang === "id" ? docData.data.id_lang : docData.data.en)
    : docData.data;

  // Dynamic document title
  useEffect(() => {
    document.title = `${docMeta.title} | TsarChain Documentation`;
  }, [docMeta]);

  return (
    <div className="doc-page-container">
      {/* Mobile Sticky Bar */}
      <div className="doc-mobile-trigger-bar">
        <button
          type="button"
          className="doc-mobile-trigger-btn"
          onClick={() => setMobileSidebarOpen(true)}
        >
          <RiMenuUnfoldLine size={18} />
          <span>Menu</span>
        </button>

        <div className="doc-mobile-current-title">
          {docMeta.title}
        </div>
      </div>

      <div className="doc-layout">
        {/* Left Sidebar */}
        <DocSidebar
          activeDocId={activeDocId}
          onSelectDoc={handleSelectDoc}
          isMobileOpen={mobileSidebarOpen}
          onCloseMobile={() => setMobileSidebarOpen(false)}
        />

        {/* Main Content Area */}
        <main className="doc-content-wrapper">
          <DocHeader
            docMeta={docMeta}
            activeLang={activeLang}
            onLangChange={handleLangChange}
            downloadInfo={docData.data.downloads}
            tagline={currentContent.tagline}
            author={currentContent.author}
          />

          <DocContentRenderer
            docData={docData}
            activeLang={activeLang}
          />
        </main>

        {/* Right Table of Contents */}
        <aside className="doc-toc-wrapper">
          <DocTableOfContents items={tocItems} />
        </aside>
      </div>
    </div>
  );
};

Documentation.propTypes = {
  onSearchClick: PropTypes.func,
};

export default Documentation;
