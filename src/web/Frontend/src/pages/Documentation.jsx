import { useState, useEffect } from "react";
import PropTypes from "prop-types";
import { useSearchParams } from "react-router-dom";
import { RiMenuUnfoldLine, RiListCheck2 } from "react-icons/ri";

import DocSidebar from "../components/docs/DocSidebar";
import DocHeader from "../components/docs/DocHeader";
import DocContentRenderer from "../components/docs/DocContentRenderer";
import DocTableOfContents from "../components/docs/DocTableOfContents";
import { getDocData, getDocById } from "../docs";

const Documentation = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [selectedMobileSection, setSelectedMobileSection] = useState("");

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

  // Handle jumping to section on mobile
  const handleMobileSectionJump = (sectionId) => {
    if (!sectionId) return;
    setSelectedMobileSection(sectionId);
    const el = document.getElementById(sectionId);
    if (el) {
      const offset = 80;
      const bodyRect = document.body.getBoundingClientRect().top;
      const elementRect = el.getBoundingClientRect().top;
      const elementPosition = elementRect - bodyRect;
      const offsetPosition = elementPosition - offset;

      globalThis.scrollTo({
        top: offsetPosition,
        behavior: "smooth",
      });
    }
  };

  return (
    <div className="doc-page-container">
      {/* Mobile Sticky Bar with Menu & Chapter Quick Picker */}
      <div className="doc-mobile-trigger-bar">
        <div className="doc-mobile-left-controls">
          <button
            type="button"
            className="doc-mobile-trigger-btn"
            onClick={() => setMobileSidebarOpen(true)}
            aria-label="Open documentation navigation menu"
          >
            <RiMenuUnfoldLine size={18} />
            <span>Docs</span>
          </button>

          <div className="doc-mobile-current-title">
            {docMeta.title}
          </div>
        </div>

        {tocItems && tocItems.length > 0 && (
          <div className="doc-mobile-chapter-picker">
            <RiListCheck2 className="picker-icon" size={14} />
            <select
              className="doc-mobile-select"
              value={selectedMobileSection}
              onChange={(e) => handleMobileSectionJump(e.target.value)}
              aria-label="Jump to section on this page"
            >
              <option value="" disabled>Jump to chapter...</option>
              {tocItems.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </select>
          </div>
        )}
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
