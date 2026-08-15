import { useEffect, useState, useCallback } from "react";
import PropTypes from "prop-types";
import { RiListCheck2, RiArrowUpLine } from "react-icons/ri";

const DocTableOfContents = ({ items = [] }) => {
  const [activeId, setActiveId] = useState("");

  const handleScrollSpy = useCallback(() => {
    if (!items || items.length === 0) return;

    const scrollY = globalThis.scrollY || document.documentElement.scrollTop;
    const headerOffset = 140;

    // Check if bottom of page is reached
    if (globalThis.innerHeight + scrollY >= document.documentElement.scrollHeight - 50) {
      if (items.length > 0) {
        setActiveId(items[items.length - 1].id);
        return;
      }
    }

    // Find the section currently in viewport
    let currentId = items[0]?.id || "";
    for (const item of items) {
      const el = document.getElementById(item.id);
      if (el) {
        const top = el.getBoundingClientRect().top + scrollY;
        if (scrollY >= top - headerOffset) {
          currentId = item.id;
        }
      }
    }

    if (currentId) {
      setActiveId(currentId);
    }
  }, [items]);

  useEffect(() => {
    if (!items || items.length === 0) return;

    handleScrollSpy();
    globalThis.addEventListener("scroll", handleScrollSpy, { passive: true });
    return () => {
      globalThis.removeEventListener("scroll", handleScrollSpy);
    };
  }, [items, handleScrollSpy]);

  const scrollToSection = (id) => {
    const el = document.getElementById(id);
    if (el) {
      const offset = 90;
      const bodyRect = document.body.getBoundingClientRect().top;
      const elementRect = el.getBoundingClientRect().top;
      const elementPosition = elementRect - bodyRect;
      const offsetPosition = elementPosition - offset;

      globalThis.scrollTo({
        top: offsetPosition,
        behavior: "smooth"
      });
      setActiveId(id);
    }
  };

  const scrollToTop = () => {
    globalThis.scrollTo({ top: 0, behavior: "smooth" });
  };

  if (!items || items.length === 0) return null;

  return (
    <nav className="doc-toc-container" aria-label="Table of contents">
      <div className="doc-toc-header">
        <RiListCheck2 size={16} />
        <span>On This Page</span>
      </div>

      <ul className="doc-toc-list">
        {items.map((item) => {
          const isActive = activeId === item.id;
          return (
            <li key={item.id} className="doc-toc-item">
              <button
                type="button"
                className={`doc-toc-link ${isActive ? "active" : ""}`}
                onClick={() => scrollToSection(item.id)}
                aria-current={isActive ? "true" : undefined}
              >
                {item.label}
              </button>
            </li>
          );
        })}
      </ul>

      <div className="doc-toc-footer">
        <button 
          type="button" 
          className="doc-toc-back-to-top" 
          onClick={scrollToTop}
          aria-label="Scroll back to top of document"
        >
          <RiArrowUpLine size={15} />
          <span>Back to Top</span>
        </button>
      </div>
    </nav>
  );
};

DocTableOfContents.propTypes = {
  items: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.string.isRequired,
      label: PropTypes.string.isRequired,
    })
  ),
};

export default DocTableOfContents;
