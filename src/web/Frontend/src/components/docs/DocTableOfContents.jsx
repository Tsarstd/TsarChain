import { useEffect, useState } from "react";
import PropTypes from "prop-types";
import { RiListCheck2, RiArrowUpLine } from "react-icons/ri";

const DocTableOfContents = ({ items = [] }) => {
  const [activeId, setActiveId] = useState("");

  useEffect(() => {
    if (!items || items.length === 0) return;

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries.find((e) => e.isIntersecting);
        if (visible) {
          setActiveId(visible.target.id);
        }
      },
      {
        rootMargin: "-80px 0% -60% 0%",
        threshold: 0.1,
      }
    );

    items.forEach((item) => {
      const el = document.getElementById(item.id);
      if (el) observer.observe(el);
    });

    return () => observer.disconnect();
  }, [items]);

  const scrollToSection = (id) => {
    const el = document.getElementById(id);
    if (el) {
      const offset = 80;
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
              >
                {item.label}
              </button>
            </li>
          );
        })}
      </ul>

      <div className="doc-toc-footer">
        <button type="button" className="doc-toc-back-to-top" onClick={scrollToTop}>
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
