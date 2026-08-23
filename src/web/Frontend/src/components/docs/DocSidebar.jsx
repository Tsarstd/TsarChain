import { useState, useMemo } from "react";
import PropTypes from "prop-types";
import { 
  RiSearchLine, 
  RiBook2Line, 
  RiCompass3Line, 
  RiCpuLine, 
  RiCloseLine,
  RiArrowRightSLine
} from "react-icons/ri";
import { DOC_CATEGORIES } from "../../docs/docNavigation";

const CATEGORY_ICONS = {
  about: <RiBook2Line size={17} />,
  guides: <RiCompass3Line size={17} />,
  tsarchain: <RiCpuLine size={17} />,
};

const DocSidebar = ({ activeDocId, onSelectDoc, isMobileOpen, onCloseMobile }) => {
  const [searchTerm, setSearchTerm] = useState("");

  const filteredCategories = useMemo(() => {
    if (!searchTerm.trim()) return DOC_CATEGORIES;
    const term = searchTerm.toLowerCase().trim();

    return DOC_CATEGORIES.map((cat) => {
      const matchedItems = cat.items.filter((item) => 
        item.title.toLowerCase().includes(term) ||
        item.subtitle?.toLowerCase().includes(term) ||
        item.summary?.toLowerCase().includes(term) ||
        item.keywords?.some((k) => k.toLowerCase().includes(term))
      );
      return { ...cat, items: matchedItems };
    }).filter((cat) => cat.items.length > 0);
  }, [searchTerm]);

  return (
    <>
      {/* Mobile Backdrop */}
      {isMobileOpen && (
        <div 
          className="doc-sidebar-mobile-backdrop" 
          onClick={onCloseMobile} 
          aria-hidden="true" 
        />
      )}

      <aside className={`doc-sidebar ${isMobileOpen ? "doc-sidebar--mobile-open" : ""}`}>
        <div className="doc-sidebar-header">
          <div className="doc-sidebar-title-wrap">
            <span className="doc-sidebar-title">Documentation</span>
          </div>
          {isMobileOpen && (
            <button 
              type="button" 
              className="doc-sidebar-close-btn" 
              onClick={onCloseMobile}
              aria-label="Close sidebar"
            >
              <RiCloseLine size={20} />
            </button>
          )}
        </div>

        <div className="doc-sidebar-search">
          <RiSearchLine size={15} className="doc-search-icon" />
          <input
            type="text"
            className="doc-search-input"
            placeholder="Filter documentation..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          {searchTerm && (
            <button 
              type="button" 
              className="doc-search-clear"
              onClick={() => setSearchTerm("")}
            >
              <RiCloseLine size={14} />
            </button>
          )}
        </div>

        <nav className="doc-sidebar-nav">
          {filteredCategories.length === 0 ? (
            <div className="doc-sidebar-empty">
              No documentation found matching &ldquo;{searchTerm}&rdquo;
            </div>
          ) : (
            filteredCategories.map((category) => (
              <div key={category.id} className="doc-nav-group">
                <div className="doc-nav-group-header">
                  <span className="doc-nav-group-icon">
                    {CATEGORY_ICONS[category.id] || <RiBook2Line size={17} />}
                  </span>
                  <span className="doc-nav-group-title">{category.title}</span>
                </div>

                <ul className="doc-nav-list">
                  {category.items.map((item) => {
                    const isActive = activeDocId === item.id;
                    return (
                      <li key={item.id} className="doc-nav-item">
                        <button
                          type="button"
                          className={`doc-nav-link ${isActive ? "active" : ""}`}
                          onClick={() => {
                            onSelectDoc(item.id);
                            if (isMobileOpen && onCloseMobile) onCloseMobile();
                          }}
                        >
                          <span className="doc-nav-link-text">{item.title}</span>
                          <div className="doc-nav-link-meta">
                            {item.badge && (
                              <span className={`doc-nav-badge ${isActive ? "doc-nav-badge--active" : ""}`}>
                                {item.badge}
                              </span>
                            )}
                            {isActive && <RiArrowRightSLine size={16} className="doc-nav-active-arrow" />}
                          </div>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))
          )}
        </nav>
      </aside>
    </>
  );
};

DocSidebar.propTypes = {
  activeDocId: PropTypes.string.isRequired,
  onSelectDoc: PropTypes.func.isRequired,
  isMobileOpen: PropTypes.bool,
  onCloseMobile: PropTypes.func,
};

export default DocSidebar;
