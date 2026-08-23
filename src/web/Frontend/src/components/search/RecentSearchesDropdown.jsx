import { useState, useMemo, useEffect, useRef } from "react";
import PropTypes from "prop-types";
import { IoTimeOutline, IoTrashOutline, IoClose } from "react-icons/io5";
import {
  getSearchHistory,
  clearSearchHistory,
  removeSearchHistoryItem,
} from "../../utils/searchHistory";

const RecentSearchesDropdown = ({
  isOpen,
  query = "",
  onSelect,
  activeIndex = -1,
  className = "",
}) => {
  const [cleared, setCleared] = useState(false);
  const [removed, setRemoved] = useState(() => new Set());
  const dropdownRef = useRef(null);

  // Prevent input blur when clicking inside dropdown
  useEffect(() => {
    const el = dropdownRef.current;
    if (!el) return;

    const handleMouseDown = (e) => {
      e.preventDefault();
    };

    el.addEventListener("mousedown", handleMouseDown);
    return () => {
      el.removeEventListener("mousedown", handleMouseDown);
    };
  }, [isOpen]);

  const cleanQuery = query?.trim().toLowerCase() || "";
  const filtered = useMemo(() => {
    if (!isOpen || cleared) return [];
    const all = getSearchHistory().filter((item) => !removed.has(item));
    if (!cleanQuery) return all;
    return all.filter((item) => item.toLowerCase().includes(cleanQuery));
  }, [isOpen, cleared, removed, cleanQuery]);

  if (!isOpen || filtered.length === 0) {
    return null;
  }

  const handleClearAll = (e) => {
    e.preventDefault();
    e.stopPropagation();
    clearSearchHistory();
    setCleared(true);
  };

  const handleRemoveItem = (e, item) => {
    e.preventDefault();
    e.stopPropagation();
    removeSearchHistoryItem(item);
    setRemoved((prev) => new Set([...prev, item]));
  };

  return (
    <section
      ref={dropdownRef}
      className={`recent-searches-dropdown ${className}`.trim()}
      aria-label="Recent Searches"
    >
      <div className="recent-searches-dropdown__header">
        <span className="recent-searches-dropdown__title">
          <IoTimeOutline className="recent-searches-dropdown__title-icon" />
          Recent Searches
        </span>
        <button
          type="button"
          className="recent-searches-dropdown__clear-btn"
          onClick={handleClearAll}
          title="Clear all recent search history"
        >
          <IoTrashOutline /> Clear
        </button>
      </div>

      <ul className="recent-searches-dropdown__list">
        {filtered.map((item, idx) => {
          const isActive = idx === activeIndex;
          return (
            <li
              key={item}
              className={`recent-searches-dropdown__item ${isActive ? "active" : ""}`}
            >
              <button
                type="button"
                className="recent-searches-dropdown__item-btn"
                onClick={() => onSelect?.(item)}
                title={item}
              >
                <IoTimeOutline className="recent-searches-dropdown__item-icon" />
                <span className="recent-searches-dropdown__item-text">
                  {item}
                </span>
              </button>
              <button
                type="button"
                className="recent-searches-dropdown__remove-btn"
                onClick={(e) => handleRemoveItem(e, item)}
                title="Remove item"
                aria-label={`Remove ${item} from search history`}
              >
                <IoClose />
              </button>
            </li>
          );
        })}
      </ul>

      <div className="recent-searches-dropdown__footer">
        <span className="recent-searches-dropdown__hint">
          <kbd className="recent-searches-dropdown__kbd">↑↓</kbd> nav
        </span>
        <span className="recent-searches-dropdown__hint">
          <kbd className="recent-searches-dropdown__kbd">↵</kbd> select
        </span>
        <span className="recent-searches-dropdown__hint">
          <kbd className="recent-searches-dropdown__kbd">ESC</kbd> close
        </span>
      </div>
    </section>
  );
};

RecentSearchesDropdown.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  query: PropTypes.string,
  onSelect: PropTypes.func.isRequired,
  activeIndex: PropTypes.number,
  className: PropTypes.string,
};

export default RecentSearchesDropdown;
