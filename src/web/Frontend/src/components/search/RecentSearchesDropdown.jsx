import { useState, useMemo } from "react";
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
  const [history, setHistory] = useState(() => getSearchHistory());
  const [prevIsOpen, setPrevIsOpen] = useState(isOpen);

  if (prevIsOpen !== isOpen) {
    setPrevIsOpen(isOpen);
    if (isOpen) {
      setHistory(getSearchHistory());
    }
  }

  const cleanQuery = query?.trim().toLowerCase() || "";
  const filtered = useMemo(() => {
    if (!cleanQuery) return history;
    return history.filter((item) => item.toLowerCase().includes(cleanQuery));
  }, [history, cleanQuery]);

  if (!isOpen || filtered.length === 0) {
    return null;
  }

  const handleClearAll = (e) => {
    e.preventDefault();
    e.stopPropagation();
    clearSearchHistory();
    setHistory([]);
  };

  const handleRemoveItem = (e, item) => {
    e.preventDefault();
    e.stopPropagation();
    const updated = removeSearchHistoryItem(item);
    setHistory(updated);
  };

  return (
    <div
      className={`recent-searches-dropdown ${className}`}
      onMouseDown={(e) => e.preventDefault()}
      role="region"
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

      <ul className="recent-searches-dropdown__list" role="listbox">
        {filtered.map((item, idx) => {
          const isActive = idx === activeIndex;
          return (
            <li
              key={item}
              className={`recent-searches-dropdown__item ${isActive ? "active" : ""}`}
              role="option"
              aria-selected={isActive}
              onClick={() => onSelect?.(item)}
            >
              <div className="recent-searches-dropdown__item-content">
                <IoTimeOutline className="recent-searches-dropdown__item-icon" />
                <span className="recent-searches-dropdown__item-text" title={item}>
                  {item}
                </span>
              </div>
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
    </div>
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
