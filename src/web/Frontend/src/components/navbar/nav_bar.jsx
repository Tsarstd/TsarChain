import { useState, useEffect, useRef } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { IoSearch, IoMenu, IoClose, IoCloseCircle } from "react-icons/io5";
import { TbDeviceTvOld, TbDeviceTvOff } from "react-icons/tb";
import PropTypes from "prop-types";
import { assets } from "../../assets/assets";
import { useCrt } from "../../context/useCrt";
import RecentSearchesDropdown from "../search/RecentSearchesDropdown";
import { getSearchHistory } from "../../utils/searchHistory";

const NAV_LINKS = [
  { label: "Home", path: "/" },
  { label: "Block", path: "/block" },
  { label: "Graffiti", path: "/graffiti" },
  { label: "Network", path: "/network" },
  { label: "Docs", path: "/documentation" },
];

const getFilteredRecent = (q) => {
  const all = getSearchHistory();
  const clean = q?.trim().toLowerCase() || "";
  return clean ? all.filter((item) => item.toLowerCase().includes(clean)) : all;
};

const handleHistoryKeyNav = (e, items, isOpen, setIsOpen, setActiveIndex) => {
  if (e.key !== "ArrowDown" && e.key !== "ArrowUp") {
    if (e.key === "Escape" && isOpen) {
      e.stopPropagation();
      setIsOpen(false);
      setActiveIndex(-1);
    }
    return;
  }

  if (items.length === 0) return;

  if (!isOpen) {
    setIsOpen(true);
    setActiveIndex(0);
    return;
  }

  e.preventDefault();
  if (e.key === "ArrowDown") {
    setActiveIndex((prev) => (prev + 1) % items.length);
  } else {
    setActiveIndex((prev) => (prev <= 0 ? items.length - 1 : prev - 1));
  }
};

const Navbar = ({ query, onQueryChange, onSearch, onSearchClick }) => {
  const { isCrtEnabled, toggleCrt } = useCrt();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isMobileSearchOpen, setIsMobileSearchOpen] = useState(false);
  const [isDesktopHistoryOpen, setIsDesktopHistoryOpen] = useState(false);
  const [isMobileHistoryOpen, setIsMobileHistoryOpen] = useState(false);
  const [desktopActiveIndex, setDesktopActiveIndex] = useState(-1);
  const [mobileActiveIndex, setMobileActiveIndex] = useState(-1);

  const desktopSearchRef = useRef(null);
  const mobileSearchRef = useRef(null);
  const desktopInputRef = useRef(null);
  const mobileInputRef = useRef(null);
  const location = useLocation();

  const [prevPath, setPrevPath] = useState(location.pathname);
  if (prevPath !== location.pathname) {
    setPrevPath(location.pathname);
    setIsMobileMenuOpen(false);
    setIsMobileSearchOpen(false);
    setIsDesktopHistoryOpen(false);
    setIsMobileHistoryOpen(false);
    setDesktopActiveIndex(-1);
    setMobileActiveIndex(-1);
  }

  const closeAllMobile = () => {
    setIsMobileMenuOpen(false);
    setIsMobileSearchOpen(false);
    setIsMobileHistoryOpen(false);
  };

  const closeAllDrawers = () => {
    closeAllMobile();
    setIsDesktopHistoryOpen(false);
    setDesktopActiveIndex(-1);
    setMobileActiveIndex(-1);
  };

  const isAnyMobileDrawerOpen = isMobileMenuOpen || isMobileSearchOpen;

  // Lock body scroll when mobile drawers are open
  useEffect(() => {
    document.body.style.overflow = isAnyMobileDrawerOpen ? "hidden" : "";
    return () => {
      document.body.style.overflow = "";
    };
  }, [isAnyMobileDrawerOpen]);

  // Click outside to close dropdowns
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (desktopSearchRef.current && !desktopSearchRef.current.contains(e.target)) {
        setIsDesktopHistoryOpen(false);
        setDesktopActiveIndex(-1);
      }
      if (mobileSearchRef.current && !mobileSearchRef.current.contains(e.target)) {
        setIsMobileHistoryOpen(false);
        setMobileActiveIndex(-1);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Focus mobile input when mobile search bar opens
  useEffect(() => {
    if (!isMobileSearchOpen) return;
    const timer = setTimeout(() => {
      mobileInputRef.current?.focus();
      mobileInputRef.current?.select();
    }, 80);
    return () => clearTimeout(timer);
  }, [isMobileSearchOpen]);

  const openSearch = (selectText = false) => {
    if ((globalThis.window?.innerWidth ?? 1200) <= 768) {
      setIsMobileMenuOpen(false);
      setIsMobileSearchOpen(true);
      return;
    }
    desktopInputRef.current?.focus();
    if (selectText) {
      desktopInputRef.current?.select();
    }
    setIsDesktopHistoryOpen(true);
  };

  // Keyboard shortcut (Ctrl+K or Cmd+K or '/') listener
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        setIsMobileMenuOpen(false);
        setIsMobileSearchOpen(false);
        setIsMobileHistoryOpen(false);
        setIsDesktopHistoryOpen(false);
        setDesktopActiveIndex(-1);
        setMobileActiveIndex(-1);
        return;
      }

      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        openSearch(true);
        return;
      }

      const isInput = ["INPUT", "TEXTAREA"].includes(document.activeElement?.tagName);
      if (e.key === "/" && !isInput) {
        e.preventDefault();
        openSearch(false);
      }
    };

    globalThis.addEventListener("keydown", handleKeyDown);
    return () => globalThis.removeEventListener("keydown", handleKeyDown);
  }, []);

  const handleSelectRecent = (item) => {
    onQueryChange?.(item);
    closeAllDrawers();
    if (onSearchClick) {
      onSearchClick(item);
    } else {
      onSearch?.();
    }
  };

  const handleFormSubmit = (event, isHistoryOpen, activeIndex, onComplete) => {
    event.preventDefault();
    const items = getFilteredRecent(query);
    if (isHistoryOpen && activeIndex >= 0 && activeIndex < items.length) {
      handleSelectRecent(items[activeIndex]);
      return;
    }
    onComplete();
    onSearch?.();
  };

  const handleDesktopSubmit = (e) =>
    handleFormSubmit(e, isDesktopHistoryOpen, desktopActiveIndex, () => {
      setIsDesktopHistoryOpen(false);
      setDesktopActiveIndex(-1);
    });

  const handleMobileSubmit = (e) =>
    handleFormSubmit(e, isMobileHistoryOpen, mobileActiveIndex, () => {
      setIsMobileHistoryOpen(false);
      setIsMobileSearchOpen(false);
      setMobileActiveIndex(-1);
    });

  const handleDesktopInputKeyDown = (e) => {
    const items = getFilteredRecent(query);
    handleHistoryKeyNav(e, items, isDesktopHistoryOpen, setIsDesktopHistoryOpen, setDesktopActiveIndex);
  };

  const handleMobileInputKeyDown = (e) => {
    const items = getFilteredRecent(query);
    handleHistoryKeyNav(e, items, isMobileHistoryOpen, setIsMobileHistoryOpen, setMobileActiveIndex);
  };

  const toggleMobileMenu = () => {
    setIsMobileMenuOpen((prev) => !prev);
    if (!isMobileMenuOpen) {
      setIsMobileSearchOpen(false);
      setIsMobileHistoryOpen(false);
    }
  };

  const toggleMobileSearch = () => {
    setIsMobileSearchOpen((prev) => !prev);
    if (isMobileSearchOpen) {
      setIsMobileHistoryOpen(false);
    } else {
      setIsMobileMenuOpen(false);
    }
  };

  const isLinkActive = (linkPath) =>
    linkPath === "/" ? location.pathname === "/" : location.pathname.startsWith(linkPath);

  return (
    <header className="navbar">
      <div className="navbar__inner">
        <div className="navbar__left">
          <NavLink 
            to="/" 
            end 
            className={() => 
              `navbar__logo-link ${isLinkActive("/") ? "active" : ""}`
            }
            onClick={closeAllMobile}
          >
            <img 
              src={assets.logo_header} 
              alt="TsarChain" 
              className="navbar__logo" 
            />
          </NavLink>
          
          {/* Desktop Navigation Menu */}
          <nav className={`navbar__menu ${isMobileMenuOpen ? "open" : ""}`}>
            <ul className="navbar__menu-list">
              {NAV_LINKS.map((link) => (
                <li key={link.path} className="navbar__menu-item">
                  <NavLink 
                    to={link.path}
                    className={() => 
                      `navbar__menu-link ${isLinkActive(link.path) ? "active" : ""}`
                    }
                    onClick={closeAllMobile}
                  >
                    {link.label}
                  </NavLink>
                </li>
              ))}
            </ul>
          </nav>
        </div>

        {/* Right Section */}
        <div className="navbar__right">
          {/* Desktop Search Form */}
          <form
            ref={desktopSearchRef}
            className="navbar__search navbar__search--desktop"
            onSubmit={handleDesktopSubmit}
          >
            <div className="navbar__search-wrapper">
              <input
                ref={desktopInputRef}
                type="text"
                className="navbar__search-input"
                placeholder="Search Height / BlockHash / TxId / Address / Graffiti"
                value={query}
                onFocus={() => setIsDesktopHistoryOpen(true)}
                onChange={(e) => {
                  onQueryChange?.(e.target.value);
                  setIsDesktopHistoryOpen(true);
                  setDesktopActiveIndex(-1);
                }}
                onKeyDown={handleDesktopInputKeyDown}
              />
              {query ? (
                <button
                  type="button"
                  className="navbar__desktop-search-clear"
                  onClick={() => {
                    onQueryChange?.("");
                    desktopInputRef.current?.focus();
                  }}
                  aria-label="Clear search input"
                  style={{
                    background: "none",
                    border: "none",
                    color: "rgba(255, 248, 240, 0.6)",
                    cursor: "pointer",
                    display: "flex",
                    alignItems: "center",
                    padding: "0 6px",
                    fontSize: "16px",
                    lineHeight: 1
                  }}
                  title="Clear input"
                >
                  <IoCloseCircle />
                </button>
              ) : (
                <kbd className="navbar__shortcut">/</kbd>
              )}
            </div>
            <button 
              className="navbar__search-btn btn-primary" 
              type="submit"
              aria-label="Search"
            >
              <IoSearch />
            </button>

            <RecentSearchesDropdown
              isOpen={isDesktopHistoryOpen}
              query={query}
              onSelect={handleSelectRecent}
              activeIndex={desktopActiveIndex}
            />
          </form>

          {/* Desktop CRT Mode Switcher (USP Feature) */}
          <button
            type="button"
            className={`navbar__crt-toggle ${isCrtEnabled ? "active" : ""}`}
            onClick={toggleCrt}
            title={isCrtEnabled ? "CRT Glitch Mode: ON (Click to disable)" : "CRT Glitch Mode: OFF (Click to enable)"}
            aria-label={isCrtEnabled ? "Disable CRT Mode" : "Enable CRT Mode"}
            aria-pressed={isCrtEnabled}
          >
            <span className="navbar__crt-icon">
              {isCrtEnabled ? <TbDeviceTvOld /> : <TbDeviceTvOff />}
            </span>
            <span className="navbar__crt-text">CRT</span>
            <span className="navbar__crt-indicator" aria-hidden="true" />
          </button>

          {/* Mobile Actions: CRT Switcher + Search Icon Button + Hamburger Menu Button */}
          <div className="navbar__mobile-actions">
            <button 
              className={`navbar__action-btn navbar__action-btn--crt ${isCrtEnabled ? "active" : ""}`}
              onClick={toggleCrt}
              aria-label={isCrtEnabled ? "Disable CRT Mode" : "Enable CRT Mode"}
              aria-pressed={isCrtEnabled}
              title={isCrtEnabled ? "CRT Mode: ON" : "CRT Mode: OFF"}
            >
              {isCrtEnabled ? <TbDeviceTvOld /> : <TbDeviceTvOff />}
              <span className="navbar__crt-mobile-dot" aria-hidden="true" />
            </button>

            <button 
              className={`navbar__action-btn ${isMobileSearchOpen ? "active" : ""}`}
              onClick={toggleMobileSearch}
              aria-label={isMobileSearchOpen ? "Close search bar" : "Open search bar"}
              aria-expanded={isMobileSearchOpen}
              title="Search"
            >
              {isMobileSearchOpen ? <IoClose /> : <IoSearch />}
            </button>

            <button 
              className={`navbar__action-btn ${isMobileMenuOpen ? "active" : ""}`}
              onClick={toggleMobileMenu}
              aria-label={isMobileMenuOpen ? "Close menu" : "Open menu"}
              aria-expanded={isMobileMenuOpen}
              title="Menu"
            >
              {isMobileMenuOpen ? <IoClose /> : <IoMenu />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Expandable Search Bar (Full-width drop-down under navbar) */}
      <div className={`navbar__mobile-search-dropdown ${isMobileSearchOpen ? "open" : ""}`}>
        <form
          ref={mobileSearchRef}
          className="navbar__mobile-search-form"
          onSubmit={handleMobileSubmit}
        >
          <div className="navbar__mobile-search-input-wrapper">
            <IoSearch className="navbar__mobile-search-icon" />
            <input
              ref={mobileInputRef}
              type="text"
              className="navbar__mobile-search-input"
              placeholder="Search Height, Hash, TxID, Address..."
              value={query}
              onFocus={() => setIsMobileHistoryOpen(true)}
              onChange={(e) => {
                onQueryChange?.(e.target.value);
                setIsMobileHistoryOpen(true);
                setMobileActiveIndex(-1);
              }}
              onKeyDown={handleMobileInputKeyDown}
            />
            {query && (
              <button
                type="button"
                className="navbar__mobile-search-clear"
                onClick={() => {
                  onQueryChange?.("");
                  mobileInputRef.current?.focus();
                }}
                aria-label="Clear search input"
              >
                <IoCloseCircle />
              </button>
            )}
          </div>
          <button 
            type="submit" 
            className="navbar__mobile-search-submit"
            aria-label="Search"
          >
            Search
          </button>

          <RecentSearchesDropdown
            isOpen={isMobileHistoryOpen}
            query={query}
            onSelect={handleSelectRecent}
            activeIndex={mobileActiveIndex}
            className="recent-searches-dropdown--mobile"
          />
        </form>
      </div>

      {/* Mobile Backdrop Overlay */}
      {isAnyMobileDrawerOpen && (
        <div 
          className="navbar__mobile-overlay"
          onClick={closeAllMobile}
          aria-hidden="true"
        />
      )}
    </header>
  );
};

Navbar.propTypes = {
  query: PropTypes.string.isRequired,
  onQueryChange: PropTypes.func,
  onSearch: PropTypes.func,
  onSearchClick: PropTypes.func,
};

export default Navbar;
