import { useState, useEffect, useRef } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { IoSearch, IoMenu, IoClose, IoCloseCircle } from "react-icons/io5";
import { TbDeviceTvOld, TbDeviceTvOff } from "react-icons/tb";
import PropTypes from "prop-types";
import { assets } from "../../assets/assets";
import { useCrt } from "../../context/useCrt";
import RecentSearchesDropdown from "../search/RecentSearchesDropdown";
import { getSearchHistory } from "../../utils/searchHistory";

const getFilteredRecent = (q) => {
  const all = getSearchHistory();
  const clean = q?.trim().toLowerCase() || "";
  return clean ? all.filter((item) => item.toLowerCase().includes(clean)) : all;
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

  // Reset drawer states on route navigation
  useEffect(() => {
    Promise.resolve().then(() => {
      setIsMobileMenuOpen(false);
      setIsMobileSearchOpen(false);
      setIsDesktopHistoryOpen(false);
      setIsMobileHistoryOpen(false);
    });
  }, [location.pathname]);

  const isAnyMobileDrawerOpen = isMobileMenuOpen || isMobileSearchOpen;

  // Lock body scroll when mobile drawers are open
  useEffect(() => {
    if (isAnyMobileDrawerOpen) {
      document.body.style.overflow = "hidden";
    } else {
      document.body.style.overflow = "";
    }
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
    if (isMobileSearchOpen) {
      const timer = setTimeout(() => {
        mobileInputRef.current?.focus();
        mobileInputRef.current?.select();
      }, 80);
      return () => clearTimeout(timer);
    }
  }, [isMobileSearchOpen]);

  // Keyboard shortcut (Ctrl+K or Cmd+K or '/') listener
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        if (isDesktopHistoryOpen) setIsDesktopHistoryOpen(false);
        if (isMobileHistoryOpen) setIsMobileHistoryOpen(false);
        if (isMobileSearchOpen) setIsMobileSearchOpen(false);
        if (isMobileMenuOpen) setIsMobileMenuOpen(false);
        return;
      }

      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (window.innerWidth <= 768) {
          setIsMobileMenuOpen(false);
          setIsMobileSearchOpen(true);
        } else {
          desktopInputRef.current?.focus();
          desktopInputRef.current?.select();
          setIsDesktopHistoryOpen(true);
        }
      } else if (e.key === "/" && document.activeElement !== desktopInputRef.current && document.activeElement !== mobileInputRef.current) {
        const isInput = ["INPUT", "TEXTAREA"].includes(document.activeElement?.tagName);
        if (!isInput) {
          e.preventDefault();
          if (window.innerWidth <= 768) {
            setIsMobileMenuOpen(false);
            setIsMobileSearchOpen(true);
          } else {
            desktopInputRef.current?.focus();
            setIsDesktopHistoryOpen(true);
          }
        }
      }
    };
    globalThis.addEventListener("keydown", handleKeyDown);
    return () => globalThis.removeEventListener("keydown", handleKeyDown);
  }, [isMobileSearchOpen, isMobileMenuOpen, isDesktopHistoryOpen, isMobileHistoryOpen]);

  const handleSelectRecent = (item) => {
    onQueryChange?.(item);
    setIsDesktopHistoryOpen(false);
    setIsMobileHistoryOpen(false);
    setIsMobileSearchOpen(false);
    setDesktopActiveIndex(-1);
    setMobileActiveIndex(-1);
    if (onSearchClick) {
      onSearchClick(item);
    } else if (onSearch) {
      onSearch();
    }
  };

  const handleDesktopSubmit = (event) => {
    event.preventDefault();
    const items = getFilteredRecent(query);
    if (isDesktopHistoryOpen && desktopActiveIndex >= 0 && desktopActiveIndex < items.length) {
      handleSelectRecent(items[desktopActiveIndex]);
      return;
    }
    setIsDesktopHistoryOpen(false);
    setDesktopActiveIndex(-1);
    if (onSearch) onSearch();
  };

  const handleMobileSubmit = (event) => {
    event.preventDefault();
    const items = getFilteredRecent(query);
    if (isMobileHistoryOpen && mobileActiveIndex >= 0 && mobileActiveIndex < items.length) {
      handleSelectRecent(items[mobileActiveIndex]);
      return;
    }
    setIsMobileHistoryOpen(false);
    setIsMobileSearchOpen(false);
    setMobileActiveIndex(-1);
    if (onSearch) onSearch();
  };

  const handleDesktopInputKeyDown = (e) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      const items = getFilteredRecent(query);
      if (items.length === 0) return;

      if (!isDesktopHistoryOpen) {
        setIsDesktopHistoryOpen(true);
        setDesktopActiveIndex(0);
        return;
      }

      e.preventDefault();
      if (e.key === "ArrowDown") {
        setDesktopActiveIndex((prev) => (prev + 1) % items.length);
      } else {
        setDesktopActiveIndex((prev) => (prev <= 0 ? items.length - 1 : prev - 1));
      }
    } else if (e.key === "Escape") {
      if (isDesktopHistoryOpen) {
        e.stopPropagation();
        setIsDesktopHistoryOpen(false);
        setDesktopActiveIndex(-1);
      }
    }
  };

  const handleMobileInputKeyDown = (e) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      const items = getFilteredRecent(query);
      if (items.length === 0) return;

      if (!isMobileHistoryOpen) {
        setIsMobileHistoryOpen(true);
        setMobileActiveIndex(0);
        return;
      }

      e.preventDefault();
      if (e.key === "ArrowDown") {
        setMobileActiveIndex((prev) => (prev + 1) % items.length);
      } else {
        setMobileActiveIndex((prev) => (prev <= 0 ? items.length - 1 : prev - 1));
      }
    } else if (e.key === "Escape") {
      if (isMobileHistoryOpen) {
        e.stopPropagation();
        setIsMobileHistoryOpen(false);
        setMobileActiveIndex(-1);
      }
    }
  };

  const navLinks = [
    { label: "Home", path: "/" },
    { label: "Block", path: "/block" },
    { label: "Graffiti", path: "/graffiti" },
    { label: "Network", path: "/network" },
    { label: "Docs", path: "/documentation" },
  ];

  const toggleMobileMenu = () => {
    setIsMobileMenuOpen((prev) => !prev);
    if (!isMobileMenuOpen) {
      setIsMobileSearchOpen(false);
      setIsMobileHistoryOpen(false);
    }
  };

  const toggleMobileSearch = () => {
    setIsMobileSearchOpen((prev) => !prev);
    if (!isMobileSearchOpen) {
      setIsMobileMenuOpen(false);
    } else {
      setIsMobileHistoryOpen(false);
    }
  };

  const closeAllMobile = () => {
    setIsMobileMenuOpen(false);
    setIsMobileSearchOpen(false);
    setIsMobileHistoryOpen(false);
  };

  const isLinkActive = (linkPath) => {
    if (linkPath === "/") {
      return location.pathname === "/";
    }
    return location.pathname.startsWith(linkPath);
  };

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
              {navLinks.map((link) => (
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
