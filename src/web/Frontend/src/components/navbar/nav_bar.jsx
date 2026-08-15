import { useState, useEffect, useRef } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { IoSearch, IoMenu, IoClose, IoCloseCircle } from "react-icons/io5";
import { TbDeviceTvOld, TbDeviceTvOff } from "react-icons/tb";
import PropTypes from "prop-types";
import { assets } from "../../assets/assets";
import { useCrt } from "../../context/useCrt";

const Navbar = ({ query, onQueryChange, onSearch }) => {
  const { isCrtEnabled, toggleCrt } = useCrt();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isMobileSearchOpen, setIsMobileSearchOpen] = useState(false);
  const desktopInputRef = useRef(null);
  const mobileInputRef = useRef(null);
  const location = useLocation();

  const [prevPath, setPrevPath] = useState(location.pathname);
  if (prevPath !== location.pathname) {
    setPrevPath(location.pathname);
    setIsMobileMenuOpen(false);
    setIsMobileSearchOpen(false);
  }

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
          }
        }
      }
    };
    globalThis.addEventListener("keydown", handleKeyDown);
    return () => globalThis.removeEventListener("keydown", handleKeyDown);
  }, [isMobileSearchOpen, isMobileMenuOpen]);

  const handleSubmit = (event) => {
    event.preventDefault();
    if (onSearch) onSearch();
    setIsMobileSearchOpen(false);
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
    }
  };

  const toggleMobileSearch = () => {
    setIsMobileSearchOpen((prev) => !prev);
    if (!isMobileSearchOpen) {
      setIsMobileMenuOpen(false);
    }
  };

  const closeAllMobile = () => {
    setIsMobileMenuOpen(false);
    setIsMobileSearchOpen(false);
  };

  const isLinkActive = (linkPath) => {
    if (linkPath === "/") {
      return location.pathname === "/";
    }
    return location.pathname.startsWith(linkPath);
  };

  const isAnyMobileDrawerOpen = isMobileMenuOpen || isMobileSearchOpen;

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
          <form className="navbar__search navbar__search--desktop" onSubmit={handleSubmit}>
            <div className="navbar__search-wrapper">
              <input
                ref={desktopInputRef}
                type="text"
                className="navbar__search-input"
                placeholder="Search Height / BlockHash / TxId / Address / Graffiti"
                value={query}
                onChange={(e) => onQueryChange?.(e.target.value)}
              />
              <kbd className="navbar__shortcut">/</kbd>
            </div>
            <button 
              className="navbar__search-btn btn-primary" 
              type="submit"
              aria-label="Search"
            >
              <IoSearch />
            </button>
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
        <form className="navbar__mobile-search-form" onSubmit={handleSubmit}>
          <div className="navbar__mobile-search-input-wrapper">
            <IoSearch className="navbar__mobile-search-icon" />
            <input
              ref={mobileInputRef}
              type="text"
              className="navbar__mobile-search-input"
              placeholder="Search Height, Hash, TxID, Address..."
              value={query}
              onChange={(e) => onQueryChange?.(e.target.value)}
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
};

export default Navbar;
