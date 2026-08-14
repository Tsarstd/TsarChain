import { useState, useEffect, useRef } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { IoSearch, IoMenu, IoClose } from "react-icons/io5";
import PropTypes from "prop-types";
import { assets } from "../../assets/assets";

const Navbar = ({ query, onQueryChange, onSearch }) => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const inputRef = useRef(null);
  const location = useLocation();

  // Keyboard shortcut (Ctrl+K or Cmd+K or '/') listener
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
      } else if (e.key === "/" && document.activeElement !== inputRef.current) {
        // Pressing '/' when not typing inside an input focuses search
        const isInput = ["INPUT", "TEXTAREA"].includes(document.activeElement?.tagName);
        if (!isInput) {
          e.preventDefault();
          inputRef.current?.focus();
        }
      }
    };
    globalThis.addEventListener("keydown", handleKeyDown);
    return () => globalThis.removeEventListener("keydown", handleKeyDown);
  }, []);

  const handleSubmit = (event) => {
    event.preventDefault();
    if (onSearch) onSearch();
  };

  const navLinks = [
    { label: "Block", path: "/" },
    { label: "Graffiti", path: "/graffiti" },
    { label: "Network", path: "/network" },
  ];

  const toggleMobileMenu = () => {
    setIsMobileMenuOpen(!isMobileMenuOpen);
  };

  const closeMobileMenu = () => {
    setIsMobileMenuOpen(false);
  };

  const isLinkActive = (linkPath) => {
    if (linkPath === "/" || linkPath === "/block") {
      return location.pathname === "/" || location.pathname === "/block";
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
            onClick={closeMobileMenu}
          >
            <img 
              src={assets.logo_header} 
              alt="TsarChain" 
              className="navbar__logo" 
            />
          </NavLink>
          
          <nav className={`navbar__menu ${isMobileMenuOpen ? "open" : ""}`}>
            <ul className="navbar__menu-list">
              {navLinks.map((link) => (
                <li key={link.path} className="navbar__menu-item">
                  <NavLink 
                    to={link.path}
                    className={() => 
                      `navbar__menu-link ${isLinkActive(link.path) ? "active" : ""}`
                    }
                    onClick={closeMobileMenu}
                  >
                    {link.label}
                  </NavLink>
                </li>
              ))}
            </ul>
          </nav>
        </div>

        <div className="navbar__right">
          <form className="navbar__search" onSubmit={handleSubmit}>
            <div className="navbar__search-wrapper">
              <input
                ref={inputRef}
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

          {/* Mobile Menu Toggle Button */}
          <button 
            className="navbar__mobile-toggle"
            onClick={toggleMobileMenu}
            aria-label={isMobileMenuOpen ? "Close menu" : "Open menu"}
            aria-expanded={isMobileMenuOpen}
          >
            {isMobileMenuOpen ? <IoClose /> : <IoMenu />}
          </button>
        </div>

        {/* Mobile Menu Overlay */}
        {isMobileMenuOpen && (
          <div 
            className="navbar__mobile-overlay"
            onClick={closeMobileMenu}
            aria-hidden="true"
          />
        )}
      </div>
    </header>
  );
};

Navbar.propTypes = {
  query: PropTypes.string.isRequired,
  onQueryChange: PropTypes.func,
  onSearch: PropTypes.func,
};

export default Navbar;
