import { useState } from "react";
import { NavLink } from "react-router-dom";
import { IoSearch, IoMenu, IoClose } from "react-icons/io5";
import { assets } from "../../assets/assets";

const Navbar = ({ query, onQueryChange, onSearch }) => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const handleSubmit = (event) => {
    event.preventDefault();
    if (onSearch) onSearch();
  };

  const navLinks = [
    { label: "Block", path: "/block" },
    { label: "Graffiti", path: "/graffiti" },
    { label: "Network", path: "/network" },
  ];

  const toggleMobileMenu = () => {
    setIsMobileMenuOpen(!isMobileMenuOpen);
  };

  const closeMobileMenu = () => {
    setIsMobileMenuOpen(false);
  };

  return (
    <header className="navbar">
      <div className="navbar__inner">
        <div className="navbar__left">
          <NavLink 
            to="/" 
            end 
            className={({ isActive }) => 
              `navbar__logo-link ${isActive ? "active" : ""}`
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
                    end={link.path === "/block"}
                    className={({ isActive }) => 
                      `navbar__menu-link ${isActive ? "active" : ""}`
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
            <input
              type="text"
              className="navbar__search-input"
              placeholder="Search by Height / BlockHash / TxId / Address / Graffiti_Id"
              value={query}
              onChange={(e) => onQueryChange?.(e.target.value)}
            />
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

export default Navbar;
