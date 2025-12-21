import React from "react";
import "./nav_bar.css";
import { assets } from "../../assets/assets";

const Navbar = ({ query, onQueryChange, onSearch }) => {
  const handleSubmit = (e) => {
    e.preventDefault();
    onSearch?.();
  };

  return (
    <header className="navbar">
      <div className="nav-left">
        <img src={assets.logo_header} alt="TsarChain" className="logo" />
        <ul className="navbar-menu">
          <li>Home</li>
          <li>Graffiti</li>
          <li>Network</li>
        </ul>
      </div>

      <form className="navbar-search" onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Cari block / txid / address / graffiti id"
          value={query}
          onChange={(e) => onQueryChange?.(e.target.value)}
        />
        <button type="submit">Search</button>
      </form>
    </header>
  );
};

export default Navbar;
