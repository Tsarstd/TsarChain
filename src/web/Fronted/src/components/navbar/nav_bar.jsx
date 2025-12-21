import React from "react";
import { NavLink } from "react-router-dom";
import "./nav_bar.css";
import { assets } from "../../assets/assets";

const Navbar = () => {
  return (
    <header className="navbar">
      <div className="nav-left">
        <img src={assets.logo_header} alt="" className="logo" />
        <ul className="navbar-menu">
          <li>
            <NavLink to="/" end className={({ isActive }) => (isActive ? "active" : "")}>
              Home
            </NavLink>
          </li>
          <li>
            <NavLink to="/graffiti" className={({ isActive }) => (isActive ? "active" : "")}>
              Graffiti
            </NavLink>
          </li>
          <li>
            <NavLink to="/network" className={({ isActive }) => (isActive ? "active" : "")}>
              Network
            </NavLink>
          </li>
        </ul>
      </div>
    </header>
  );
};

export default Navbar;
