import { NavLink } from "react-router-dom";
import "./nav_bar.css";
import { assets } from "../../assets/assets";

const Navbar = ({ query, onQueryChange, onSearch }) => {
  const handleSubmit = (event) => {
    event.preventDefault();
    if (onSearch) onSearch();
  };

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
      <div className="nav-right">
        <form className="nav-search" onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder="Height/BlockHash/TxId/Address/Graffiti_Id"
            value={query}
            onChange={(e) => onQueryChange?.(e.target.value)}
          />
          <button className="btn-primary" type="submit">
            Search
          </button>
        </form>
      </div>
    </header>
  );
};

export default Navbar;
