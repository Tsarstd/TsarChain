import { NavLink } from "react-router-dom";
import { IoSearch } from "react-icons/io5";

import { assets } from "../../assets/assets";

const Navbar = ({ query, onQueryChange, onSearch }) => {
  const handleSubmit = (event) => {
    event.preventDefault();
    if (onSearch) onSearch();
  };

  return (
    <header className="navbar">
      <div className="nav-left">
        <NavLink to="/" end className={({ isActive }) => (isActive ? "active" : "")}>
          <img src={assets.logo_header} alt="" className="logo" />
        </NavLink>
        <ul className="navbar-menu">
          <li>
            <NavLink to="/block" end className={({ isActive }) => (isActive ? "active" : "")}>
              Block
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
            placeholder="Search by Height / BlockHash / TxId / Address / Graffiti_Id"
            value={query}
            onChange={(e) => onQueryChange?.(e.target.value)}
          />
          <button className="btn-primary" type="submit">
            <IoSearch />
          </button>
        </form>
      </div>
    </header>
  );
};

export default Navbar;
