import React from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import Navbar from "./components/navbar/nav_bar";
import Home from "./pages/Home";
import Graffiti from "./pages/Graffiti";
import Network from "./pages/Network";
import "./App.css";

const App = () => {
  return (
    <div className="app">
      <Navbar />
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/graffiti" element={<Graffiti />} />
        <Route path="/network" element={<Network />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  );
};

export default App;
