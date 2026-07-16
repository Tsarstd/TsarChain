import { useCallback, useState, useEffect } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";

import Navbar from "./components/navbar/nav_bar";
import Footer from "./components/footer/footer";
import Block from "./pages/Block";
import Graffiti from "./pages/Graffiti";
import Network from "./pages/Network";

import SearchOverlay from "./components/search/SearchOverlay";
import { searchExplorer } from "./api/explorer";
import { guessKind } from "./utils/searchKind";

import "./App.css";
import "./styles/networkpages.css";
import "./styles/card.css";
import "./styles/search.css";
import "./styles/footer.css";
import "./styles/nav_bar.css";
import "./styles/label.css";
import "./styles/txid.css";
import "./styles/address.css";

const App = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState("unknown");
  const [result, setResult] = useState(null);
  const [status, setStatus] = useState("idle");
  const [message, setMessage] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);

  useEffect(() => {
    const searchParams = new URLSearchParams(location.search);
    const searchQuery = searchParams.get('search');
    
    if (searchQuery?.trim()) {
      setQuery(searchQuery);
      setSearchOpen(true);
      runSearch(searchQuery);
    }
  }, [location]);

  const runSearch = useCallback(async (q) => {
    if (!q.trim()) return;
    const inferred = guessKind(q);
    setKind(inferred);
    setStatus("loading");
    setMessage("");
    try {
      const resp = await searchExplorer(q);
      setResult(resp.data);
      setKind(resp.kind || inferred);
      setStatus("done");
    } catch (err) {
      setResult(null);
      setStatus("error");
      setMessage(err.message || "Gagal memuat data.");
    }
  }, []);

  const handleSearchClick = useCallback((value) => {
    setQuery(value);
    setSearchOpen(true);
    runSearch(value);
    const newUrl = `${location.pathname}?search=${encodeURIComponent(value)}`;
    navigate(newUrl, { replace: true });
  }, [runSearch, location.pathname, navigate]);

  const handleSearch = useCallback(() => {
    const q = query.trim();
    if (!q) {
      setStatus("error");
      setMessage("Input some keywords");
      setSearchOpen(true);
      return;
    }
    setSearchOpen(true);
    runSearch(q);
  }, [query, runSearch]);

  return (
    <div className="app">
      <Navbar query={query} onQueryChange={setQuery} onSearch={handleSearch} />
      
      <SearchOverlay
        open={searchOpen}
        status={status}
        kind={kind}
        result={result}
        message={message}
        onSearchClick={handleSearchClick}
        onClose={() => setSearchOpen(false)}
      />
      
      <div className="app-main">
        <Routes>
          <Route path="/" element={<Block onSearchClick={handleSearchClick} />} />
          <Route path="/graffiti" element={<Graffiti onSearchClick={handleSearchClick} />} />
          <Route path="/network" element={<Network onSearchClick={handleSearchClick} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
      <Footer />
    </div>
  );
};

export default App;