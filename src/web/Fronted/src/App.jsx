import { useCallback, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import Navbar from "./components/navbar/nav_bar";
import Footer from "./components/footer/footer";
import Home from "./pages/Home";
import Graffiti from "./pages/Graffiti";
import Network from "./pages/Network";
import SearchOverlay from "./components/search/SearchOverlay";
import { searchExplorer } from "./api/explorer";
import { guessKind } from "./utils/searchKind";
import "./App.css";

const App = () => {
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState("unknown");
  const [result, setResult] = useState(null);
  const [status, setStatus] = useState("idle");
  const [message, setMessage] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);

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

  const handleSearch = useCallback(() => {
    const q = query.trim();
    if (!q) {
      setStatus("error");
      setMessage("Isi kata kunci pencarian.");
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
        query={query}
        status={status}
        kind={kind}
        result={result}
        message={message}
        onClose={() => setSearchOpen(false)}
      />
      <div className="app-main">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/graffiti" element={<Graffiti />} />
          <Route path="/network" element={<Network />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
      <Footer />
    </div>
  );
};

export default App;
