import { useCallback, useState, useEffect } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "motion/react";

import Navbar from "./components/navbar/nav_bar";
import Footer from "./components/footer/footer";
import Home from "./pages/Home";
import Block from "./pages/Block";
import Graffiti from "./pages/Graffiti";
import Network from "./pages/Network";
import Documentation from "./pages/Documentation";

import SearchOverlay from "./components/search/SearchOverlay";
import { saveSearchHistory } from "./utils/searchHistory";
import { ToastProvider } from "./components/common/ToastContainer";
import { searchExplorer } from "./api/explorer";
import { guessKind } from "./utils/searchKind";

import "./App.css";
import "./styles/home.css";
import "./styles/networkpages.css";
import "./styles/card.css";
import "./styles/search.css";
import "./styles/footer.css";
import "./styles/nav_bar.css";
import "./styles/label.css";
import "./styles/tx_flowchart.css";
import "./styles/address_analytics.css";
import "./styles/txid.css";
import "./styles/address.css";
import "./styles/live_indicator.css";
import "./styles/toast.css";
import "./styles/documentation.css";

const pageVariants = {
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: -12 }
};

const pageTransition = {
  duration: 0.25,
  ease: [0.25, 0.1, 0.25, 1]
};

const App = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [query, setQuery] = useState(() => new URLSearchParams(globalThis.location?.search || "").get('search') || "");
  const [kind, setKind] = useState("unknown");
  const [result, setResult] = useState(null);
  const [status, setStatus] = useState("idle");
  const [message, setMessage] = useState("");
  const [searchOpen, setSearchOpen] = useState(() => Boolean(new URLSearchParams(globalThis.location?.search || "").get('search')?.trim()));

  const runSearch = useCallback(async (q) => {
    if (!q || !q.trim()) return;
    saveSearchHistory(q);
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

  useEffect(() => {
    const searchParams = new URLSearchParams(location.search);
    const searchQuery = searchParams.get('search');
    
    if (searchQuery?.trim()) {
      let isMounted = true;
      saveSearchHistory(searchQuery);
      searchExplorer(searchQuery)
        .then((resp) => {
          if (isMounted) {
            setResult(resp.data);
            setKind(resp.kind || guessKind(searchQuery));
            setStatus("done");
          }
        })
        .catch((err) => {
          if (isMounted) {
            setResult(null);
            setStatus("error");
            setMessage(err.message || "Gagal memuat data.");
          }
        });
      return () => {
        isMounted = false;
      };
    }
  }, [location.search]);

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

  const renderHomePage = (
    <motion.div
      variants={pageVariants}
      initial="initial"
      animate="animate"
      exit="exit"
      transition={pageTransition}
    >
      <Home onSearchClick={handleSearchClick} />
    </motion.div>
  );

  const renderBlockPage = (
    <motion.div
      variants={pageVariants}
      initial="initial"
      animate="animate"
      exit="exit"
      transition={pageTransition}
    >
      <Block onSearchClick={handleSearchClick} />
    </motion.div>
  );

  return (
    <ToastProvider>
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
          <AnimatePresence mode="wait">
            <Routes location={location} key={location.pathname}>
              <Route path="/" element={renderHomePage} />
              <Route path="/block" element={renderBlockPage} />
              <Route
                path="/graffiti"
                element={
                  <motion.div
                    variants={pageVariants}
                    initial="initial"
                    animate="animate"
                    exit="exit"
                    transition={pageTransition}
                  >
                    <Graffiti onSearchClick={handleSearchClick} />
                  </motion.div>
                }
              />
              <Route
                path="/network"
                element={
                  <motion.div
                    variants={pageVariants}
                    initial="initial"
                    animate="animate"
                    exit="exit"
                    transition={pageTransition}
                  >
                    <Network onSearchClick={handleSearchClick} />
                  </motion.div>
                }
              />
              <Route
                path="/documentation"
                element={
                  <motion.div
                    variants={pageVariants}
                    initial="initial"
                    animate="animate"
                    exit="exit"
                    transition={pageTransition}
                  >
                    <Documentation onSearchClick={handleSearchClick} />
                  </motion.div>
                }
              />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </AnimatePresence>
        </div>
        <Footer />
      </div>
    </ToastProvider>
  );
};

export default App;