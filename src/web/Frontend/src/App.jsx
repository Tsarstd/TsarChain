import { useState, useEffect, useCallback, lazy, Suspense } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "motion/react";

import Navbar from "./components/navbar/nav_bar";
import Footer from "./components/footer/footer";
import Home from "./pages/Home";
import SearchOverlay from "./components/search/SearchOverlay";
import { SkeletonSearch } from "./components/common/SkeletonLoader";
import { saveSearchHistory } from "./utils/searchHistory";
import { ToastProvider } from "./components/common/ToastContainer";
import { CrtProvider } from "./context/CrtContext";
import { useCrt } from "./context/useCrt";
import { searchExplorer } from "./api/explorer";
import { guessKind } from "./utils/searchKind";

import "./App.css";
import "./styles/crt.css";
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

// Lazy-load secondary routes for faster initial load
const Block = lazy(() => import("./pages/Block"));
const Graffiti = lazy(() => import("./pages/Graffiti"));
const Network = lazy(() => import("./pages/Network"));
const Documentation = lazy(() => import("./pages/Documentation"));

const pageVariants = {
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: -12 }
};

const pageTransition = {
  duration: 0.25,
  ease: [0.25, 0.1, 0.25, 1]
};

const RouteFallback = () => (
  <div className="page" style={{ padding: "40px 20px" }}>
    <SkeletonSearch />
  </div>
);

const AppContent = () => {
  const { isCrtEnabled } = useCrt();
  const location = useLocation();
  const navigate = useNavigate();
  const [query, setQuery] = useState(() => new URLSearchParams(globalThis.location?.search || "").get('search') || "");
  const [kind, setKind] = useState("unknown");
  const [result, setResult] = useState(null);
  const [status, setStatus] = useState("idle");
  const [message, setMessage] = useState("");
  const [searchOpen, setSearchOpen] = useState(() => Boolean(new URLSearchParams(globalThis.location?.search || "").get('search')?.trim()));

  // Single source of truth: listen to URL search params
  useEffect(() => {
    const searchParams = new URLSearchParams(location.search);
    const searchQuery = searchParams.get('search')?.trim();
    
    if (searchQuery) {
      const controller = new AbortController();
      let isMounted = true;
      saveSearchHistory(searchQuery);
      const inferred = guessKind(searchQuery);

      Promise.resolve().then(() => {
        if (!isMounted) return;
        setSearchOpen(true);
        setKind(inferred);
        setStatus("loading");
        setMessage("");
      });

      searchExplorer(searchQuery, controller.signal)
        .then((resp) => {
          if (isMounted) {
            setResult(resp.data);
            setKind(resp.kind || inferred);
            setStatus("done");
          }
        })
        .catch((err) => {
          if (err.name === "AbortError") return;
          if (isMounted) {
            setResult(null);
            setStatus("error");
            setMessage(err.message || "Gagal memuat data.");
          }
        });

      return () => {
        isMounted = false;
        controller.abort();
      };
    } else {
      Promise.resolve().then(() => {
        setSearchOpen(false);
        setResult(null);
        setStatus("idle");
        setMessage("");
      });
    }
  }, [location.search]);

  const handleSearchClick = useCallback((value) => {
    const trimmed = String(value || "").trim();
    if (!trimmed) return;
    setQuery("");
    const searchParams = new URLSearchParams(location.search);
    searchParams.set("search", trimmed);
    const newUrl = `${location.pathname}?${searchParams.toString()}`;
    navigate(newUrl, { replace: true });
  }, [location.pathname, location.search, navigate]);

  const handleSearch = useCallback(() => {
    const q = query.trim();
    if (!q) {
      setStatus("error");
      setMessage("Input some keywords");
      setSearchOpen(true);
      return;
    }
    const searchParams = new URLSearchParams(location.search);
    searchParams.set("search", q);
    const newUrl = `${location.pathname}?${searchParams.toString()}`;
    navigate(newUrl, { replace: true });
  }, [query, location.pathname, location.search, navigate]);

  const handleCloseSearch = useCallback(() => {
    setSearchOpen(false);
    setResult(null);
    setStatus("idle");
    setMessage("");
    setQuery("");

    const searchParams = new URLSearchParams(location.search);
    if (searchParams.has("search")) {
      searchParams.delete("search");
      const remainingQuery = searchParams.toString();
      const newUrl = remainingQuery ? `${location.pathname}?${remainingQuery}` : location.pathname;
      navigate(newUrl, { replace: true });
    }
  }, [location.pathname, location.search, navigate]);

  return (
    <div className={`app ${isCrtEnabled ? "crt-mode-active" : ""}`}>
      {/* 1. Subtle Tsar Studio Film Grain Noise */}
      <div className="grain-overlay" aria-hidden="true" />
      
      {/* 2. Global Retro CRT / TV Tube Raster Overlay */}
      {isCrtEnabled && <div className="crt-overlay" aria-hidden="true" />}

      <Navbar
        query={query}
        onQueryChange={setQuery}
        onSearch={handleSearch}
        onSearchClick={handleSearchClick}
      />
      
      <SearchOverlay
        open={searchOpen}
        status={status}
        kind={kind}
        result={result}
        message={message}
        onSearchClick={handleSearchClick}
        onClose={handleCloseSearch}
      />
      
      <div className="app-main">
        <AnimatePresence mode="wait">
          <Routes location={location} key={location.pathname}>
            <Route
              path="/"
              element={
                <motion.div
                  variants={pageVariants}
                  initial="initial"
                  animate="animate"
                  exit="exit"
                  transition={pageTransition}
                >
                  <Home onSearchClick={handleSearchClick} />
                </motion.div>
              }
            />
            <Route
              path="/block"
              element={
                <Suspense fallback={<RouteFallback />}>
                  <motion.div
                    variants={pageVariants}
                    initial="initial"
                    animate="animate"
                    exit="exit"
                    transition={pageTransition}
                  >
                    <Block onSearchClick={handleSearchClick} />
                  </motion.div>
                </Suspense>
              }
            />
            <Route
              path="/graffiti"
              element={
                <Suspense fallback={<RouteFallback />}>
                  <motion.div
                    variants={pageVariants}
                    initial="initial"
                    animate="animate"
                    exit="exit"
                    transition={pageTransition}
                  >
                    <Graffiti onSearchClick={handleSearchClick} />
                  </motion.div>
                </Suspense>
              }
            />
            <Route
              path="/network"
              element={
                <Suspense fallback={<RouteFallback />}>
                  <motion.div
                    variants={pageVariants}
                    initial="initial"
                    animate="animate"
                    exit="exit"
                    transition={pageTransition}
                  >
                    <Network onSearchClick={handleSearchClick} />
                  </motion.div>
                </Suspense>
              }
            />
            <Route
              path="/documentation"
              element={
                <Suspense fallback={<RouteFallback />}>
                  <motion.div
                    variants={pageVariants}
                    initial="initial"
                    animate="animate"
                    exit="exit"
                    transition={pageTransition}
                  >
                    <Documentation onSearchClick={handleSearchClick} />
                  </motion.div>
                </Suspense>
              }
            />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </AnimatePresence>
      </div>
      <Footer />
    </div>
  );
};

const App = () => {
  return (
    <CrtProvider>
      <ToastProvider>
        <AppContent />
      </ToastProvider>
    </CrtProvider>
  );
};

export default App;