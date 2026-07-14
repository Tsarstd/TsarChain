import { useCallback, useEffect, useState } from "react";
import PropTypes from "prop-types";
import { useNavigate } from "react-router-dom";
import { fetchGraffitiDetail, fetchGraffitiList } from "../api/explorer";
import { fmtBytes } from "../utils/format";
import { useDragScroll } from "./Block";
import { ResultGraffiti } from "../components/search/SearchResults";

const PAGE_SIZE = 20;
const SCROLL_THRESHOLD = 80;

const GraffitiCard = ({ item, onSelect, active, isGenesis }) => {
  const comments = item?.stats?.comments ?? item?.comments?.length ?? 0;
  const mime = item?.mime;
  const creator = item?.creator;

  const isMp4 =
  typeof mime === "string" &&
  mime.toLowerCase().startsWith("video/mp4");

  const isMatroska =
  typeof mime === "string" &&
  mime.toLowerCase().startsWith("video/x-matroska");

  const isJpeg =
  typeof mime === "string" &&
  mime.toLowerCase().startsWith("image/jpeg");

  const isPdf =
  typeof mime === "string" &&
  mime.toLowerCase().startsWith("application/pdf");

  const classes = ["lane-card--graffiti", active ? "lane-card--active" : "", isGenesis ? "lane-card--genesis" : ""]
    .filter(Boolean)
    .join(" ");

  return (
    <button className={classes} type="button" onClick={() => onSelect(item)}>
      <div className="lane-card__grid">
        <div className="stat">
          <div className="value">Graffiti</div>
          <div className="lane-card__graffheader">{item?.block_height ?? "-"}</div>
        </div>

        {isMp4 ? (
          <div className="lane-card__mp4">{"Video MP4"}</div>
        ) : null}

        {isPdf ? (
          <div className="lane-card__pdf">{"Document PDF"}</div>
        ) : null}
        
        {isJpeg ? (
          <div className="lane-card__jpeg">{"Image JPEG"}</div>
        ) : null}

        {isMatroska ? (
          <div className="lane-card__mkv">{"Video MKV"}</div>
        ) : null}
        

        {isGenesis && (
          <div className="lane-card__genesis-label">GENESIS</div>
        )}
      </div>

      {isGenesis ? null : (
        <div className="lane-card__creator">{creator}</div>
      )}

      <div className="lane-card__grid">
        <div className="stat">
          <span className="label">Size</span>
          <span className="value">{fmtBytes(item?.size || item?.size_bytes)}</span>
        </div>
        <div className="stat">
          <span className="label">Comments</span>
          <span className="value">{comments}</span>
        </div>
      </div>
      <div className="divider-card" />
      <div className="lane-card__id wrap">{item?.art_id || "-"}</div>
    </button>
  );
};

const Graffiti = ({onSearchClick}) => {
  const navigate = useNavigate();
  const [items, setItems] = useState([]);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [detail, setDetail] = useState(null);
  const [detailStatus, setDetailStatus] = useState("idle");
  const [selectedId, setSelectedId] = useState(null);
  const [navInput, setNavInput] = useState("");
  const [isNavigating, setIsNavigating] = useState(false);
  const { scrollerRef, isDragging, dragHandlers } = useDragScroll();

  const loadMore = useCallback(async () => {
    if (loading || !hasMore) return;
    setLoading(true);
    setMessage("");
    try {
      const resp = await fetchGraffitiList({ limit: PAGE_SIZE, offset });
      const data = resp.data || {};
      const nextItems = data.items || [];
      setItems((prev) => {
        const seen = new Set(prev.map((item) => item?.art_id).filter(Boolean));
        const merged = [...prev];
        for (const item of nextItems) {
          const key = item?.art_id;
          if (!key || seen.has(key)) continue;
          seen.add(key);
          merged.push(item);
        }
        return merged;
      });
      setOffset(data.nextOffset ?? offset + nextItems.length);
      setHasMore(Boolean(data.hasMore));
    } catch (err) {
      setMessage(err.message || "Failed to load graffiti.");
    } finally {
      setLoading(false);
    }
  }, [hasMore, loading, offset]);

  useEffect(() => {
    if (items.length === 0 && !loading) {
      loadMore();
    }
  }, [items.length, loading, loadMore]);

  const handleSelect = async (item) => {
    if (!item?.art_id) return;
    setDetailStatus("loading");
    setDetail(null);
    setSelectedId(item.art_id);
    try {
      const resp = await fetchGraffitiDetail(item.art_id);
      setDetail(resp.data || null);
      setDetailStatus("done");
    } catch (err) {
      setDetail(null);
      setDetailStatus("error");
      setMessage(err.message || "Failed to load graffiti details.");
    }
  };

    // Fungsi untuk navigasi ke graffiti tertentu
  const handleNavigateToGraffiti = async () => {
    const targetId = navInput.trim();
    if (!targetId) {
      setMessage("Masukkan ID graffiti");
      return;
    }

    setIsNavigating(true);
    setMessage(`Navigating to graffiti...`);

    try {
      // Cari apakah graffiti sudah dimuat
      const existingGraffiti = items.find(item => 
        item.art_id === targetId || 
        item.block_height?.toString() === targetId
      );
      
      if (existingGraffiti) {
        // Jika sudah dimuat, langsung pilih dan scroll
        await handleSelect(existingGraffiti);
        scrollToGraffiti(existingGraffiti.art_id);
      } else {
        // Jika belum dimuat, coba fetch detail
        const resp = await fetchGraffitiDetail(targetId);
        const graffitiData = resp.data || null;
        
        if (graffitiData) {
          // Tambahkan ke state jika belum ada
          setItems(prev => {
            const exists = prev.some(item => item.art_id === targetId);
            if (exists) return prev;
            return [...prev, graffitiData];
          });
          
          // Pilih graffiti
          setDetail(graffitiData);
          setDetailStatus("done");
          setSelectedId(targetId);
          
          // Scroll ke graffiti setelah di-render
          setTimeout(() => scrollToGraffiti(targetId), 100);
        } else {
          setMessage(`Graffiti dengan ID ${targetId} tidak ditemukan`);
        }
      }
    } catch (err) {
      setMessage(err.message || "Gagal navigasi ke graffiti");
    } finally {
      setIsNavigating(false);
    }
  };

  // Fungsi untuk scroll ke graffiti tertentu
  const scrollToGraffiti = (artId) => {
    const graffitiIndex = items.findIndex(item => item.art_id === artId);
    if (graffitiIndex !== -1 && scrollerRef.current) {
      const cardWidth = 240 + 18; // width card + gap
      const scrollPosition = graffitiIndex * cardWidth;
      scrollerRef.current.scrollTo({
        left: scrollPosition,
        behavior: 'smooth'
      });
    }
  };

  const handleSearchClickLocal = useCallback((value) => {
    if (onSearchClick) {
      onSearchClick(value);
    } else {
      // Fallback ke navigate
      navigate(`/?search=${encodeURIComponent(value)}`);
    }
  }, [onSearchClick, navigate]);

  // Fungsi untuk kembali ke graffiti terkini
  const handleGoToLatest = () => {
    if (items.length > 0) {
      const latestGraffiti = items[0]; // Graffiti pertama adalah yang terbaru
      setSelectedId(latestGraffiti.art_id);
      setDetail(null);
      setDetailStatus("idle");
      
      // Scroll ke awal
      if (scrollerRef.current) {
        scrollerRef.current.scrollTo({
          left: 0,
          behavior: 'smooth'
        });
      }
    }
  };

  // Handle Enter key untuk input navigasi
  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      handleNavigateToGraffiti();
    }
  };

  const handleScroll = useCallback(() => {
    const el = scrollerRef.current;
    if (!el || loading || !hasMore) return;
    if (el.scrollLeft + el.clientWidth >= el.scrollWidth - SCROLL_THRESHOLD) {
      loadMore();
    }
  }, [hasMore, loading, loadMore, scrollerRef]);

  const genesisId = !hasMore && items.length
    ? items.at(-1)?.art_id
    : null;

  return (
    <main className="page">
      <section className="section">
        <div className="section-header">
          <div>
            <p className="muted">Swipe right to load older graffiti.</p>
          </div>
          <div className="navigation-controls">
            <button 
              className="nav-button nav-button--back"
              onClick={handleGoToLatest}
              title="Kembali ke graffiti terkini"
              disabled={items.length === 0 || selectedId === items[0]?.art_id}
            >
              ←
            </button>
            
            <div className="nav-input-group">
              <input
                type="text"
                className="nav-input"
                placeholder="Graffiti ID or Block Height"
                value={navInput}
                onChange={(e) => setNavInput(e.target.value)}
                onKeyDown={handleKeyDown}
              />
              <button 
                className="nav-button nav-button--go"
                onClick={handleNavigateToGraffiti}
                disabled={isNavigating || !navInput.trim()}
              >
                {isNavigating ? "..." : "Go"}
              </button>
            </div>
          </div>
        </div>
        <div className="lane">
          <section
            className={`lane-scroll ${isDragging ? "lane-scroll--dragging" : ""}`}
            ref={scrollerRef}
            aria-label="Graffiti list"
            tabIndex={-1}
            onScroll={handleScroll}
            {...dragHandlers}
          >
            {items.map((item) => (
              <GraffitiCard
                key={item.art_id}
                item={item}
                active={item.art_id === selectedId}
                isGenesis={Boolean(genesisId && item.art_id === genesisId)}
                onSelect={handleSelect}
                onSearchClick={handleSearchClickLocal}
              />
            ))}
          </section>
        </div>
        {loading && <div className="result-empty">Load More...</div>}
        {!hasMore && items.length > 0 && <div className="result-empty">*All Graffiti was Achieved</div>}
        {message && <div className="result-empty">{message}</div>}
      </section>

      <section className="section">
        {detailStatus === "error" && (
          <div className="result-empty">
            {setMessage || "Failed to load graffiti details."}
          </div>
        )}
        {detailStatus === "done" && detail ? <ResultGraffiti data={detail} onSearchClick={handleSearchClickLocal} /> : null}
      </section>
    </main>
  );
};

Graffiti.propTypes = {
  onSearchClick: PropTypes.func,
};

GraffitiCard.propTypes = {
  item: PropTypes.shape({
    art_id: PropTypes.string,
    creator: PropTypes.string,
    block_height: PropTypes.number,
    mime: PropTypes.string,
    size: PropTypes.number,
    size_bytes: PropTypes.number,
    
    stats: PropTypes.shape({
      comments: PropTypes.number,
    }),
    
    comments: PropTypes.array,
    comments_length: PropTypes.number,
  }),
  onSelect: PropTypes.func.isRequired,
  active: PropTypes.bool,
  isGenesis: PropTypes.bool,
};

export default Graffiti;
