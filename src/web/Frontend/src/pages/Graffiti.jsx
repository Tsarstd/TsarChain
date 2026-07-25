import PropTypes from "prop-types";
import { useDragScroll } from "./Block";
import { fmtBytes } from "../utils/format";
import { useNavigate } from "react-router-dom";
import { useCallback, useEffect, useState, useMemo, memo } from "react";
import { ResultGraffiti } from "../components/search/SearchResults";
import { fetchGraffitiDetail, fetchGraffitiList } from "../api/explorer";
import { SkeletonCard, SkeletonSearch } from "../components/common/SkeletonLoader";

import { 
  RiFilmLine, 
  RiImageLine, 
  RiFilePdfLine, 
  RiFilter3Line, 
  RiLayoutGridLine
} from "react-icons/ri";

const PAGE_SIZE = 20;
const SCROLL_THRESHOLD = 80;

const GraffitiCard = memo(({ item, onSelect, active, isGenesis }) => {
  const comments = item?.stats?.comments ?? item?.comments?.length ?? 0;
  const mime = item?.mime;
  const creator = item?.creator;

  const isMp4 = typeof mime === "string" && mime.toLowerCase().startsWith("video/mp4");
  const isMatroska = typeof mime === "string" && mime.toLowerCase().startsWith("video/x-matroska");
  const isJpeg = typeof mime === "string" && (mime.toLowerCase().startsWith("image/jpeg") || mime.toLowerCase().startsWith("image/png") || mime.toLowerCase().startsWith("image/webp"));
  const isPdf = typeof mime === "string" && mime.toLowerCase().startsWith("application/pdf");

  const classes = [
    "lane-card--graffiti",
    active ? "lane-card--active" : "",
    isGenesis ? "lane-card--genesis" : "",
  ]
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
          <div className="lane-card__mp4">
            <RiFilmLine className="media-badge-icon" /> MP4
          </div>
        ) : null}

        {isPdf ? (
          <div className="lane-card__pdf">
            <RiFilePdfLine className="media-badge-icon" /> PDF
          </div>
        ) : null}
        
        {isJpeg ? (
          <div className="lane-card__jpeg">
            <RiImageLine className="media-badge-icon" /> Image
          </div>
        ) : null}

        {isMatroska ? (
          <div className="lane-card__mkv">
            <RiFilmLine className="media-badge-icon" /> MKV
          </div>
        ) : null}

        {isGenesis && (
          <div className="lane-card__genesis-label">GENESIS</div>
        )}
      </div>

      {isGenesis ? null : (
        <div className="lane-card__creator mono-text">{creator}</div>
      )}

      <div className="lane-card__grid">
        <div className="stat">
          <span className="label">Size</span>
          <span className="value mono-text">{fmtBytes(item?.size || item?.size_bytes)}</span>
        </div>
        <div className="stat">
          <span className="label">Comments</span>
          <span className="value">{comments}</span>
        </div>
      </div>
      <div className="lane-card__id wrap mono-text">{item?.art_id || "-"}</div>
    </button>
  );
});

const Graffiti = ({ onSearchClick }) => {
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
  
  // Media Filter State ('all' | 'video' | 'image' | 'pdf')
  const [filterTab, setFilterTab] = useState("all");

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

  // Filter items based on active tab
  const filteredItems = useMemo(() => {
    if (filterTab === "all") return items;
    return items.filter((item) => {
      const mime = (item?.mime || "").toLowerCase();
      if (filterTab === "video") return mime.startsWith("video/");
      if (filterTab === "image") return mime.startsWith("image/");
      if (filterTab === "pdf") return mime.startsWith("application/pdf");
      return true;
    });
  }, [items, filterTab]);

  // Media type counts
  const counts = useMemo(() => {
    let video = 0, image = 0, pdf = 0;
    for (const item of items) {
      const mime = (item?.mime || "").toLowerCase();
      if (mime.startsWith("video/")) video++;
      else if (mime.startsWith("image/")) image++;
      else if (mime.startsWith("application/pdf")) pdf++;
    }
    return { all: items.length, video, image, pdf };
  }, [items]);

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

  const handleNavigateToGraffiti = async () => {
    const targetId = navInput.trim();
    if (!targetId) {
      setMessage("Masukkan ID graffiti");
      return;
    }

    setIsNavigating(true);
    setMessage(`Navigating to graffiti...`);

    try {
      const existingGraffiti = items.find(
        (item) => item.art_id === targetId || item.block_height?.toString() === targetId
      );

      if (existingGraffiti) {
        await handleSelect(existingGraffiti);
        scrollToGraffiti(existingGraffiti.art_id);
      } else {
        const resp = await fetchGraffitiDetail(targetId);
        const graffitiData = resp.data || null;

        if (graffitiData) {
          setItems((prev) => {
            const exists = prev.some((item) => item.art_id === targetId);
            if (exists) return prev;
            return [...prev, graffitiData];
          });

          setDetail(graffitiData);
          setDetailStatus("done");
          setSelectedId(targetId);

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

  const scrollToGraffiti = (artId) => {
    const graffitiIndex = filteredItems.findIndex((item) => item.art_id === artId);
    if (graffitiIndex !== -1 && scrollerRef.current) {
      const cardWidth = 240 + 18;
      const scrollPosition = graffitiIndex * cardWidth;
      scrollerRef.current.scrollTo({
        left: scrollPosition,
        behavior: "smooth",
      });
    }
  };

  const handleSearchClickLocal = useCallback(
    (value) => {
      if (onSearchClick) {
        onSearchClick(value);
      } else {
        navigate(`/?search=${encodeURIComponent(value)}`);
      }
    },
    [onSearchClick, navigate]
  );

  const handleGoToLatest = () => {
    if (filteredItems.length > 0) {
      const latestGraffiti = filteredItems[0];
      setSelectedId(latestGraffiti.art_id);
      setDetail(null);
      setDetailStatus("idle");

      if (scrollerRef.current) {
        scrollerRef.current.scrollTo({
          left: 0,
          behavior: "smooth",
        });
      }
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter") {
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

  const genesisId = !hasMore && items.length ? items.at(-1)?.art_id : null;

  return (
    <main className="page">
      <section className="section">
        {/* Category Filter Tab Bar */}
        <div className="graffiti-filter-bar glass-panel">
          <div className="graffiti-filter-title">
            <RiFilter3Line className="filter-icon" /> Filter Media:
          </div>
          <div className="graffiti-tabs">
            <button
              className={`graffiti-tab-btn ${filterTab === "all" ? "active" : ""}`}
              onClick={() => setFilterTab("all")}
              type="button"
            >
              <RiLayoutGridLine /> All ({counts.all})
            </button>
            <button
              className={`graffiti-tab-btn ${filterTab === "image" ? "active" : ""}`}
              onClick={() => setFilterTab("image")}
              type="button"
            >
              <RiImageLine /> Images ({counts.image})
            </button>
            <button
              className={`graffiti-tab-btn ${filterTab === "video" ? "active" : ""}`}
              onClick={() => setFilterTab("video")}
              type="button"
            >
              <RiFilmLine /> Videos ({counts.video})
            </button>
            <button
              className={`graffiti-tab-btn ${filterTab === "pdf" ? "active" : ""}`}
              onClick={() => setFilterTab("pdf")}
              type="button"
            >
              <RiFilePdfLine /> Documents ({counts.pdf})
            </button>
          </div>
        </div>

        <div className="section-header">
          <div>
            <p className="muted">
              Swipe right to load older posts.
            </p>
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
                placeholder="Graffiti ID"
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
          {items.length === 0 && loading ? (
            <SkeletonCard count={6} />
          ) : (
            <section
              className={`lane-scroll ${isDragging ? "lane-scroll--dragging" : ""}`}
              ref={scrollerRef}
              aria-label="Graffiti post list"
              tabIndex={-1}
              onScroll={handleScroll}
              {...dragHandlers}
            >
              {filteredItems.map((item) => (
                <GraffitiCard
                  key={item.art_id}
                  item={item}
                  active={item.art_id === selectedId}
                  isGenesis={Boolean(genesisId && item.art_id === genesisId)}
                  onSelect={handleSelect}
                />
              ))}
            </section>
          )}
        </div>

        {loading && items.length > 0 && <div className="result-empty">Loading More Inscriptions...</div>}
        {!hasMore && items.length > 0 && (
          <div className="result-empty">*All Graffiti Inscriptions Loaded</div>
        )}
        {message && <div className="result-empty">{message}</div>}
      </section>

      {/* Graffiti Detail Result & Cinema Mode Trigger */}
      <section className="section">
        {detailStatus === "loading" && (
          <SkeletonSearch />
        )}
        {detailStatus === "error" && (
          <div className="result-empty">{message || "Failed to load graffiti details."}</div>
        )}
        {detailStatus === "done" && detail ? (
          <div className="graffiti-detail-wrapper glass-panel">
            <ResultGraffiti data={detail} onSearchClick={handleSearchClickLocal} />
          </div>
        ) : null}
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
