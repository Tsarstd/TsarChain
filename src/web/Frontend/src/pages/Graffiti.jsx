import PropTypes from "prop-types";
import { useDragScroll } from "../utils/useDragScroll";
import { fmtBytes } from "../utils/format";
import { useNavigate, useLocation } from "react-router-dom";
import { useCallback, useEffect, useState, useMemo, useRef, memo } from "react";
import { ResultGraffiti } from "../components/search/SearchResults";
import { fetchGraffitiDetail, fetchGraffitiList, fetchByKind } from "../api/explorer";
import { SkeletonCard, SkeletonSearch } from "../components/common/SkeletonLoader";

import { 
  RiFilmLine, 
  RiImageLine, 
  RiFilePdfLine, 
  RiFilter3Line, 
  RiLayoutGridLine
} from "react-icons/ri";

const PAGE_SIZE = 50;
const OVERSCAN = 4;
const SCROLL_THRESHOLD = 600;

const GraffitiCard = memo(({ item, onSelect, active, isGenesis }) => {
  const comments = item?.stats?.comments ?? item?.comments?.length ?? 0;
  const mime = item?.mime;
  const creator = item?.creator;

  const isMp4 = typeof mime === "string" && mime.toLowerCase().startsWith("video/mp4");
  const isMatroska = typeof mime === "string" && mime.toLowerCase().startsWith("video/x-matroska");
  const isJpeg = typeof mime === "string" && (mime.toLowerCase().startsWith("image/jpeg") || mime.toLowerCase().startsWith("image/png") || mime.toLowerCase().startsWith("image/webp"));
  const isPdf = typeof mime === "string" && mime.toLowerCase().startsWith("application/pdf");

  const classes = [
    "lane-card",
    "lane-card--graffiti",
    active ? "lane-card--active" : "",
    isGenesis ? "lane-card--genesis" : "",
  ]
    .filter(Boolean)
    .join(" ");

  const renderCreatorAddress = (addr) => {
    if (!addr || typeof addr !== "string") return addr || "-";
    if (addr.length > 22) {
      const line1 = addr.slice(0, 22);
      const line2 = addr.slice(22);
      return (
        <>
          <span className="creator-addr-line">{line1}</span>
          <span className="creator-addr-line">{line2}</span>
        </>
      );
    }
    return <span className="creator-addr-line">{addr}</span>;
  };

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
        <div className="lane-card__creator mono-text" title={creator}>
          {renderCreatorAddress(creator)}
        </div>
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

GraffitiCard.displayName = "GraffitiCard";

const Graffiti = ({ onSearchClick }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const jumpParam = useMemo(() => new URLSearchParams(location.search).get("jump"), [location.search]);

  const [items, setItems] = useState([]);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(false);
  const [initialLoading, setInitialLoading] = useState(true);
  const [message, setMessage] = useState("");
  const [detail, setDetail] = useState(null);
  const [detailStatus, setDetailStatus] = useState("idle");
  const [detailMessage, setDetailMessage] = useState("");
  const [selectedId, setSelectedId] = useState(null);
  
  // Media Filter State ('all' | 'video' | 'image' | 'pdf')
  const [filterTab, setFilterTab] = useState("all");

  // Virtualizer Scroll Tracking
  const [scrollLeft, setScrollLeft] = useState(0);
  const [containerWidth, setContainerWidth] = useState(() =>
    globalThis.window === undefined ? 1200 : globalThis.window.innerWidth
  );
  const [isMobile, setIsMobile] = useState(() =>
    globalThis.window === undefined ? false : globalThis.window.innerWidth <= 768
  );

  const { scrollerRef, isDragging, dragHandlers } = useDragScroll();
  const scrollRafRef = useRef(null);

  // Responsive slot metrics matching card.css
  const cardWidth = isMobile ? 220 : 270;
  const cardGap = isMobile ? 12 : 18;
  const slotWidth = cardWidth + cardGap;

  // Window resize observer
  useEffect(() => {
    const handleResize = () => {
      const w = globalThis.window?.innerWidth ?? 1200;
      setIsMobile(w <= 768);
      if (scrollerRef.current) {
        setContainerWidth(scrollerRef.current.clientWidth || w);
      }
    };
    globalThis.addEventListener("resize", handleResize);
    return () => globalThis.removeEventListener("resize", handleResize);
  }, [scrollerRef]);

  // Fetch Graffiti items from backend
  const fetchGraffiti = useCallback(async (currentOffset) => {
    try {
      const resp = await fetchGraffitiList({ limit: PAGE_SIZE, offset: currentOffset });
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
        merged.sort((a, b) => Number(b.block_height || 0) - Number(a.block_height || 0));
        return merged;
      });
      setOffset(data.nextOffset ?? currentOffset + nextItems.length);
      setHasMore(Boolean(data.hasMore));
    } catch (err) {
      setMessage(err.message || "Failed to load graffiti.");
    } finally {
      setLoading(false);
      setInitialLoading(false);
    }
  }, []);

  const loadMore = useCallback(async () => {
    if (loading || !hasMore) return;
    setLoading(true);
    setMessage("");
    await fetchGraffiti(offset);
  }, [fetchGraffiti, hasMore, loading, offset]);

  // Handle scroll event with requestAnimationFrame throttling for 60 FPS
  const handleScroll = useCallback(() => {
    if (!scrollerRef.current) return;
    const currentScrollLeft = scrollerRef.current.scrollLeft;
    if (scrollRafRef.current) cancelAnimationFrame(scrollRafRef.current);
    scrollRafRef.current = requestAnimationFrame(() => {
      setScrollLeft(currentScrollLeft);
    });

    // Check pagination threshold
    const el = scrollerRef.current;
    if (!loading && hasMore && el.scrollLeft + el.clientWidth >= el.scrollWidth - SCROLL_THRESHOLD) {
      loadMore();
    }
  }, [loading, hasMore, loadMore, scrollerRef]);

  // Initial Load
  useEffect(() => {
    let isMounted = true;
    fetchGraffitiList({ limit: PAGE_SIZE, offset: 0 })
      .then((resp) => {
        if (!isMounted) return;
        const data = resp.data || {};
        const incoming = Array.isArray(data.items) ? data.items : [];
        incoming.sort((a, b) => Number(b.block_height || 0) - Number(a.block_height || 0));
        setItems(incoming);
        setOffset(data.nextOffset ?? incoming.length);
        setHasMore(Boolean(data.hasMore));
      })
      .catch((err) => {
        if (isMounted) setMessage(err.message || "Failed to load graffiti.");
      })
      .finally(() => {
        if (isMounted) setInitialLoading(false);
      });
    return () => {
      isMounted = false;
    };
  }, []);

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

  const totalCount = filteredItems.length;

  // Compute Virtual Window (startIndex and endIndex)
  const { startIndex, endIndex, leftSpacerWidth, rightSpacerWidth } = useMemo(() => {
    if (totalCount === 0) {
      return { startIndex: 0, endIndex: 0, leftSpacerWidth: 0, rightSpacerWidth: 0 };
    }

    const start = Math.max(0, Math.floor(scrollLeft / slotWidth) - OVERSCAN);
    const end = Math.min(
      totalCount - 1,
      Math.ceil((scrollLeft + containerWidth) / slotWidth) + OVERSCAN
    );

    const leftSpacer = start > 0 ? start * slotWidth - cardGap : 0;
    const rightSpacer = totalCount - 1 - end > 0 ? (totalCount - 1 - end) * slotWidth - cardGap : 0;

    return {
      startIndex: start,
      endIndex: end,
      leftSpacerWidth: leftSpacer,
      rightSpacerWidth: rightSpacer,
    };
  }, [scrollLeft, containerWidth, slotWidth, cardGap, totalCount]);

  // Smooth scroll to graffiti by art_id
  const scrollToGraffiti = useCallback((artId) => {
    const graffitiIndex = filteredItems.findIndex((item) => item.art_id === artId);
    if (graffitiIndex !== -1 && scrollerRef.current) {
      const scrollPosition = Math.max(
        0,
        graffitiIndex * slotWidth - (containerWidth / 2 - cardWidth / 2)
      );
      scrollerRef.current.scrollTo({
        left: scrollPosition,
        behavior: "smooth",
      });
    }
  }, [filteredItems, scrollerRef, slotWidth, containerWidth, cardWidth]);

  // Select graffiti item and load its detail
  const handleSelect = useCallback(async (item) => {
    if (!item?.art_id) return;
    setDetailStatus("loading");
    setDetail(null);
    setDetailMessage("");
    setSelectedId(item.art_id);
    try {
      const resp = await fetchGraffitiDetail(item.art_id);
      setDetail(resp.data || null);
      setDetailStatus("done");
    } catch (err) {
      setDetail(null);
      setDetailStatus("error");
      setDetailMessage(err.message || "Failed to load graffiti details.");
    }
  }, []);

  const appendAndFocusGraffiti = useCallback((graffitiData) => {
    setItems((prev) => {
      const exists = prev.some((item) => item.art_id === graffitiData.art_id);
      if (exists) return prev;
      const updated = [...prev, graffitiData];
      updated.sort((a, b) => Number(b.block_height || 0) - Number(a.block_height || 0));
      return updated;
    });
    setFilterTab("all");
    setDetail(graffitiData);
    setDetailStatus("done");
    setSelectedId(graffitiData.art_id);
    setTimeout(() => scrollToGraffiti(graffitiData.art_id), 100);
  }, [scrollToGraffiti]);

  const searchRemoteBlockHeight = useCallback(async (targetHeight) => {
    const blockResp = await fetchByKind("block", targetHeight).catch(() => null);
    const blockData = blockResp?.data || null;

    if (!blockData) {
      setMessage(`Block #${targetHeight} tidak ditemukan`);
      return;
    }

    const graffitiList = blockData.graffiti || [];
    const artId = graffitiList[0]?.art_id || (typeof blockData.block_id === "string" && blockData.block_id.startsWith("graf") ? blockData.block_id : null);

    if (!artId) {
      setMessage(`Block #${targetHeight} tidak memiliki Graffiti Post`);
      return;
    }

    const detailResp = await fetchGraffitiDetail(artId);
    const graffitiData = detailResp.data || null;
    if (graffitiData) {
      appendAndFocusGraffiti(graffitiData);
    } else {
      setMessage(`Graffiti pada Block #${targetHeight} gagal dimuat`);
    }
  }, [appendAndFocusGraffiti]);

  const searchRemoteArtId = useCallback(async (rawId) => {
    const detailResp = await fetchGraffitiDetail(rawId).catch(() => null);
    const graffitiData = detailResp?.data || null;

    if (graffitiData?.art_id) {
      appendAndFocusGraffiti(graffitiData);
    } else {
      setMessage(`Graffiti ID "${rawId}" tidak ditemukan`);
    }
  }, [appendAndFocusGraffiti]);

  // Jump To Navigation (Supports Graffiti ID & Block Height)
  const handleNavigateToGraffiti = useCallback(
    async (targetInput) => {
      if (targetInput === null || targetInput === undefined) return;
      const rawInput = String(targetInput).trim();
      if (!rawInput) return;

      setMessage("");

      try {
        const isHeightQuery = /^\d+$/.test(rawInput);
        const targetHeight = isHeightQuery ? Number.parseInt(rawInput, 10) : null;

        const existingGraffiti = isHeightQuery
          ? items.find((item) => Number(item.block_height) === targetHeight)
          : items.find((item) => item.art_id?.toLowerCase() === rawInput.toLowerCase());

        if (existingGraffiti) {
          setFilterTab("all");
          await handleSelect(existingGraffiti);
          scrollToGraffiti(existingGraffiti.art_id);
          return;
        }

        if (isHeightQuery) {
          await searchRemoteBlockHeight(targetHeight);
        } else {
          await searchRemoteArtId(rawInput);
        }
      } catch (err) {
        console.error("Graffiti navigation error:", err);
        setMessage(`Gagal navigasi ke graffiti: ${err.message}`);
      }
    },
    [items, handleSelect, scrollToGraffiti, searchRemoteBlockHeight, searchRemoteArtId]
  );

  // Listen to URL search param ?jump=...
  useEffect(() => {
    if (jumpParam && items.length > 0) {
      const timer = setTimeout(() => {
        handleNavigateToGraffiti(jumpParam);
      }, 0);
      return () => clearTimeout(timer);
    }
  }, [jumpParam, items.length, handleNavigateToGraffiti]);

  const handleSearchClickLocal = useCallback(
    (value) => {
      if (onSearchClick) {
        onSearchClick(value);
      } else {
        const searchParams = new URLSearchParams(location.search);
        searchParams.set("search", value);
        navigate(`${location.pathname}?${searchParams.toString()}`);
      }
    },
    [onSearchClick, location.pathname, location.search, navigate]
  );

  const genesisId = !hasMore && items.length ? items.at(-1)?.art_id : null;

  // Rendered cards in current virtual window
  const renderedCards = useMemo(() => {
    if (totalCount === 0) return [];
    return filteredItems.slice(startIndex, endIndex + 1);
  }, [filteredItems, startIndex, endIndex, totalCount]);

  return (
    <main className="page">
      <section className="section">
        {/* Top Header Bar: Filter Tabs */}
        <div className="graffiti-filter-bar glass-panel">
          <div className="graffiti-filter-left">
            <div className="graffiti-filter-title">
              <RiFilter3Line className="filter-icon" /> Filter
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
        </div>

        <div className="lane">
          {initialLoading && totalCount === 0 ? (
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
              {/* Virtual Left Spacer */}
              {leftSpacerWidth > 0 && (
                <div
                  style={{
                    width: `${leftSpacerWidth}px`,
                    minWidth: `${leftSpacerWidth}px`,
                    flexShrink: 0,
                    pointerEvents: "none",
                  }}
                  aria-hidden="true"
                />
              )}

              {/* Rendered Visible Block Cards Window */}
              {renderedCards.map((item) => (
                <GraffitiCard
                  key={item.art_id}
                  item={item}
                  active={item.art_id === selectedId}
                  isGenesis={genesisId === item.art_id}
                  onSelect={handleSelect}
                />
              ))}

              {/* Virtual Right Spacer */}
              {rightSpacerWidth > 0 && (
                <div
                  style={{
                    width: `${rightSpacerWidth}px`,
                    minWidth: `${rightSpacerWidth}px`,
                    flexShrink: 0,
                    pointerEvents: "none",
                  }}
                  aria-hidden="true"
                />
              )}
            </section>
          )}
        </div>

        {loading && items.length > 0 && <div className="result-empty">Loading More ...</div>}
        {!hasMore && items.length > 0 && (
          <div className="result-empty">*All Graffiti Loaded</div>
        )}
        {message && <div className="result-empty">{message}</div>}
      </section>

      {/* Graffiti Detail Result & Cinema Mode Trigger */}
      <section className="section">
        {detailStatus === "loading" && <SkeletonSearch />}
        {detailStatus === "error" && (
          <div className="result-empty">{detailMessage || "Failed to load graffiti details."}</div>
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

Graffiti.propTypes = {
  onSearchClick: PropTypes.func,
};

export default Graffiti;


