import PropTypes from "prop-types";
import { useNavigate } from "react-router-dom";
import { fmtDateLong, timeAgo } from "../utils/format";
import { fetchBlockRange, fetchByKind } from "../api/explorer";
import { ResultBlock } from "../components/search/SearchResults";
import { SkeletonCard, SkeletonBlockCard, SkeletonSearch } from "../components/common/SkeletonLoader";
import { LiveIndicator } from "../components/common/LiveIndicator";
import { useCallback, useEffect, useState, useRef, useMemo, memo } from "react";
import { useDragScroll } from "../utils/useDragScroll";

const OVERSCAN = 4;
const CACHE_KEY = "block_range_cache_v2";
const CACHE_EXPIRE_MS = 15 * 60 * 1000;

const getCachedTipState = () => {
  try {
    const cached = localStorage.getItem(CACHE_KEY);
    if (cached) {
      const { state, timestamp } = JSON.parse(cached);
      if (Date.now() - timestamp < CACHE_EXPIRE_MS) {
        return state;
      }
    }
  } catch (e) {
    console.warn("Cache read error:", e);
  }
  return null;
};

const setCachedTipState = (state) => {
  try {
    const limitedState = {
      tipHeight: state.tipHeight,
      blocks: Array.isArray(state.blocks) ? state.blocks.slice(0, 30) : [],
    };
    localStorage.setItem(
      CACHE_KEY,
      JSON.stringify({
        state: limitedState,
        timestamp: Date.now(),
      })
    );
  } catch (e) {
    console.warn("Cache write error:", e);
  }
};

const mergeBlocksToMap = (prevMap, incomingList) => {
  const next = new Map(prevMap);
  for (const b of incomingList) {
    if (b?.height !== undefined && b?.height !== null) {
      next.set(Number(b.height), b);
    }
  }
  return next;
};

const BlockCard = memo(({ item, onSelect, active, isGenesis }) => {
  const graffitiComments = Number(item?.graffiti_comments || 0);
  const graffitiPayout = Number(item?.graffiti_payouts || 0);
  const blockId = item?.block_id;

  const isGraffiti =
    typeof blockId === "string" &&
    blockId.toLowerCase().startsWith("graf");

  const classes = [
    "lane-card",
    isGraffiti ? "lane-card--graffiti" : "",
    active ? "lane-card--active" : "",
    isGenesis ? "lane-card--genesis" : "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <button className={classes} type="button" onClick={() => onSelect(item)}>
      <div className="lane-card__grid">
        <div className="stat">
          <div className="lane-card__date">{fmtDateLong(item?.timestamp)}</div>
          <div className="lane-card__blockheight">{item?.height ?? "-"}</div>
        </div>
        <div className="lane-card__time-ago">{timeAgo(item?.timestamp)}</div>

        {isGenesis ? (
          <div className="lane-card__genesis-label">GENESIS</div>
        ) : null}
      </div>

      {isGraffiti ? (
        <div className="lane-card__graf">Graffiti Post</div>
      ) : null}

      {isGenesis || isGraffiti || !blockId ? null : (
        <div className="lane-card__bid">{blockId}</div>
      )}

      <div className="lane-card__grid">
        <div className="stat">
          <span className="label">Transactions</span>
          <span className="value">{item?.tx_count ?? 0}</span>
        </div>
      </div>
      <div className="lane-card__grid">
        <div className="stat">
          <span className="label">Comments</span>
          <span className="value">{graffitiComments ?? 0}</span>
        </div>
        <div className="stat">
          <span className="label">Payouts</span>
          <span className="value">{graffitiPayout ?? 0}</span>
        </div>
      </div>
      <div className="lane-card__id wrap">{item?.hash || "-"}</div>
    </button>
  );
});

BlockCard.displayName = "BlockCard";

const Block = ({ onSearchClick }) => {
  const navigate = useNavigate();
  const cached = useMemo(() => getCachedTipState(), []);

  // Map of block height -> block summary object
  const [blocksMap, setBlocksMap] = useState(() => {
    const map = new Map();
    if (cached?.blocks && Array.isArray(cached.blocks)) {
      cached.blocks.forEach((b) => {
        if (b?.height !== undefined && b?.height !== null) {
          map.set(Number(b.height), b);
        }
      });
    }
    return map;
  });

  const [tipHeight, setTipHeight] = useState(() => cached?.tipHeight ?? null);
  const [loadingInitial, setLoadingInitial] = useState(() => cached?.tipHeight === null || cached?.tipHeight === undefined);
  const [message, setMessage] = useState("");
  const [detail, setDetail] = useState(null);
  const [detailStatus, setDetailStatus] = useState("idle");
  const [detailMessage, setDetailMessage] = useState("");
  const [selectedHeight, setSelectedHeight] = useState(null);
  const [navInput, setNavInput] = useState("");
  const [isNavigating, setIsNavigating] = useState(false);
  const [isLive, setIsLive] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Virtualizer Scroll Tracking
  const [scrollLeft, setScrollLeft] = useState(0);
  const [containerWidth, setContainerWidth] = useState(() =>
    globalThis.window === undefined ? 1200 : globalThis.window.innerWidth
  );
  const [isMobile, setIsMobile] = useState(() =>
    globalThis.window === undefined ? false : globalThis.window.innerWidth <= 768
  );

  const { scrollerRef, isDragging, dragHandlers } = useDragScroll();
  const inFlightRangesRef = useRef(new Set());
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

  // Handle scroll event with requestAnimationFrame throttling for 60 FPS
  const handleScroll = useCallback(() => {
    if (!scrollerRef.current) return;
    const currentScrollLeft = scrollerRef.current.scrollLeft;
    if (scrollRafRef.current) cancelAnimationFrame(scrollRafRef.current);
    scrollRafRef.current = requestAnimationFrame(() => {
      setScrollLeft(currentScrollLeft);
    });
  }, [scrollerRef]);

  // Initial Tip Fetch & Sync
  useEffect(() => {
    let isMounted = true;
    const loadInitialBlocks = async () => {
      try {
        const resp = await fetchBlockRange({ limit: 50, startHeight: null, source: "database" });
        if (!isMounted) return;
        const data = resp.data || {};
        const incoming = Array.isArray(data.items) ? data.items : [];
        const detectedTip =
          data.tipHeight ??
          data.tip_height ??
          (incoming.length > 0 ? incoming[0].height : null);

        if (detectedTip !== null && detectedTip !== undefined) {
          setTipHeight(Number(detectedTip));
          setCachedTipState({ tipHeight: Number(detectedTip), blocks: incoming });
        }

        if (incoming.length > 0) {
          setBlocksMap((prev) => mergeBlocksToMap(prev, incoming));
        }
        setLastUpdated(new Date());
      } catch (err) {
        if (isMounted) setMessage(err.message || "Gagal memuat block.");
      } finally {
        if (isMounted) setLoadingInitial(false);
      }
    };

    loadInitialBlocks();
    return () => {
      isMounted = false;
    };
  }, []);

  // Total items in the entire chain: 0 to tipHeight
  const totalCount = tipHeight === null || tipHeight < 0 ? 0 : tipHeight + 1;

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

  // On-Demand Batch Range Fetcher for Missing Visible Blocks
  useEffect(() => {
    if (tipHeight === null || totalCount === 0) return;

    // Visible height bounds: index 0 is tipHeight, index (totalCount - 1) is 0
    const maxVisibleHeight = tipHeight - startIndex;
    const minVisibleHeight = Math.max(0, tipHeight - endIndex);

    const missingHeights = [];
    for (let h = maxVisibleHeight; h >= minVisibleHeight; h--) {
      if (!blocksMap.has(h) && !inFlightRangesRef.current.has(h)) {
        missingHeights.push(h);
      }
    }

    if (missingHeights.length === 0) return;

    // Group request range with slight buffer
    const fetchMax = Math.min(tipHeight, Math.max(...missingHeights) + 10);
    const fetchMin = Math.max(0, Math.min(...missingHeights) - 10);
    const fetchLimit = Math.min(100, fetchMax - fetchMin + 1);

    for (let h = fetchMin; h <= fetchMax; h++) {
      inFlightRangesRef.current.add(h);
    }

    let isMounted = true;
    const fetchBatchRange = async () => {
      try {
        const resp = await fetchBlockRange({
          startHeight: fetchMax,
          limit: Math.max(fetchLimit, 30),
          source: "database",
        });
        if (!isMounted) return;
        const incoming = Array.isArray(resp.data?.items) ? resp.data.items : [];
        if (incoming.length > 0) {
          setBlocksMap((prev) => mergeBlocksToMap(prev, incoming));
        }
      } catch (err) {
        console.warn("Failed to fetch block batch range:", err);
      } finally {
        for (let h = fetchMin; h <= fetchMax; h++) {
          inFlightRangesRef.current.delete(h);
        }
      }
    };

    fetchBatchRange();
    return () => {
      isMounted = false;
    };
  }, [startIndex, endIndex, tipHeight, totalCount, blocksMap]);

  // Live Sync auto-refresh polling
  useEffect(() => {
    if (!isLive) return;

    const pollLatestBlock = async () => {
      if (tipHeight === null || isRefreshing) return;
      try {
        const resp = await fetchBlockRange({ limit: 1, source: "database" });
        const freshTip = resp.data?.items?.[0]?.height ?? resp.data?.tipHeight;
        setLastUpdated(new Date());
        if (freshTip !== undefined && freshTip !== null && freshTip > tipHeight) {
          const delta = freshTip - tipHeight;
          setTipHeight(freshTip);

          const freshBatch = await fetchBlockRange({
            limit: Math.min(50, delta + 5),
            startHeight: freshTip,
            source: "database",
          });
          const items = freshBatch.data?.items || [];
          if (items.length > 0) {
            setBlocksMap((prev) => mergeBlocksToMap(prev, items));
          }

          if (scrollerRef.current && scrollerRef.current.scrollLeft > 100) {
            scrollerRef.current.scrollLeft += delta * slotWidth;
          }
        }
      } catch (err) {
        console.error(err);
      }
    };

    const interval = setInterval(pollLatestBlock, 20000);
    return () => clearInterval(interval);
  }, [isLive, tipHeight, isRefreshing, slotWidth, scrollerRef]);

  // Manual Refresh Handler
  const handleManualRefresh = useCallback(async () => {
    if (isRefreshing) return;
    setIsRefreshing(true);
    try {
      const resp = await fetchBlockRange({ limit: 50, startHeight: null, source: "database" });
      const incoming = Array.isArray(resp.data?.items) ? resp.data.items : [];
      const detectedTip =
        resp.data?.tipHeight ??
        resp.data?.tip_height ??
        (incoming.length > 0 ? incoming[0].height : null);

      if (detectedTip !== null && detectedTip !== undefined) {
        setTipHeight(Number(detectedTip));
      }

      if (incoming.length > 0) {
        setBlocksMap((prev) => mergeBlocksToMap(prev, incoming));
      }
      setLastUpdated(new Date());
    } catch (err) {
      console.error(err);
    } finally {
      setIsRefreshing(false);
    }
  }, [isRefreshing]);

  // Block Detail Local Cache Management
  const safeSetBlockDetailCache = (height, detailData) => {
    try {
      const cacheKey = `block_detail_${height}`;
      const detailKeys = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k?.startsWith("block_detail_")) {
          detailKeys.push(k);
        }
      }
      if (detailKeys.length > 25) {
        detailKeys.slice(0, -20).forEach((k) => localStorage.removeItem(k));
      }
      localStorage.setItem(
        cacheKey,
        JSON.stringify({
          detail: detailData,
          timestamp: Date.now(),
        })
      );
    } catch (err) {
      console.warn("LocalStorage cache error:", err);
    }
  };

  // Block Selection & Detail Fetching
  const handleSelect = useCallback(async (item) => {
    const height = item?.height;
    if (height === undefined || height === null) return;

    const cacheKey = `block_detail_${height}`;
    try {
      const cachedDetail = localStorage.getItem(cacheKey);
      if (cachedDetail) {
        const { detail: cachedData, timestamp } = JSON.parse(cachedDetail);
        if (Date.now() - timestamp < 60000) {
          setDetail(cachedData);
          setDetailStatus("done");
          setSelectedHeight(height);
          return;
        }
      }
    } catch {
      // Ignore cache parse error
    }

    setDetailStatus("loading");
    setDetailMessage("");
    setSelectedHeight(height);

    try {
      const resp = await fetchByKind("block", height);
      const detailData = resp.data || null;
      setDetail(detailData);
      setDetailStatus("done");

      if (detailData) {
        safeSetBlockDetailCache(height, detailData);
      }
    } catch (err) {
      setDetail(null);
      setDetailStatus("error");
      setDetailMessage(err.message || "Gagal memuat detail block.");
    }
  }, []);

  // Jump to Block Navigation (Zero Gap Guarantee)
  const handleNavigateToBlock = async () => {
    const targetHeight = Number.parseInt(navInput, 10);
    if (Number.isNaN(targetHeight) || targetHeight < 0) {
      setMessage("Masukkan nomor Block Height yang valid");
      return;
    }

    if (tipHeight !== null && targetHeight > tipHeight) {
      setMessage(`Block height melebihi tip saat ini (#${tipHeight})`);
      return;
    }

    setIsNavigating(true);
    setMessage("");

    try {
      // 1. Math-precise pixel target offset
      const currentTip = tipHeight ?? targetHeight;
      const targetIndex = Math.max(0, currentTip - targetHeight);
      const targetScrollLeft = Math.max(
        0,
        targetIndex * slotWidth - (containerWidth / 2 - cardWidth / 2)
      );

      // 2. Smoothly scroll directly to target position
      if (scrollerRef.current) {
        scrollerRef.current.scrollTo({
          left: targetScrollLeft,
          behavior: "smooth",
        });
      }

      // 3. Immediately select block and open details
      setSelectedHeight(targetHeight);
      await handleSelect({ height: targetHeight });
    } catch (err) {
      console.error("Navigation error:", err);
      setMessage(`Gagal navigasi ke block #${targetHeight}: ${err.message}`);
    } finally {
      setIsNavigating(false);
    }
  };

  // Return to Latest Block (←)
  const handleGoToLatest = () => {
    if (tipHeight !== null && scrollerRef.current) {
      setSelectedHeight(tipHeight);
      handleSelect({ height: tipHeight });
      setNavInput("");
      scrollerRef.current.scrollTo({
        left: 0,
        behavior: "smooth",
      });
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter") {
      handleNavigateToBlock();
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

  // Generate visible cards array
  const renderedCards = useMemo(() => {
    if (totalCount === 0 || tipHeight === null) return [];
    const items = [];
    for (let i = startIndex; i <= endIndex; i++) {
      const h = tipHeight - i;
      const blockData = blocksMap.get(h);
      items.push({
        height: h,
        block: blockData || null,
        isGenesis: h === 0,
      });
    }
    return items;
  }, [startIndex, endIndex, tipHeight, totalCount, blocksMap]);

  return (
    <main className="page">
      <section className="section">
        <div className="block-header-bar">
          <div className="block-header-left">
            <LiveIndicator
              isLive={isLive}
              onToggleLive={() => setIsLive((prev) => !prev)}
              onRefresh={handleManualRefresh}
              lastUpdated={lastUpdated}
              isRefreshing={isRefreshing}
              intervalSec={20}
              label="Live Sync"
            />
          </div>
          <div className="navigation-controls">
            <button
              className="nav-button nav-button--back"
              onClick={handleGoToLatest}
              title="Kembali ke block terkini"
              disabled={tipHeight === null || selectedHeight === tipHeight}
            >
              ←
            </button>

            <div className="nav-input-group">
              <input
                type="number"
                className="nav-input"
                placeholder={tipHeight === null ? "Block height" : `0 - ${tipHeight}`}
                value={navInput}
                onChange={(e) => setNavInput(e.target.value)}
                onKeyDown={handleKeyDown}
                min="0"
                max={tipHeight ?? undefined}
              />
              <button
                className="nav-button nav-button--go"
                onClick={handleNavigateToBlock}
                disabled={isNavigating || !navInput.trim()}
              >
                {isNavigating ? "..." : "Go"}
              </button>
            </div>
          </div>
        </div>

        <div className="lane">
          {loadingInitial && totalCount === 0 ? (
            <SkeletonCard count={6} />
          ) : (
            <section
              className={`lane-scroll ${isDragging ? "lane-scroll--dragging" : ""}`}
              ref={scrollerRef}
              aria-label="Block list"
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
              {renderedCards.map(({ height: h, block: item, isGenesis }) =>
                item ? (
                  <BlockCard
                    key={h}
                    item={item}
                    active={h === selectedHeight}
                    isGenesis={isGenesis}
                    onSelect={handleSelect}
                    onSearchClick={handleSearchClickLocal}
                  />
                ) : (
                  <SkeletonBlockCard key={h} height={h} />
                )
              )}

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

        {message && <div className="result-empty">{message}</div>}
      </section>

      <section className="section">
        {detailStatus === "loading" && <SkeletonSearch />}
        {detailStatus === "error" && (
          <div className="result-empty">
            {detailMessage || "Gagal memuat detail."}
          </div>
        )}
        {detailStatus === "done" && detail ? (
          <ResultBlock data={detail} onSearchClick={handleSearchClickLocal} />
        ) : null}
      </section>
    </main>
  );
};

Block.propTypes = {
  onSearchClick: PropTypes.func,
};

BlockCard.propTypes = {
  item: PropTypes.shape({
    graffiti_posts: PropTypes.number,
    graffiti_comments: PropTypes.number,
    graffiti_payouts: PropTypes.number,
    block_id: PropTypes.string,
    graffiti_count: PropTypes.number,
    timestamp: PropTypes.number,
    height: PropTypes.number,
    hash: PropTypes.string,
    tx_count: PropTypes.number,
  }),
  onSelect: PropTypes.func.isRequired,
  active: PropTypes.bool,
  isGenesis: PropTypes.bool,
};

export default Block;

