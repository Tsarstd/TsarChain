import PropTypes from "prop-types";
import { useNavigate } from "react-router-dom";
import { fmtDateLong, timeAgo } from "../utils/format";
import { fetchBlockRange, fetchByKind } from "../api/explorer";
import { ResultBlock } from "../components/search/SearchResults";
import { SkeletonCard, SkeletonSearch } from "../components/common/SkeletonLoader";
import { LiveIndicator } from "../components/common/LiveIndicator";
import { useCallback, useEffect, useRef, useState, memo } from "react";

const PAGE_SIZE = 200;
const SCROLL_THRESHOLD = 800;
const CACHE_KEY = 'block_range_cache';
const CACHE_EXPIRE_MS = 15 * 60 * 1000;

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

      {!isGenesis && !isGraffiti && blockId ? (
        <div className="lane-card__bid">{blockId}</div>
      ) : null}

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

// ============ Custom Hook for Drag Scroll ============
export const useDragScroll = () => {
  const scrollerRef = useRef(null);
  const [isDragging, setIsDragging] = useState(false);
  const dragRef = useRef({
    isDown: false,
    startX: 0,
    scrollLeft: 0,
    moved: false,
    wasDrag: false,
  });

  useEffect(() => {
    const handleGlobalMouseMove = (e) => {
      if (!dragRef.current.isDown) return;
      const el = scrollerRef.current;
      if (!el) return;

      const walk = (e.clientX - dragRef.current.startX) * 1.15;
      if (Math.abs(walk) > 5) {
        dragRef.current.moved = true;
        setIsDragging(true);
      }
      el.scrollLeft = dragRef.current.scrollLeft - walk;
    };

    const handleGlobalMouseUp = () => {
      if (!dragRef.current.isDown) return;
      dragRef.current.isDown = false;
      dragRef.current.wasDrag = dragRef.current.moved;
      setIsDragging(false);
      setTimeout(() => {
        dragRef.current.wasDrag = false;
      }, 100);
    };

    globalThis.addEventListener("mousemove", handleGlobalMouseMove);
    globalThis.addEventListener("mouseup", handleGlobalMouseUp);
    return () => {
      globalThis.removeEventListener("mousemove", handleGlobalMouseMove);
      globalThis.removeEventListener("mouseup", handleGlobalMouseUp);
    };
  }, []);

  const handleMouseDown = (event) => {
    if (event.button !== undefined && event.button !== 0) return;
    const el = scrollerRef.current;
    if (!el) return;
    dragRef.current.isDown = true;
    dragRef.current.startX = event.clientX;
    dragRef.current.scrollLeft = el.scrollLeft;
    dragRef.current.moved = false;
    dragRef.current.wasDrag = false;
  };

  const handleTouchStart = (event) => {
    const touch = event.touches[0];
    if (!touch) return;
    const el = scrollerRef.current;
    if (!el) return;
    dragRef.current.isDown = true;
    dragRef.current.startX = touch.clientX;
    dragRef.current.scrollLeft = el.scrollLeft;
    dragRef.current.moved = false;
    dragRef.current.wasDrag = false;
  };

  const handleTouchMove = (event) => {
    if (!dragRef.current.isDown) return;
    const el = scrollerRef.current;
    if (!el) return;
    const touch = event.touches[0];
    if (!touch) return;
    const walk = (touch.clientX - dragRef.current.startX) * 1.15;
    if (Math.abs(walk) > 5) {
      dragRef.current.moved = true;
      setIsDragging(true);
    }
    el.scrollLeft = dragRef.current.scrollLeft - walk;
  };

  const handleTouchEnd = () => {
    dragRef.current.isDown = false;
    dragRef.current.wasDrag = dragRef.current.moved;
    setIsDragging(false);
    setTimeout(() => {
      dragRef.current.wasDrag = false;
    }, 100);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      e.preventDefault();
      const el = scrollerRef.current;
      if (!el) return;
      const scrollAmount = e.key === 'ArrowLeft' ? -300 : 300;
      el.scrollBy({ left: scrollAmount, behavior: 'smooth' });
    }
  };

  const handleClickCapture = (event) => {
    if (dragRef.current.wasDrag) {
      event.preventDefault();
      event.stopPropagation();
      dragRef.current.wasDrag = false;
    }
  };

  return {
    scrollerRef,
    isDragging,
    dragHandlers: {
      onMouseDown: handleMouseDown,
      onTouchStart: handleTouchStart,
      onTouchMove: handleTouchMove,
      onTouchEnd: handleTouchEnd,
      onKeyDown: handleKeyDown,
      onClickCapture: handleClickCapture,
    },
  };
};

const Home = ({ onSearchClick }) => {
  const navigate = useNavigate();
  const [blocks, setBlocks] = useState([]);
  const [nextHeight, setNextHeight] = useState(null);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [detail, setDetail] = useState(null);
  const [detailStatus, setDetailStatus] = useState("idle");
  const [detailMessage, setDetailMessage] = useState("");
  const [selectedHeight, setSelectedHeight] = useState(null);
  const [navInput, setNavInput] = useState("");
  const [isNavigating, setIsNavigating] = useState(false);
  const [initialLoadDone, setInitialLoadDone] = useState(false);
  const [isLive, setIsLive] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [isRefreshing, setIsRefreshing] = useState(false);
  const { scrollerRef, isDragging, dragHandlers } = useDragScroll();

  const handleSearchClickLocal = useCallback((value) => {
    if (onSearchClick) {
      onSearchClick(value);
    } else {
      // Fallback ke navigate
      navigate(`/?search=${encodeURIComponent(value)}`);
    }
  }, [onSearchClick, navigate]);

  const getCachedState = () => {
    try {
      const cached = localStorage.getItem(CACHE_KEY);
      if (cached) {
        const { state, timestamp } = JSON.parse(cached);
        // Cache valid selama 5 menit
        if (Date.now() - timestamp < CACHE_EXPIRE_MS) {
          return state;
        }
      }
    } catch (e) {
      console.warn('Cache read error:', e);
    }
    return null;
  };

  const setCachedState = (state) => {
    try {
      localStorage.setItem(CACHE_KEY, JSON.stringify({
        state,
        timestamp: Date.now()
      }));
    } catch (e) {
      console.warn('Cache write error:', e);
    }
  };

  useEffect(() => {
    if (blocks.length > 0 || nextHeight !== null || hasMore !== true) {
      setCachedState({ blocks, nextHeight, hasMore, initialLoadDone });
    }
  }, [blocks, nextHeight, hasMore, initialLoadDone]);

  const loadBlocks = useCallback(
    async (startHeight, forceRefresh = false) => {
      if ((loading && !forceRefresh) || (!forceRefresh && !hasMore)) return;
      
      setLoading(true);
      setMessage("");
      
      try {
        const resp = await fetchBlockRange({
          limit: PAGE_SIZE,
          startHeight,
          source: 'database'
        });
        
        const data = resp.data || {};
        const incoming = Array.isArray(data.items) ? data.items : [];
        
        setBlocks((prev) => {
          const blockMap = new Map();
          
          incoming.forEach(item => {
            if (item?.height !== undefined) {
              blockMap.set(item.height, item);
            }
          });
          
          prev.forEach(item => {
            if (item?.height !== undefined) {
              blockMap.set(item.height, item);
            }
          });
          
          const merged = Array.from(blockMap.values())
            .sort((a, b) => b.height - a.height);
          
          return merged;
        });
        
        const next = data.nextHeight ?? 
          data.next_height ?? 
          (incoming.length ? Number(incoming[incoming.length - 1]?.height ?? 0) - 1 : -1);
        
        setNextHeight(next);
        const more = data.hasMore ?? 
          data.has_more ?? 
          (incoming.length > 0 && Number(next) >= 0);
        
        setHasMore(Boolean(more));
        setInitialLoadDone(true);
        setLastUpdated(new Date());
      } catch (err) {
        setMessage(err.message || "Gagal memuat block.");
      } finally {
        setLoading(false);
      }
    },
    [hasMore, loading]
  );

  const handleManualRefresh = useCallback(async () => {
    if (isRefreshing) return;
    setIsRefreshing(true);
    try {
      await loadBlocks(null, true);
      setLastUpdated(new Date());
    } catch (err) {
      console.error(err);
    } finally {
      setIsRefreshing(false);
    }
  }, [loadBlocks, isRefreshing]);

  useEffect(() => {
    const cached = getCachedState();
    
    if (cached?.blocks?.length > 0) {
      setBlocks(cached.blocks);
      setNextHeight(cached.nextHeight);
      setHasMore(cached.hasMore);
      setInitialLoadDone(cached.initialLoadDone || false);
      
      if (cached.blocks.length > 0) {
        const latestCachedHeight = cached.blocks[0].height;
        
        fetchBlockRange({ limit: 1, source: 'database' })
          .then(resp => {
            const currentTip = resp.data?.items?.[0]?.height;
            setLastUpdated(new Date());
            if (currentTip > latestCachedHeight) {
              loadBlocks(null, true);
            }
          })
          .catch(console.error);
      }
    } else {
      loadBlocks(null);
    }
  }, []);

  useEffect(() => {
    if (!isLive) return;

    const refreshInterval = setInterval(() => {
      if (blocks.length > 0 && !loading && !isRefreshing) {
        const latestHeight = blocks[0]?.height;
        setIsRefreshing(true);
        fetchBlockRange({ limit: 1, source: 'database' })
          .then(resp => {
            const currentTip = resp.data?.items?.[0]?.height;
            setLastUpdated(new Date());
            if (currentTip > latestHeight) {
              loadBlocks(null, true);
            }
          })
          .catch(console.error)
          .finally(() => {
            setIsRefreshing(false);
          });
      }
    }, 30000);
    
    return () => clearInterval(refreshInterval);
  }, [isLive, blocks, loading, isRefreshing, loadBlocks]);





  const handleNavigateToBlock = async () => {
    const targetHeight = Number.parseInt(navInput);
    if (Number.isNaN(targetHeight) || targetHeight < 0) {
      setMessage("Input a valid Block Height");
      return;
    }

    setIsNavigating(true);
    setMessage("");

    try {
      const existingBlock = blocks.find(block => block.height === targetHeight);
      
      if (existingBlock) {
        await handleSelect(existingBlock);
        scrollToBlock(targetHeight);
        setIsNavigating(false);
        return;
      }

      // Fetch block target
      const resp = await fetchByKind("block", targetHeight);
      const blockData = resp.data || null;
      
      if (blockData) {
        // Fetch 5 blocks sebelumnya (lebih rendah height-nya)
        const beforeResp = await fetchBlockRange({
          startHeight: Math.max(0, targetHeight - 50), // Ambil 50 block sebelumnya
          limit: 80, // Ambil lebih banyak untuk jaga-jaga
          source: 'database'
        });
        
        // Fetch 50 blocks sesudahnya (lebih tinggi height-nya)
        const afterResp = await fetchBlockRange({
          startHeight: targetHeight + 1,
          limit: 80,
          source: 'database'
        });
        
        // Gabungkan semua block yang didapat
        const allNewBlocks = [];
        
        if (beforeResp.data?.items) {
          allNewBlocks.push(...beforeResp.data.items);
        }
        
        allNewBlocks.push(blockData);
        
        if (afterResp.data?.items) {
          allNewBlocks.push(...afterResp.data.items);
        }
        
        // Update state blocks dengan block baru
        setBlocks(prev => {
          const blockMap = new Map();
          
          // Tambahkan existing blocks
          prev.forEach(item => {
            if (item?.height !== undefined) {
              blockMap.set(item.height, item);
            }
          });
          
          // Tambahkan new blocks
          allNewBlocks.forEach(item => {
            if (item?.height !== undefined) {
              blockMap.set(item.height, item);
            }
          });
          
          const merged = Array.from(blockMap.values())
            .sort((a, b) => b.height - a.height);
          
          return merged;
        });
        
        // Set detail block target
        setDetail(blockData);
        setDetailStatus("done");
        setSelectedHeight(targetHeight);
        
        // Scroll ke block target setelah render
        setTimeout(() => scrollToBlock(targetHeight), 100);
      } else {
        setMessage(`Block #${targetHeight} not found`);
      }
    } catch (err) {
      console.error('Navigation error:', err);
      setMessage(err.message || "Failed to navigate to block target");
    } finally {
      setIsNavigating(false);
    }
  };

  const scrollToBlock = (height) => {
    const blockIndex = blocks.findIndex(block => block.height === height);
    if (blockIndex !== -1 && scrollerRef.current) {
      const cardWidth = 240 + 18;
      const scrollPosition = Math.max(0, blockIndex * cardWidth - 200);
      scrollerRef.current.scrollTo({
        left: scrollPosition,
        behavior: 'smooth'
      });
    }
  };

  const handleGoToLatest = () => {
    if (blocks.length > 0) {
      const latestBlock = blocks[0];
      setSelectedHeight(latestBlock.height);
      setDetail(null);
      setDetailStatus("idle");
      setNavInput("");
      
      if (scrollerRef.current) {
        scrollerRef.current.scrollTo({
          left: 0,
          behavior: 'smooth'
        });
      }
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      handleNavigateToBlock();
    }
  };

  const handleSelect = async (item) => {
    if (item?.height === undefined) return;
    
    const cacheKey = `block_detail_${item.height}`;
    const cachedDetail = localStorage.getItem(cacheKey);
    
    if (cachedDetail) {
      const { detail: cached, timestamp } = JSON.parse(cachedDetail);
      if (Date.now() - timestamp < 60000) { // Cache 1 menit
        setDetail(cached);
        setDetailStatus("done");
        setSelectedHeight(item.height);
        return;
      }
    }
    
    setDetailStatus("loading");
    setDetailMessage("");
    setSelectedHeight(item.height);
    
    try {
      const resp = await fetchByKind("block", item.height);
      const detailData = resp.data || null;
      setDetail(detailData);
      setDetailStatus("done");
      
      if (detailData) {
        localStorage.setItem(cacheKey, JSON.stringify({
          detail: detailData,
          timestamp: Date.now()
        }));
      }
    } catch (err) {
      setDetail(null);
      setDetailStatus("error");
      setDetailMessage(err.message || "Gagal memuat detail block.");
    }
  };

  const handleScroll = useCallback(() => {
    const el = scrollerRef.current;
    if (!el || loading || !hasMore) return;
    if (el.scrollLeft + el.clientWidth >= el.scrollWidth - SCROLL_THRESHOLD) {
      loadBlocks(nextHeight);
    }
  }, [hasMore, loading, loadBlocks, nextHeight, scrollerRef]);

  return (
    <main className="page">
      <section className="section">
        <div className="section-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <LiveIndicator
              isLive={isLive}
              onToggleLive={() => setIsLive(prev => !prev)}
              onRefresh={handleManualRefresh}
              lastUpdated={lastUpdated}
              isRefreshing={isRefreshing}
              intervalSec={30}
              label="LIVE BLOCK STREAM"
            />
            <p className="muted" style={{ margin: 0 }}>
              Swipe right to load older blocks.
            </p>
          </div>
          <div className="navigation-controls">
            <button 
              className="nav-button nav-button--back"
              onClick={handleGoToLatest}
              title="Kembali ke block terkini"
              disabled={blocks.length === 0 || selectedHeight === blocks[0]?.height}
            >
              ←
            </button>
            
            <div className="nav-input-group">
              <input
                type="number"
                className="nav-input"
                placeholder="Block height"
                value={navInput}
                onChange={(e) => setNavInput(e.target.value)}
                onKeyDown={handleKeyDown}
                min="0"
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
          {blocks.length === 0 && loading ? (
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
              {blocks.map((item) => (
                <BlockCard
                  key={item.height ?? item.hash}
                  item={item}
                  active={item.height === selectedHeight}
                  isGenesis={Number(item?.height ?? -1) === 0}
                  onSelect={handleSelect}
                  onSearchClick={handleSearchClickLocal}
                />
              ))}
            </section>
          )}
        </div>

        {message && <div className="result-empty">{message}</div>}
      </section>

      <section className="section">
        {detailStatus === "loading" && (
          <SkeletonSearch />
        )}
        {detailStatus === "error" && (
          <div className="result-empty">
            {detailMessage || "Gagal memuat detail."}
          </div>
        )}
        {detailStatus === "done" && detail ? <ResultBlock data={detail} onSearchClick={handleSearchClickLocal} /> : null}
      </section>
    </main>
  );
};

Home.propTypes = {
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

export default Home;
