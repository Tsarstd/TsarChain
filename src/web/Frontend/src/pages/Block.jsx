import PropTypes from "prop-types";
import { useNavigate } from "react-router-dom";
import { fmtDateLong, timeAgo } from "../utils/format";
import { fetchBlockRange, fetchByKind } from "../api/explorer";
import { ResultBlock } from "../components/search/SearchResults";
import { SkeletonCard, SkeletonSearch } from "../components/common/SkeletonLoader";
import { LiveIndicator } from "../components/common/LiveIndicator";
import { useCallback, useEffect, useState, memo } from "react";
import { useDragScroll } from "../utils/useDragScroll";

const PAGE_SIZE = 200;
const SCROLL_THRESHOLD = 800;
const CACHE_KEY = 'block_range_cache';
const CACHE_EXPIRE_MS = 15 * 60 * 1000;

const getCachedState = () => {
  try {
    const cached = localStorage.getItem(CACHE_KEY);
    if (cached) {
      const { state, timestamp } = JSON.parse(cached);
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

const Home = ({ onSearchClick }) => {
  const navigate = useNavigate();
  const [cachedState] = useState(() => getCachedState());
  const [blocks, setBlocks] = useState(() => cachedState?.blocks || []);
  const [nextHeight, setNextHeight] = useState(() => cachedState?.nextHeight ?? null);
  const [hasMore, setHasMore] = useState(() => cachedState?.hasMore ?? true);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [detail, setDetail] = useState(null);
  const [detailStatus, setDetailStatus] = useState("idle");
  const [detailMessage, setDetailMessage] = useState("");
  const [selectedHeight, setSelectedHeight] = useState(null);
  const [navInput, setNavInput] = useState("");
  const [isNavigating, setIsNavigating] = useState(false);
  const [initialLoadDone, setInitialLoadDone] = useState(() => cachedState?.initialLoadDone || false);
  const [isLive, setIsLive] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [isRefreshing, setIsRefreshing] = useState(false);
  const { scrollerRef, isDragging, dragHandlers } = useDragScroll();

  const handleSearchClickLocal = useCallback((value) => {
    if (onSearchClick) {
      onSearchClick(value);
    } else {
      navigate(`/?search=${encodeURIComponent(value)}`);
    }
  }, [onSearchClick, navigate]);

  useEffect(() => {
    if (blocks.length > 0 || nextHeight !== null || hasMore !== true) {
      setCachedState({ blocks, nextHeight, hasMore, initialLoadDone });
    }
  }, [blocks, nextHeight, hasMore, initialLoadDone]);

  const fetchBlocks = useCallback(
    async (startHeight) => {
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
    []
  );

  const loadBlocks = useCallback(
    async (startHeight, forceRefresh = false) => {
      if ((loading && !forceRefresh) || (!forceRefresh && !hasMore)) return;
      setLoading(true);
      setMessage("");
      await fetchBlocks(startHeight);
    },
    [fetchBlocks, hasMore, loading]
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
    let isMounted = true;
    const initialBlocks = cachedState?.blocks || [];
    if (initialBlocks.length > 0) {
      const latestCachedHeight = initialBlocks[0]?.height;
      fetchBlockRange({ limit: 1, source: 'database' })
        .then((resp) => {
          if (!isMounted) return;
          const currentTip = resp.data?.items?.[0]?.height;
          setLastUpdated(new Date());
          if (currentTip > latestCachedHeight) {
            fetchBlockRange({ limit: PAGE_SIZE, startHeight: null, source: 'database' })
              .then((freshResp) => {
                if (!isMounted) return;
                const incoming = Array.isArray(freshResp.data?.items) ? freshResp.data.items : [];
                setBlocks(incoming);
                setNextHeight(freshResp.data?.nextHeight ?? -1);
                setHasMore(Boolean(freshResp.data?.hasMore));
                setInitialLoadDone(true);
              })
              .catch(console.error);
          }
        })
        .catch(console.error);
    } else {
      fetchBlockRange({ limit: PAGE_SIZE, startHeight: null, source: 'database' })
        .then((freshResp) => {
          if (!isMounted) return;
          const incoming = Array.isArray(freshResp.data?.items) ? freshResp.data.items : [];
          setBlocks(incoming);
          setNextHeight(freshResp.data?.nextHeight ?? -1);
          setHasMore(Boolean(freshResp.data?.hasMore));
          setInitialLoadDone(true);
        })
        .catch((err) => {
          if (isMounted) setMessage(err.message || "Gagal memuat block.");
        });
    }
    return () => {
      isMounted = false;
    };
  }, [cachedState]);

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
        <div className="block-header-bar">
          <div className="block-header-left">
            <LiveIndicator
              isLive={isLive}
              onToggleLive={() => setIsLive(prev => !prev)}
              onRefresh={handleManualRefresh}
              lastUpdated={lastUpdated}
              isRefreshing={isRefreshing}
              intervalSec={30}
              label="Live Sync"
            />
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
