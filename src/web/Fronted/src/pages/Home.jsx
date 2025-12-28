import { useCallback, useEffect, useRef, useState } from "react";
import { fetchBlockRange, fetchByKind } from "../api/explorer";
import { fmtBytes } from "../utils/format";
import { ResultBlock } from "../components/search/SearchResults";
import "./pages.css";

const PAGE_SIZE = 10;
const SCROLL_THRESHOLD = 40;

const BlockCard = ({ item, onSelect, active, isGenesis }) => {
  const graffitiPosts = Number(item?.graffiti_posts || 0);
  const graffitiComments = Number(item?.graffiti_comments || 0);
  const graffitiCount =
    item?.graffiti_count ?? graffitiPosts + graffitiComments;
  const classes = [
    "lane-card",
    graffitiPosts > 0 ? "lane-card--graffiti" : "",
    active ? "lane-card--active" : "",
    isGenesis ? "lane-card--genesis" : "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <button className={classes} type="button" onClick={() => onSelect(item)}>
      <div className="lane-card__header">Block {item?.height ?? "-"}</div>
      {graffitiPosts > 0 ? (
        <div className="lane-card__tag">Graffiti Post</div>
      ) : null}
      <div className="lane-card__grid">
        <div className="stat">
          <span className="label">Size</span>
          <span className="value">{fmtBytes(item?.size_bytes)}</span>
        </div>
        <div className="stat">
          <span className="label">Transactions</span>
          <span className="value">{item?.tx_count ?? 0}</span>
        </div>
        <div className="stat">
          <span className="label">Graffiti Activity</span>
          <span className="value">{graffitiCount ?? 0}</span>
        </div>
      </div>
    </button>
  );
};

const Home = () => {
  const [blocks, setBlocks] = useState([]);
  const [nextHeight, setNextHeight] = useState(null);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [detail, setDetail] = useState(null);
  const [detailStatus, setDetailStatus] = useState("idle");
  const [detailMessage, setDetailMessage] = useState("");
  const [selectedHeight, setSelectedHeight] = useState(null);
  const [isDragging, setIsDragging] = useState(false);

  const scrollerRef = useRef(null);
  const dragRef = useRef({
    isDown: false,
    startX: 0,
    scrollLeft: 0,
    moved: false,
    wasDrag: false,
  });

  const loadBlocks = useCallback(
    async (startHeight) => {
      if (loading || !hasMore) return;
      setLoading(true);
      setMessage("");
      try {
        const resp = await fetchBlockRange({
          limit: PAGE_SIZE,
          startHeight,
        });
        const data = resp.data || {};
        const incoming = Array.isArray(data.items) ? data.items : [];
        setBlocks((prev) => {
          const seen = new Set(prev.map((blk) => blk?.height));
          const merged = [...prev];
          for (const item of incoming) {
            if (item?.height === undefined || seen.has(item.height)) continue;
            seen.add(item.height);
            merged.push(item);
          }
          return merged;
        });
        const next =
          data.nextHeight ??
          data.next_height ??
          (incoming.length
            ? Number(incoming[incoming.length - 1]?.height ?? 0) - 1
            : -1);
        setNextHeight(next);
        const more =
          data.hasMore ??
          data.has_more ??
          (incoming.length > 0 && Number(next) >= 0);
        setHasMore(Boolean(more));
      } catch (err) {
        setMessage(err.message || "Gagal memuat block.");
      } finally {
        setLoading(false);
      }
    },
    [hasMore, loading]
  );

  useEffect(() => {
    if (blocks.length === 0 && !loading) {
      loadBlocks(null);
    }
  }, [blocks.length, loadBlocks, loading]);

  const handleScroll = useCallback(() => {
    const el = scrollerRef.current;
    if (!el || loading || !hasMore) return;
    if (el.scrollLeft + el.clientWidth >= el.scrollWidth - SCROLL_THRESHOLD) {
      loadBlocks(nextHeight);
    }
  }, [hasMore, loading, loadBlocks, nextHeight]);

  const handleMouseDown = (event) => {
    if (event.button !== undefined && event.button !== 0) return;
    const el = scrollerRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    dragRef.current.isDown = true;
    dragRef.current.startX = event.clientX - rect.left;
    dragRef.current.scrollLeft = el.scrollLeft;
    dragRef.current.moved = false;
    dragRef.current.wasDrag = false;
    setIsDragging(true);
  };

  const handleMouseMove = (event) => {
    if (!dragRef.current.isDown) return;
    const el = scrollerRef.current;
    if (!el) return;
    event.preventDefault();
    const rect = el.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const walk = x - dragRef.current.startX;
    if (Math.abs(walk) > 6) {
      dragRef.current.moved = true;
    }
    el.scrollLeft = dragRef.current.scrollLeft - walk;
  };

  const endDrag = () => {
    dragRef.current.isDown = false;
    dragRef.current.wasDrag = dragRef.current.moved;
    setIsDragging(false);
    setTimeout(() => {
      dragRef.current.wasDrag = false;
    }, 0);
  };

  const handleClickCapture = (event) => {
    if (dragRef.current.wasDrag) {
      event.preventDefault();
      event.stopPropagation();
      dragRef.current.wasDrag = false;
    }
  };

  const handleSelect = async (item) => {
    if (!item || item.height === undefined) return;
    setDetailStatus("loading");
    setDetailMessage("");
    setSelectedHeight(item.height);
    try {
      const resp = await fetchByKind("block", item.height);
      setDetail(resp.data || null);
      setDetailStatus("done");
    } catch (err) {
      setDetail(null);
      setDetailStatus("error");
      setDetailMessage(err.message || "Gagal memuat detail block.");
    }
  };

  return (
    <main className="page">
      <section className="section">
        <div className="section-header">
          <div>
            <h2>Latest Blocks</h2>
            <p className="muted">
              Swipe right to load older blocks.
            </p>
          </div>
        </div>
        <div className="lane">
          <div
            className={`lane-scroll ${isDragging ? "lane-scroll--dragging" : ""}`}
            ref={scrollerRef}
            onScroll={handleScroll}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={endDrag}
            onMouseLeave={endDrag}
            onClickCapture={handleClickCapture}
          >
            {blocks.map((item) => (
              <BlockCard
                key={item.height ?? item.hash}
                item={item}
                active={item.height === selectedHeight}
                isGenesis={Number(item?.height ?? -1) === 0}
                onSelect={handleSelect}
              />
            ))}
          </div>
        </div>
        {loading && <div className="result-empty">Memuat block...</div>}
        {message && <div className="result-empty">{message}</div>}
      </section>

      <section className="section">
        {detailStatus === "loading" && (
          <div className="result-empty">Memuat detail block...</div>
        )}
        {detailStatus === "error" && (
          <div className="result-empty">
            {detailMessage || "Gagal memuat detail."}
          </div>
        )}
        {detailStatus === "done" && detail ? <ResultBlock data={detail} /> : null}
      </section>
    </main>
  );
};

export default Home;
