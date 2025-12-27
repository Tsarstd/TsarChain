import { useCallback, useEffect, useRef, useState } from "react";
import { fetchGraffitiDetail, fetchGraffitiList } from "../api/explorer";
import { fmtBytes, fmtTimestamp, fmtTsar } from "../utils/format";

const PAGE_SIZE = 10;
const SCROLL_THRESHOLD = 40;

const isVideoMime = (mime) => {
  const m = String(mime || "").toLowerCase();
  return m.includes("video") || m.includes("mp4");
};

const GraffitiCard = ({ item, onSelect, active, isGenesis }) => {
  const comments = item?.stats?.comments ?? item?.comments?.length ?? 0;
  const classes = ["lane-card", active ? "lane-card--active" : "", isGenesis ? "lane-card--genesis" : ""]
    .filter(Boolean)
    .join(" ");
  return (
    <button className={classes} type="button" onClick={() => onSelect(item)}>
      <div className="lane-card__title">Graffiti Block {item?.block_height ?? "-"}</div>
      <div className="lane-card__grid">
        <div className="stat">
          <span className="label">Size</span>
          <span className="value">{fmtBytes(item?.size || item?.size_bytes)}</span>
        </div>
        <div className="stat">
          <span className="label">Type</span>
          <span className="value">{item?.mime || "-"}</span>
        </div>
        <div className="stat">
          <span className="label">Total Comments</span>
          <span className="value">{comments}</span>
        </div>
      </div>
      <div className="lane-card__id mono wrap">{item?.art_id || "-"}</div>
    </button>
  );
};

const GraffitiDetail = ({ detail, status, onClose }) => {
  if (!detail && status !== "loading") return null;
  const video = isVideoMime(detail?.mime);
  return (
    <section className="detail-panel">
      <div className="detail-header">
        <div>
          <h3>Graffiti Detail</h3>
          <p className="mono wrap">{detail?.art_id || "-"}</p>
        </div>
        <button className="btn-ghost" type="button" onClick={onClose}>
          Close
        </button>
      </div>
      {status === "loading" ? (
        <div className="muted">Memuat detail...</div>
      ) : (
        <div className="detail-body">
          <div className="detail-media">
            {detail?.preview_url ? (
              video ? (
                <video controls preload="metadata" src={detail.preview_url} />
              ) : (
                <img src={detail.preview_url} alt={detail.art_id} />
              )
            ) : (
              <div className="media-fallback">Preview tidak tersedia</div>
            )}
          </div>
          <div className="detail-meta">
            <div className="stat">
              <span className="label">Creator</span>
              <span className="value mono wrap">{detail?.creator || "-"}</span>
            </div>
            <div className="stat">
              <span className="label">Block</span>
              <span className="value">#{detail?.block_height ?? "-"}</span>
            </div>
            <div className="stat">
              <span className="label">Size</span>
              <span className="value">{fmtBytes(detail?.size || detail?.size_bytes)}</span>
            </div>
            <div className="stat">
              <span className="label">MIME</span>
              <span className="value">{detail?.mime || "-"}</span>
            </div>
            <div className="stat">
              <span className="label">TxID</span>
              <span className="value mono wrap">{detail?.txid || "-"}</span>
            </div>
            <div className="stat">
              <span className="label">Merkle</span>
              <span className="value mono wrap">{detail?.mroot || "-"}</span>
            </div>
            <div className="stat">
              <span className="label">Merkle Chunk</span>
              <span className="value mono wrap">{detail?.mchunk || "-"}</span>
            </div>
            <div className="stat">
              <span className="label">Merkle Count</span>
              <span className="value mono wrap">{detail?.mcount || "-"}</span>
            </div>
            <div className="stat">
              <span className="label">Pool Address</span>
              <span className="value mono wrap">{detail?.pool_address || "-"}</span>
            </div>
          </div>
          <div className="detail-comments">
            <h4>Comments ({detail?.comments?.length || 0})</h4>
            <div className="list">
              {(detail?.comments || []).slice(0, 12).map((c, idx) => (
                <div className="comment-item" key={idx}>
                  <div className="muted">{fmtTimestamp(c.ts)}</div>
                  <div className="value">{c.commenter || "-"}</div>
                  <div className="value">{"-----------"}</div>
                  <div className="value">{c.comment_text || c.comment || "-"}</div>
                  <div className="value">{"-----------"}</div>
                  <div className="muted">
                    {fmtTsar(c.amount)} {c.tip ? ` - Tip ${fmtTsar(c.tip)}` : ""}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </section>
  );
};

const Graffiti = () => {
  const [items, setItems] = useState([]);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [detail, setDetail] = useState(null);
  const [detailStatus, setDetailStatus] = useState("idle");
  const [selectedId, setSelectedId] = useState(null);
  const [isDragging, setIsDragging] = useState(false);

  const scrollerRef = useRef(null);
  const dragRef = useRef({
    isDown: false,
    startX: 0,
    scrollLeft: 0,
    moved: false,
    wasDrag: false,
  });

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
      setMessage(err.message || "Gagal memuat graffiti.");
    } finally {
      setLoading(false);
    }
  }, [hasMore, loading, offset]);

  useEffect(() => {
    if (items.length === 0 && !loading) {
      loadMore();
    }
  }, [items.length, loading, loadMore]);

  const handleScroll = useCallback(() => {
    const el = scrollerRef.current;
    if (!el || loading || !hasMore) return;
    if (el.scrollLeft + el.clientWidth >= el.scrollWidth - SCROLL_THRESHOLD) {
      loadMore();
    }
  }, [hasMore, loading, loadMore]);

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
      setMessage(err.message || "Gagal memuat detail graffiti.");
    }
  };

  const closeDetail = () => {
    setDetail(null);
    setDetailStatus("idle");
    setSelectedId(null);
  };

  const genesisId = !hasMore && items.length
    ? items[items.length - 1]?.art_id
    : null;

  return (
    <main className="page">
      <section className="section">
        <div className="section-header">
          <div>
            <h2>Graffiti Gallery</h2>
            <p className="muted">Swipe right to load older graffiti.</p>
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
            {items.map((item) => (
              <GraffitiCard
                key={item.art_id}
                item={item}
                active={item.art_id === selectedId}
                isGenesis={Boolean(genesisId && item.art_id === genesisId)}
                onSelect={handleSelect}
              />
            ))}
          </div>
        </div>
        {loading && <div className="result-empty">Memuat lebih banyak...</div>}
        {!hasMore && items.length > 0 && <div className="result-empty">Tidak ada data lagi.</div>}
        {message && <div className="result-empty">{message}</div>}
      </section>

      <GraffitiDetail detail={detail} status={detailStatus} onClose={closeDetail} />
    </main>
  );
};

export default Graffiti;
