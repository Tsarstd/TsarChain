import React, { useCallback, useEffect, useRef, useState } from "react";
import { fetchGraffitiDetail, fetchGraffitiList } from "../api/explorer";
import { fmtBytes, fmtTimestamp, fmtTsar, shortHash } from "../utils/format";

const PAGE_SIZE = 24;

const isVideoMime = (mime) => {
  const m = String(mime || "").toLowerCase();
  return m.includes("video") || m.includes("mp4");
};

const GraffitiCard = ({ item, onSelect }) => {
  const video = isVideoMime(item?.mime);
  return (
    <button className="media-card" type="button" onClick={() => onSelect(item)}>
      <div className={`media-thumb ${video ? "media-thumb--video" : "media-thumb--image"}`}>
        {item?.preview_url ? (
          video ? (
            <video src={item.preview_url} preload="metadata" muted />
          ) : (
            <img src={item.preview_url} alt={item.art_id} loading="lazy" />
          )
        ) : (
          <div className="media-fallback">No Preview</div>
        )}
      </div>
      <div className="media-meta">
        <div className="media-title"> Graffiti Block {item?.block_height ?? "-"}</div>
        <div className="media-sub">{fmtBytes(item?.size || item?.size_bytes)} - {item?.mime ?? "-"}</div>
      </div>
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
                  <div className="muted">{fmtTsar(c.amount)} {c.tip ? ` - Tip ${fmtTsar(c.tip)}` : ""}</div>
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

  const sentinelRef = useRef(null);

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

  useEffect(() => {
    const sentinel = sentinelRef.current;
    if (!sentinel) return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting) {
          loadMore();
        }
      },
      { rootMargin: "200px" }
    );
    observer.observe(sentinel);
    return () => observer.disconnect();
  }, [loadMore]);

  const handleSelect = async (item) => {
    if (!item?.art_id) return;
    setDetailStatus("loading");
    setDetail(null);
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
  };

  return (
    <main className="page">
      <section className="section">
        <h2>Graffiti Gallery</h2>
        <p className="muted">Katalog media graffiti terbaru dari jaringan TsarChain.</p>
      </section>

      <section className="gallery-grid">
        {items.map((item) => (
          <GraffitiCard key={item.art_id} item={item} onSelect={handleSelect} />
        ))}
      </section>

      <div ref={sentinelRef} className="scroll-sentinel" />
      {loading && <div className="result-empty">Memuat lebih banyak...</div>}
      {!hasMore && items.length > 0 && <div className="result-empty">Tidak ada data lagi.</div>}
      {message && <div className="result-empty">{message}</div>}

      <GraffitiDetail detail={detail} status={detailStatus} onClose={closeDetail} />
    </main>
  );
};

export default Graffiti;
