import { useState } from "react";
import { ClickableValue } from ".././SearchResults";
import { fmtBytes, fmtTimestamp, fmtTsar } from "../../../utils/format"
import "../search.css";
import "../label.css";

const ResultGraffiti = ({ data, onSearchClick }) => {
  const mime = String(data?.mime || "").toLowerCase();
  const isVideo = mime.includes("video") || mime.includes("mp4");
  const [showDetails, setShowDetails] = useState(false);

  return (
    <div className="card">
      <span className="graffiti-details">Graffiti Details #{data?.block_height ?? "-"}</span>
      <div className="divider" />

      {/* Media Preview */}
      {data?.preview_url ? (
        isVideo ? (
          <video
            className="media-preview"
            controls
            preload="metadata"
            src={data.preview_url}
          />
        ) : (
          <img
            className="media-preview"
            src={data.preview_url}
            alt="Graffiti preview"
            loading="lazy"
          />
        )
      ) : (
        <div className="muted">Preview is not available</div>
      )}

      {/* Toggle Button */}
      <div style={{ display: 'flex', justifyContent: 'right', margin: '15px 0' }}>
        <button 
          onClick={() => setShowDetails(!showDetails)}
          style={{
            padding: '8px 20px',
            backgroundColor: showDetails ? '#cd7213' : '#9a5710',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
            fontWeight: '600',
            fontSize: '14px',
            transition: 'background-color 0.3s ease',
            boxShadow: '0 2px 4px rgba(0,0,0,0.2)'
          }}
          onMouseEnter={(e) => e.target.style.backgroundColor = '#eb8c27'}
          onMouseLeave={(e) => e.target.style.backgroundColor = showDetails ? '#cd7213' : '#9a5710'}
        >
          {showDetails ? 'Hide Details' : 'View Details'}
        </button>
      </div>

      <div className="divider" />

      {showDetails && (
        <div className="graffiti-details-border">
          <div className="stat">
            <div className="grid">
              <div className="stat">
                <span className="info-label">Graffiti ID</span>
                <span className="value">{data?.art_id || "-"}</span>
              </div>
              <div className="stat">
                <span className="info-label">Creator</span>
                <ClickableValue value={data?.creator || "-"} onSearchClick={onSearchClick} className="value muted">
                  {data?.creator || "-"}
                </ClickableValue>
              </div>
            </div>
            <div className="grid">
              <div className="stat">
                <span className="info-label">Upload Fee</span>
                <span className="value">{fmtTsar(data?.amount_paid)}</span>
              </div>
              <div className="stat">
                <span className="info-label">Total Creator Income</span>
                <span className="value">{fmtTsar(data?.stats?.creator_paid)}</span>
              </div>
            </div>

            <div className="divider2" />

            <div className="grid">
              <div className="stat">
                <span className="info-label">Anchoring at</span>
                <span className="value">Block {data?.block_height ?? "-"}</span>
              </div>
              <div className="stat">
                <span className="info-label">Block Hash</span>
                <ClickableValue value={data?.block_hash ?? "-"} onSearchClick={onSearchClick} className="value muted">
                  {data?.block_hash ?? "-"}
                </ClickableValue>
              </div>
            </div>
            <div className="stat">
              <span className="info-label">Transaction ID</span>
              <ClickableValue value={data?.txid || "-"} onSearchClick={onSearchClick} className="value muted">
                {data?.txid || "-"}
              </ClickableValue>
            </div>
          </div>

          <div className="divider2" />

          <div className="stat">
            <div className="grid">
              <div className="stat">
                <span className="info-label">SHA256 File</span>
                <span className="value">{data?.sha256 || "-"}</span>
              </div>
              <div className="stat">
                <span className="info-label">Graffiti Merkle</span>
                <span className="value">{data?.mroot || "-"}</span>
              </div>
            </div>
            <div className="grid">
              <div className="stat">
                <span className="info-label">Merkle Chunk</span>
                <span className="value">{fmtBytes(data?.mchunk)}</span>
              </div>
              <div className="stat">
                <span className="info-label">Merkle Count</span>
                <span className="value">{data?.mcount || "-"}</span>
              </div>
            </div>
            <div className="grid">
              <div className="stat">
                <span className="info-label">File Size</span>
                <span className="value">{fmtBytes(data?.size || data?.size_bytes)}</span>
              </div>
              <div className="stat">
              </div>
            </div>
          </div>

          <div className="divider2" />

          <div className="grid">
            <div className="stat">
              <span className="info-label">Pool Address</span>
              <ClickableValue value={data?.pool_address} onSearchClick={onSearchClick} className="value muted">
                {data?.pool_address}
              </ClickableValue>
            </div>
            <div className="stat">
              <span className="info-label">Pool Balance</span>
              <span className="value">{fmtTsar(data?.stats?.pool_balance)}</span>
            </div>
          </div>
          <div className="grid">
            <div className="stat">
              <span className="info-label">Storage Address</span>
              <ClickableValue value={data?.storer} onSearchClick={onSearchClick} className="value muted">
                {data?.storer}
              </ClickableValue>
            </div>
            <div className="stat">
              <span className="info-label">Storage Income From Comment</span>
              <span className="value">{fmtTsar(data?.stats?.storage_paid)}</span>
            </div>
          </div>
          <div className="stat">
            <span className="info-label">Last Paid Epoch</span>
            <span className="value">Epoch {data?.stats?.last_paid_epoch}</span>
          </div>
        </div>
      )}

      <div className="divider" />

      <div className="list">
        <div className="stat" style={{ marginBottom: '10px' }}>
          <span className="value">Comments : {data?.comments?.length || 0}</span>
        </div>
        {(data?.comments || []).slice(0, 6).map((c, idx) => (
          <div className="comment-item" key={idx}>
            <div className="muted">{fmtTimestamp(c.ts)}</div>
            <div className="value">
            <ClickableValue value={c.commenter || "-"} onSearchClick={onSearchClick} className="value muted">
                {c.commenter || "-"}
            </ClickableValue>
            </div>
            <div className="divider" />
            <div className="value">{c.comment_text || c.comment || "-"}</div>
            <div className="divider" />
            <div className="muted">{fmtTsar(c.amount)} {c.tip ? ` - Tip ${fmtTsar(c.tip)}` : ""}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

export { ResultGraffiti }
