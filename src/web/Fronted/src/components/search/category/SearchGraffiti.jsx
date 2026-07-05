import PropTypes from "prop-types";
import { useState } from "react";
import { useRenderHelpers } from "./SearchHelpers";
import { ClickableValue } from "../SearchResults";
import { Document, Page, pdfjs } from 'react-pdf';
import { 
  fmtBytes, 
  fmtTimestamp, 
  fmtTsar, 
  fmtAddress,
  fmtHash,
  fmtTxid
} from "../../../utils/format"
import { GrNext, GrPrevious } from "react-icons/gr";

// Konfigurasi worker PDF
pdfjs.GlobalWorkerOptions.workerSrc = `//unpkg.com/pdfjs-dist@${pdfjs.version}/build/pdf.worker.min.mjs`;

const ResultGraffiti = ({ data, onSearchClick }) => {
  const mime = String(data?.mime || "").toLowerCase();
  const isVideo = mime.includes("video") || mime.includes("mp4");
  const isPdf = mime.includes("pdf") || (data?.preview_url && data.preview_url.toLowerCase().endsWith('.pdf'));
  const { renderHash, renderClickableHash } = useRenderHelpers();
  const [showDetails, setShowDetails] = useState(false);
  const [numPages, setNumPages] = useState(null);
  const [pageNumber, setPageNumber] = useState(1);

  // Fungsi untuk PDF loading success
  const onDocumentLoadSuccess = ({ numPages }) => {
    setNumPages(numPages);
    setPageNumber(1);
  };

  // Navigasi halaman PDF
  const goToPrevPage = () => setPageNumber(pageNumber - 1);
  const goToNextPage = () => setPageNumber(pageNumber + 1);

  return (
      <>
      {/* Media Preview */}
      {data?.preview_url ? (
        isVideo ? (
          <video
            className="media-preview"
            controls
            preload="metadata"
            src={data.preview_url}
          >
            <track
              kind="captions"
              src={data?.captions_url || ''}
              label="Captions"
              default={!!data?.captions_url}
            />
          </video>
        ) : isPdf ? (
          <div className="pdf-preview-container">
            
            <div className="pdf-document-wrapper">
              <Document
                file={data.preview_url}
                onLoadSuccess={onDocumentLoadSuccess}
                loading={
                  <div className="pdf-loading">
                    Loading PDF preview...
                  </div>
                }
                error={
                  <div className="pdf-error muted">
                    PDF preview could not be loaded.{' '}
                    <a href={data.preview_url} target="_blank" rel="noopener noreferrer">
                      Open PDF directly
                    </a>
                  </div>
                }
                className="pdf-document"
              >
                <Page 
                  pageNumber={pageNumber} 
                  className="pdf-page"
                  width={700}
                  renderTextLayer={false}
                  renderAnnotationLayer={false}
                />
              </Document>
            </div>

            <div className="pdf-controls">
              <button 
                onClick={goToPrevPage}
                disabled={pageNumber <= 1}
                className="pdf-nav-button"
              >
              <GrPrevious />
              </button>
              <span className="pdf-page-info">
              {pageNumber} of {numPages || '--'}
              </span>
              <button 
                onClick={goToNextPage}
                disabled={pageNumber >= (numPages || 1)}
                className="pdf-nav-button"
              >
              <GrNext />
              </button>
            </div>

          </div>
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
      <div className="divider" />
      {/* END OF Media Preview */}

      {/* Toggle Button */}
      <div 
        style={{
        maxWidth: '1250px',
        borderRadius: '3px',
        padding: '1.5rem',
        margin: '0 auto 0.5rem auto'
        }}
        >
        <div style={{ display: 'flex', justifyContent: 'right' }}>
          <button 
            onClick={() => setShowDetails(!showDetails)}
            style={{
              padding: '8px 20px',
              backgroundColor: showDetails ? '#cd7213' : '#9a5710',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
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
      </div>
      {/* END OF Toggle Button */}

    <div className="card">
      {showDetails && (
        <div className="graffiti-details-border">
          <div className="stat">
            <div className="grid">
              <div className="stat">
                <span className="info-label">Graffiti ID</span>
                {renderHash(data?.art_id, "wrap")}
              </div>
              <div className="stat">
                <span className="info-label">Creator</span>
                  {renderClickableHash(
                    data.creator,
                    onSearchClick,
                    data.creator,
                    fmtAddress(data.creator) || "-"
                  )}
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
                  {renderClickableHash(
                    data.block_hash,
                    onSearchClick,
                    data.block_hash,
                    fmtHash(data.block_hash)
                  )}
              </div>
            </div>
            <div className="stat">
              <span className="info-label">Transaction ID</span>
                {renderClickableHash(
                  data.txid,
                  onSearchClick,
                  data.txid,
                  fmtTxid(data.txid)
                )}
            </div>
          </div>

          <div className="divider2" />

          <div className="stat">
            <div className="grid">
              <div className="stat">
                <span className="info-label">SHA256 File</span>
                {renderHash(data?.sha256, "wrap")}
              </div>
              <div className="stat">
                <span className="info-label">Graffiti Merkle</span>
                {renderHash(data?.mroot, "wrap")}
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
              {renderClickableHash(
                data.pool_address,
                onSearchClick,
                data.pool_address,
                fmtAddress(data.pool_address)
              )}
            </div>
            <div className="stat">
              <span className="info-label">Pool Balance</span>
              <span className="value">{fmtTsar(data?.stats?.pool_balance)}</span>
            </div>
          </div>
          <div className="grid">
            <div className="stat">
              <span className="info-label">Storage Address</span>
              {renderClickableHash(
                data.storer,
                onSearchClick,
                data.storer,
                fmtAddress(data.storer)
              )}
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
    </>
  );
};

ResultGraffiti.propTypes = {
  data: PropTypes.shape({
    // Base
    mime: PropTypes.string,
    preview_url: PropTypes.string,
    captions_url: PropTypes.string,
    art_id: PropTypes.string,
    creator: PropTypes.string,
    amount_paid: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    block_height: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    block_hash: PropTypes.string,
    txid: PropTypes.string,
    sha256: PropTypes.string,
    mroot: PropTypes.string,
    mchunk: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    mcount: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    size: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    size_bytes: PropTypes.number,
    pool_address: PropTypes.string,
    storer: PropTypes.string,

    // Stats object
    stats: PropTypes.shape({
      creator_paid: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
      pool_balance: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
      storage_paid: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
      last_paid_epoch: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    }),

    // Array comments
    comments: PropTypes.arrayOf(
      PropTypes.shape({
        commenter: PropTypes.string,
        ts: PropTypes.number,
        comment_text: PropTypes.string,
        comment: PropTypes.string,
        amount: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
        tip: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
      })
    ),
  }),
  onSearchClick: PropTypes.func.isRequired,
};

export { ResultGraffiti }
