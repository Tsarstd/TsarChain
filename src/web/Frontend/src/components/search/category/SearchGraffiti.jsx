import PropTypes from "prop-types";
import { useState, useEffect, useRef } from "react";
import { useRenderHelpers } from "../SearchHelpers";
import { ClickableValue } from "../SearchResults";
import { graffitiMediaUrl } from "../../../api/explorer";
import { 
  FaDownload, 
  FaSearchPlus, 
  FaSearchMinus, 
  FaSync, 
  FaExpand, 
  FaCompress, 
  FaAngleLeft, 
  FaAngleRight,
  FaComments,
  FaCommentDots,
  FaUserCircle,
  FaCoins,
  FaClock,
  FaChevronDown,
  FaChevronUp
} from "react-icons/fa";

import { Document, Page, pdfjs } from 'react-pdf';
import { 
  fmtBytes, 
  fmtTimestamp, 
  fmtTsar, 
  fmtAddress,
  fmtHash,
  fmtTxid
} from "../../../utils/format";

// Konfigurasi worker PDF
pdfjs.GlobalWorkerOptions.workerSrc = `//unpkg.com/pdfjs-dist@${pdfjs.version}/build/pdf.worker.min.mjs`;

// Komponen Interactive Image Zoom & Drag
const ImageZoomViewer = ({ src, alt = "Graffiti preview" }) => {
  const [scale, setScale] = useState(1);
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const stageRef = useRef(null);

  const handleZoomIn = () => {
    setScale((prev) => Math.min(5, Number((prev + 0.25).toFixed(2))));
  };

  const handleZoomOut = () => {
    setScale((prev) => {
      const next = Math.max(1, Number((prev - 0.25).toFixed(2)));
      if (next === 1) setPosition({ x: 0, y: 0 });
      return next;
    });
  };

  const handleReset = () => {
    setScale(1);
    setPosition({ x: 0, y: 0 });
  };

  // Native event listeners for mouse wheel zoom & stage drag
  useEffect(() => {
    const stage = stageRef.current;
    if (!stage) return;

    const handleWheelNative = (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (e.deltaY < 0) {
        setScale((prev) => Math.min(5, Number((prev + 0.25).toFixed(2))));
      } else {
        setScale((prev) => {
          const next = Math.max(1, Number((prev - 0.25).toFixed(2)));
          if (next === 1) setPosition({ x: 0, y: 0 });
          return next;
        });
      }
    };

    const handleMouseDownNative = (e) => {
      setIsDragging(true);
      setDragStart({ x: e.clientX - position.x, y: e.clientY - position.y });
    };

    const handleMouseMoveNative = (e) => {
      if (!isDragging) return;
      setPosition({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y,
      });
    };

    const handleMouseUpNative = () => {
      setIsDragging(false);
    };

    const handleDoubleClickNative = () => {
      setScale((prev) => {
        if (prev > 1) {
          setPosition({ x: 0, y: 0 });
          return 1;
        }
        return 2;
      });
    };

    stage.addEventListener("wheel", handleWheelNative, { passive: false });
    stage.addEventListener("mousedown", handleMouseDownNative);
    stage.addEventListener("dblclick", handleDoubleClickNative);
    globalThis.addEventListener("mousemove", handleMouseMoveNative);
    globalThis.addEventListener("mouseup", handleMouseUpNative);

    return () => {
      stage.removeEventListener("wheel", handleWheelNative);
      stage.removeEventListener("mousedown", handleMouseDownNative);
      stage.removeEventListener("dblclick", handleDoubleClickNative);
      globalThis.removeEventListener("mousemove", handleMouseMoveNative);
      globalThis.removeEventListener("mouseup", handleMouseUpNative);
    };
  }, [isDragging, dragStart, position]);

  const isCanDragClass = scale > 1 ? "can-drag" : "";
  const isDraggingClass = isDragging ? "dragging" : "";

  return (
    <div className="image-zoom-container">
      <div className="image-zoom-toolbar">
        <button
          type="button"
          onClick={handleZoomIn}
          disabled={scale >= 5}
          className="zoom-btn"
          title="Zoom In (+)"
        >
          <FaSearchPlus />
        </button>
        <span className="zoom-level">{Math.round(scale * 100)}%</span>
        <button
          type="button"
          onClick={handleZoomOut}
          disabled={scale <= 1}
          className="zoom-btn"
          title="Zoom Out (-)"
        >
          <FaSearchMinus />
        </button>
        <button
          type="button"
          onClick={handleReset}
          disabled={scale === 1 && position.x === 0 && position.y === 0}
          className="zoom-btn reset-btn"
          title="Reset Zoom & Position"
        >
          <FaSync />
        </button>
      </div>

      <section
        ref={stageRef}
        className={`image-zoom-stage ${isDraggingClass} ${isCanDragClass}`}
        aria-label="Interactive Graffiti Image Stage"
      >
        <img
          className="media-preview zoomable-image"
          src={src}
          alt={alt}
          style={{
            transform: `translate(${position.x}px, ${position.y}px) scale(${scale})`,
            transition: isDragging ? "none" : "transform 0.15s ease-out",
          }}
          draggable={false}
        />
      </section>
    </div>
  );
};

ImageZoomViewer.propTypes = {
  src: PropTypes.string.isRequired,
  alt: PropTypes.string,
};

// Komponen Smart PDF Viewer dengan Smart Control Toolbar
const SmartPdfViewer = ({ file, previewUrl }) => {
  const [numPages, setNumPages] = useState(null);
  const [pageNumber, setPageNumber] = useState(1);
  const [pageInput, setPageInput] = useState("1");
  const [scale, setScale] = useState(1);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const containerRef = useRef(null);

  const onDocumentLoadSuccess = ({ numPages: totalPages }) => {
    setNumPages(totalPages);
    setPageNumber(1);
    setPageInput("1");
  };

  const goToPrevPage = () => {
    setPageNumber((prev) => {
      const next = Math.max(1, prev - 1);
      setPageInput(String(next));
      return next;
    });
  };

  const goToNextPage = () => {
    setPageNumber((prev) => {
      const next = Math.min(numPages || 1, prev + 1);
      setPageInput(String(next));
      return next;
    });
  };

  const commitPageJump = () => {
    const val = Number.parseInt(pageInput, 10);
    if (!Number.isNaN(val) && val >= 1 && val <= (numPages || 1)) {
      setPageNumber(val);
    } else {
      setPageInput(String(pageNumber));
    }
  };

  const handlePageInputSubmit = (e) => {
    if (e.key === "Enter") {
      commitPageJump();
    }
  };

  const handleZoomIn = () => {
    setScale((prev) => Math.min(2.5, Number((prev + 0.15).toFixed(2))));
  };

  const handleZoomOut = () => {
    setScale((prev) => Math.max(0.5, Number((prev - 0.15).toFixed(2))));
  };

  const toggleFullscreen = () => {
    if (!containerRef.current) return;
    if (document.fullscreenElement) {
      document.exitFullscreen().then(() => setIsFullscreen(false)).catch(() => {});
    } else {
      containerRef.current.requestFullscreen().then(() => setIsFullscreen(true)).catch(() => {});
    }
  };

  useEffect(() => {
    const handleFullscreenChange = () => {
      setIsFullscreen(!!document.fullscreenElement);
    };
    document.addEventListener("fullscreenchange", handleFullscreenChange);
    return () => document.removeEventListener("fullscreenchange", handleFullscreenChange);
  }, []);

  // Keyboard navigation for PDF reader
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;

      if (e.key === "ArrowLeft" || e.key === "PageUp") {
        e.preventDefault();
        goToPrevPage();
      } else if (e.key === "ArrowRight" || e.key === "PageDown") {
        e.preventDefault();
        goToNextPage();
      }
    };

    globalThis.addEventListener("keydown", handleKeyDown);
    return () => globalThis.removeEventListener("keydown", handleKeyDown);
  }, [numPages, pageNumber]);

  return (
    <div
      ref={containerRef}
      className={`smart-pdf-container ${isFullscreen ? "fullscreen" : ""}`}
    >
      {/* Smart Control Toolbar */}
      <div className="pdf-smart-toolbar">
        {/* Direct Page Jump Input & Prev/Next */}
        <div className="pdf-toolbar-group pdf-page-jump">
          <button
            type="button"
            onClick={goToPrevPage}
            disabled={pageNumber <= 1}
            className="pdf-tool-btn"
            title="Previous Page (←)"
          >
            <FaAngleLeft />
          </button>
          <div className="pdf-page-counter">
            <span>Page</span>
            <input
              type="number"
              min={1}
              max={numPages || 1}
              value={pageInput}
              onChange={(e) => setPageInput(e.target.value)}
              onKeyDown={handlePageInputSubmit}
              onBlur={commitPageJump}
              className="pdf-page-input"
              aria-label="Direct Page Number Jump"
            />
            <span>of {numPages || "--"}</span>
          </div>
          <button
            type="button"
            onClick={goToNextPage}
            disabled={pageNumber >= (numPages || 1)}
            className="pdf-tool-btn"
            title="Next Page (→)"
          >
            <FaAngleRight />
          </button>
        </div>

        {/* Zoom & Fullscreen Controls */}
        <div className="pdf-toolbar-group">
          <button
            type="button"
            onClick={handleZoomIn}
            disabled={scale >= 2.5}
            className="pdf-tool-btn"
            title="Zoom In (+)"
          >
            <FaSearchPlus />
          </button>
          <span className="pdf-scale-indicator">{Math.round(scale * 100)}%</span>
          <button
            type="button"
            onClick={handleZoomOut}
            disabled={scale <= 0.5}
            className="pdf-tool-btn"
            title="Zoom Out (-)"
          >
            <FaSearchMinus />
          </button>
          <button
            type="button"
            onClick={toggleFullscreen}
            className="pdf-tool-btn"
            title={isFullscreen ? "Exit Fullscreen" : "Fullscreen Reader Mode"}
          >
            {isFullscreen ? <FaCompress /> : <FaExpand />}
          </button>
        </div>
      </div>

      {/* PDF Stage Wrapper */}
      <div className="pdf-stage-wrapper">
        <Document
          file={file}
          onLoadSuccess={onDocumentLoadSuccess}
          loading={<div className="pdf-loading">Loading PDF document...</div>}
          error={
            <div className="pdf-error muted">
              PDF document could not be rendered.{" "}
              {previewUrl && (
                <a href={previewUrl} target="_blank" rel="noopener noreferrer">
                  Open PDF directly
                </a>
              )}
            </div>
          }
          className="pdf-document"
        >
          <Page
            pageNumber={pageNumber}
            className="pdf-page"
            scale={scale}
            renderTextLayer={false}
            renderAnnotationLayer={false}
          />
        </Document>
      </div>
    </div>
  );
};

SmartPdfViewer.propTypes = {
  file: PropTypes.any.isRequired,
  previewUrl: PropTypes.string,
};

const ResultGraffiti = ({ data, onSearchClick }) => {
  const mime = String(data?.mime || "").toLowerCase();
  const isVideo = mime.includes("video") || mime.includes("mp4");
  const isPdf = mime.includes("pdf") || data?.preview_url?.toLowerCase().endsWith('.pdf');
  const { renderHash, renderClickableHash } = useRenderHelpers();
  const [showDetails, setShowDetails] = useState(false);
  const [showAllComments, setShowAllComments] = useState(false);

  // Percentage Loading State for Media
  const [loadingProgress, setLoadingProgress] = useState(0);
  const [isLoaded, setIsLoaded] = useState(false);
  const [mediaBlobUrl, setMediaBlobUrl] = useState(null);

  useEffect(() => {
    const targetUrl = data?.preview_url || (data?.art_id ? graffitiMediaUrl(data.art_id) : null);
    if (!targetUrl) {
      setIsLoaded(true);
      setLoadingProgress(100);
      return;
    }

    const size = Number(data?.size || data?.size_bytes || 0);
    const isLargeOrStreamable = isVideo || (size > 10 * 1024 * 1024);

    if (isLargeOrStreamable) {
      // Direct HTTP Streaming mode: allow browser native HTTP Range streaming
      setIsLoaded(true);
      setLoadingProgress(100);
      setMediaBlobUrl(null);
      return;
    }

    let isMounted = true;
    setIsLoaded(false);
    setLoadingProgress(0);

    const xhr = new XMLHttpRequest();
    xhr.open("GET", targetUrl, true);
    xhr.responseType = "blob";

    xhr.onprogress = (event) => {
      if (isMounted) {
        if (event.lengthComputable && event.total > 0) {
          const percent = Math.min(99, Math.round((event.loaded / event.total) * 100));
          setLoadingProgress(percent);
        } else {
          setLoadingProgress((prev) => Math.min(95, prev + 15));
        }
      }
    };

    xhr.onload = () => {
      if (isMounted) {
        if (xhr.status >= 200 && xhr.status < 300) {
          const blob = xhr.response;
          const objectUrl = URL.createObjectURL(blob);
          setMediaBlobUrl(objectUrl);
          setLoadingProgress(100);
          setIsLoaded(true);
        } else {
          setIsLoaded(true);
          setLoadingProgress(100);
        }
      }
    };

    xhr.onerror = () => {
      if (isMounted) {
        setIsLoaded(true);
        setLoadingProgress(100);
      }
    };

    xhr.send();

    return () => {
      isMounted = false;
      xhr.abort();
      if (mediaBlobUrl) {
        URL.revokeObjectURL(mediaBlobUrl);
      }
    };
  }, [data?.art_id, data?.preview_url, data?.size, data?.size_bytes, isVideo]);

  // Render media preview
  const renderMediaPreview = () => {
    if (!data?.preview_url) {
      return <div className="muted">Preview is not available</div>;
    }

    if (!isLoaded) {
      return (
        <div className="graffiti-loading-box glass-panel">
          <div className="graffiti-loading-content">
            <span className="graffiti-loading-spinner" />
            <div className="graffiti-loading-text">
              <span>Loading Graffiti Media...</span>
              <span className="graffiti-pct">{loadingProgress}%</span>
            </div>
            <div className="graffiti-progress-track">
              <div className="graffiti-progress-fill" style={{ width: `${loadingProgress}%` }} />
            </div>
          </div>
        </div>
      );
    }

    if (isVideo) {
      return (
        <video
          className="media-preview"
          controls
          controlsList="nodownload"
          onContextMenu={(e) => e.preventDefault()}
          preload="metadata"
          src={mediaBlobUrl || data.preview_url}
        >
          <track
            kind="captions"
            src={data?.captions_url || ''}
            label="Captions"
            default={!!data?.captions_url}
          />
        </video>
      );
    }

    if (isPdf) {
      return (
        <SmartPdfViewer
          file={mediaBlobUrl || data.preview_url}
          previewUrl={data.preview_url}
        />
      );
    }

    return (
      <ImageZoomViewer
        src={mediaBlobUrl || data.preview_url}
        alt="Graffiti preview"
      />
    );
  };

  return (
      <>
      {/* Media Preview */}
      {renderMediaPreview()}
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
        <div style={{ display: 'flex', justifyContent: 'right', gap: '10px', alignItems: 'center' }}>
          {data?.art_id && (
            <button
              type="button"
              disabled={!isLoaded}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '8px 18px',
                backgroundColor: isLoaded ? '#10b981' : '#475569',
                color: isLoaded ? 'white' : '#94a3b8',
                border: 'none',
                borderRadius: '4px',
                cursor: isLoaded ? 'pointer' : 'not-allowed',
                fontSize: '14px',
                fontWeight: '500',
                opacity: isLoaded ? 1 : 0.65,
                transition: 'all 0.3s ease',
                boxShadow: '0 2px 4px rgba(0,0,0,0.2)'
              }}
              onMouseEnter={(e) => {
                if (isLoaded) e.currentTarget.style.backgroundColor = '#059669';
              }}
              onMouseLeave={(e) => {
                if (isLoaded) e.currentTarget.style.backgroundColor = '#10b981';
              }}
              title={isLoaded ? `Download media (${data.art_id})` : `Loading media data (${loadingProgress}%)...`}
              onClick={() => {
                if (!isLoaded) return;
                const downloadUrl = mediaBlobUrl || graffitiMediaUrl(data.art_id);
                const link = document.createElement("a");
                link.href = downloadUrl;
                link.download = `${data.art_id}`;
                document.body.appendChild(link);
                link.click();
                link.remove();
              }}
            >
              <FaDownload /> {isLoaded ? "Download" : `Loading (${loadingProgress}%)...`}
            </button>
          )}
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
                fmtHash(data.block_hash),
                true
              )}
            </div>
            </div>
            <div className="stat">
              <span className="info-label">Transaction ID</span>
                {renderClickableHash(
                  data.txid,
                  onSearchClick,
                  data.txid,
                  fmtTxid(data.txid),
                  true
                )}
            </div>
          </div>

          <div className="divider2" />

          <div className="stat">
            <div className="grid">
              <div className="stat">
                <span className="info-label">SHA256 File</span>
                {renderHash(data?.sha256, "wrap", false)}
              </div>
              <div className="stat">
                <span className="info-label">Graffiti Merkle</span>
                {renderHash(data?.mroot, "wrap", false)}
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
                fmtAddress(data.pool_address),
                true
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
                fmtAddress(data.storer),
                true
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

      {/* Comments Section */}
      <div className="comments-section">
        <div className="comments-header">
          <div className="comments-title">
            <FaComments className="comments-icon" />
            <span>Comments</span>
            <span className="comments-count-badge">{data?.comments?.length || 0}</span>
          </div>
        </div>

        {(!data?.comments || data.comments.length === 0) ? (
          <div className="comments-empty-state">
            <FaCommentDots className="empty-icon" />
            <p>No comments on this graffiti yet.</p>
          </div>
        ) : (
          <div className="comments-list">
            {(showAllComments ? data.comments : data.comments.slice(0, 5)).map((c, index) => {
              const commenterAddress = c.commenter || "-";
              const commentText = c.comment_text || c.comment || "-";
              const tipNum = Number(c.tip || 0);
              const hasTip = !Number.isNaN(tipNum) && tipNum > 0;
              const amountNum = Number(c.amount || 0);
              const hasAmount = c.amount !== undefined && c.amount !== null && !Number.isNaN(amountNum) && amountNum > 0;

              return (
                <div className="comment-card" key={c.txid || `${commenterAddress}-${c.ts}-${index}`}>
                  <div className="comment-card-header">
                    <div className="comment-user-info">
                      <div className="comment-avatar">
                        <FaUserCircle />
                      </div>
                      <ClickableValue
                        value={commenterAddress}
                        onSearchClick={onSearchClick}
                        className="comment-author-link"
                        info={commenterAddress}
                        isCopyable={true}
                      >
                        {fmtAddress(commenterAddress) || commenterAddress}
                      </ClickableValue>
                    </div>
                    {c.ts && (
                      <div className="comment-timestamp">
                        <FaClock className="clock-icon" />
                        <span>{fmtTimestamp(c.ts)}</span>
                      </div>
                    )}
                  </div>

                  <div className="comment-card-body">
                    <p className="comment-text">{commentText}</p>
                  </div>

                  {(hasAmount || hasTip) && (
                    <div className="comment-card-footer">
                      {hasAmount && (
                        <span className="comment-badge amount-badge" title="Fee Paid">
                          Fee: {fmtTsar(c.amount)}
                        </span>
                      )}
                      {hasTip && (
                        <span className="comment-badge tip-badge" title="Tip Amount">
                          <FaCoins className="tip-icon" /> Tip: {fmtTsar(c.tip)}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              );
            })}

            {data.comments.length > 5 && (
              <button
                type="button"
                className="comments-toggle-btn"
                onClick={() => setShowAllComments((prev) => !prev)}
              >
                {showAllComments ? (
                  <>
                    <FaChevronUp /> Show Less
                  </>
                ) : (
                  <>
                    <FaChevronDown /> Show All Comments ({data.comments.length})
                  </>
                )}
              </button>
            )}
          </div>
        )}
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
