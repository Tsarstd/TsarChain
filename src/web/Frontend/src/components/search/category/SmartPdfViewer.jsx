import { useState, useRef, useEffect } from "react";
import PropTypes from "prop-types";
import { Document, Page, pdfjs } from "react-pdf";
import {
  FaSearchPlus,
  FaSearchMinus,
  FaExpand,
  FaCompress,
  FaAngleLeft,
  FaAngleRight,
} from "react-icons/fa";

// Configure PDF worker
pdfjs.GlobalWorkerOptions.workerSrc = `//unpkg.com/pdfjs-dist@${pdfjs.version}/build/pdf.worker.min.mjs`;

export const SmartPdfViewer = ({ file, previewUrl }) => {
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
        setPageNumber((prev) => {
          const next = Math.max(1, prev - 1);
          setPageInput(String(next));
          return next;
        });
      } else if (e.key === "ArrowRight" || e.key === "PageDown") {
        e.preventDefault();
        setPageNumber((prev) => {
          const next = Math.min(numPages || 1, prev + 1);
          setPageInput(String(next));
          return next;
        });
      }
    };

    globalThis.addEventListener("keydown", handleKeyDown);
    return () => globalThis.removeEventListener("keydown", handleKeyDown);
  }, [numPages]);

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

export default SmartPdfViewer;
