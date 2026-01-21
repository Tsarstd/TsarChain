import { useState, useEffect } from "react";
import { ClickableValue } from ".././SearchResults";
import {  
  fmtAddress,
  fmtDateLong,
  fmtTsar, 
  fmtTxid,
  timeAgo,
  formatHashForDisplay,
  getMaxCharsPerLine
} from "../../../utils/format"
import { getStatusBadge, getDirectionBadge } from "../SearchUX";

const ResultAddress = ({ data, onSearchClick }) => {
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(10);

  const [isMobile, setIsMobile] = useState(false);
  const [maxCharsPerLine, setMaxCharsPerLine] = useState(getMaxCharsPerLine());
  
  useEffect(() => {
    setCurrentPage(1);
  }, [data?.address]);

  
  useEffect(() => {
    const checkMobile = () => {
      const mobile = window.innerWidth <= 768;
      setIsMobile(mobile);
      setMaxCharsPerLine(getMaxCharsPerLine());
    };

  checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, []);
  
  const historyData = data?.history || [];
  const totalItems = Math.min(historyData.length, 200); // limit
  const totalPages = Math.ceil(totalItems / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = Math.min(startIndex + itemsPerPage, totalItems);
  const currentHistory = historyData.slice(startIndex, endIndex);
  
  const handlePageChange = (page) => {
    if (page >= 1 && page <= totalPages) {
      setCurrentPage(page);
    }
  };
  
  const getPageNumbers = () => {
    const pageNumbers = [];
    const maxVisiblePages = 20; // Maximum number of page buttons to show
    
    if (totalPages <= maxVisiblePages) {
      for (let i = 1; i <= totalPages; i++) {
        pageNumbers.push(i);
      }
    } else {
      if (currentPage <= 3) {
        for (let i = 1; i <= 4; i++) {
          pageNumbers.push(i);
        }
        pageNumbers.push('...');
        pageNumbers.push(totalPages);
      } else if (currentPage >= totalPages - 2) {
        pageNumbers.push(1);
        pageNumbers.push('...');
        for (let i = totalPages - 3; i <= totalPages; i++) {
          pageNumbers.push(i);
        }
      } else {
        pageNumbers.push(1);
        pageNumbers.push('...');
        pageNumbers.push(currentPage - 1);
        pageNumbers.push(currentPage);
        pageNumbers.push(currentPage + 1);
        pageNumbers.push('...');
        pageNumbers.push(totalPages);
      }
    }
    
    return pageNumbers;
  };

  const renderHash = (hash, className = "") => {
    if (!hash) return "-";
    
    if (isMobile) {
      const formattedHash = formatHashForDisplay(hash, maxCharsPerLine);
      return (
        <span className={`value hash-multiline ${className}`} style={{whiteSpace: 'pre-wrap'}}>
          {formattedHash}
        </span>
      );
    }
    
    return <span className={`value ${className}`}>{hash}</span>;
  };

  const renderClickableHash = (value, onSearchClick, info, displayValue = null) => {
    if (!value) return "-";
    
    const display = displayValue || value;
    
    if (isMobile) {
      const formattedHash = formatHashForDisplay(display, maxCharsPerLine);
      return (
        <ClickableValue 
          value={value} 
          onSearchClick={onSearchClick} 
          className="value muted hash-multiline"
          info={info}
          style={{whiteSpace: 'pre-wrap'}}
        >
          {formattedHash}
        </ClickableValue>
      );
    }
    
    return (
      <ClickableValue 
        value={value} 
        onSearchClick={onSearchClick} 
        className="value muted"
        info={info}
      >
        {display}
      </ClickableValue>
    );
  };

  const renderAddressLabel = (direction, fromAddress, toAddress) => {
    if (direction === 'in') {
      if (fromAddress === 'coinbase') {
        return (
          <>
            <span className="tx-address-label">From : </span>
            <span className="coinbase-label">Coinbase</span>
          </>
        );
      } else {
        return (
          <>
            <span className="tx-address-label">From : </span>
            {renderClickableHash(
              fromAddress,
              onSearchClick,
              fromAddress,
              fmtAddress(fromAddress)
            )}
          </>
        );
      }
    } else if (direction === 'out') {
      return (
        <>
          <span className="tx-address-label">To : </span>
            {renderClickableHash(
              toAddress,
              onSearchClick,
              toAddress,
              fmtAddress(toAddress)
            )}
        </>
      );
    }
    return null;
  };

  return (
    <>
      <h1 className="address-details">{renderHash(data?.address, "wrap")}</h1>
        <div className="divider" />

      <div className="card">
        <div className="grid">
          <div className="stat">
            <span className="info-label">Balance</span>
            <span className="value">{fmtTsar(data?.balance)}</span>
          </div>
          <div className="stat">
            <span className="info-label">Spendable</span>
            <span className="value">{fmtTsar(data?.spendable)}</span>
          </div>
          <div className="stat">
            <span className="info-label">Immature</span>
            <span className="value">{fmtTsar(data?.immature)}</span>
          </div>
        </div>
        <div className="grid">
          <div className="stat">
            <span className="info-label">Outgoing</span>
            <span className="value">{fmtTsar(data?.outgoing)}</span>
          </div>
          <div className="stat">
            <span className="info-label">Incoming</span>
            <span className="value">{fmtTsar(data?.incoming)}</span>
          </div>
          <div className="stat">
            <span className="info-label">UTXO Set</span>
            <span className="value">{data?.utxo_count || 0}</span>
          </div>
          <div className="stat">
            <span className="info-label">Total Transactions</span>
            <span className="value">{data?.total_txs || 0}</span>
          </div>
        </div>
        <div className="divider2" />
        <div className="stat">
          <span className="value">
            Recent Activity: {totalItems} transactions 
            {totalPages > 1 && ` (Page ${currentPage} of ${totalPages})`}
          </span>
        </div>
        <div className="list">
          {currentHistory.map((h, idx) => {
            const statusBadge = getStatusBadge(h.status);
            const directionBadge = getDirectionBadge(h.direction);
            const height = h.height;
            const confirmations = h.confirmations;
            
            return (
              <div className="tx-item" key={h.txid || h.id || idx}>
                <div className="tx-items">
                  <div className="stat">
                    <span className="value">{fmtDateLong(h.timestamp)}</span>
                      {renderClickableHash(
                        h.txid,
                        onSearchClick,
                        h.txid,
                        fmtTxid(h.txid) || "-"
                      )}
                      {/* From/To Address */}
                      <div className="tx-address-row">
                        {renderAddressLabel(h.direction, h.from, h.to)}
                      </div>
                    <div className="tx-meta">
                      <span 
                        className="direction-badge" 
                        style={{ backgroundColor: directionBadge.color }}
                      >
                        {directionBadge.label}
                      </span>
                      <span 
                        className="status-badge" 
                        style={{ backgroundColor: statusBadge.color }}
                      >
                        {statusBadge.label}
                      </span>
                      {height ? (
                        <span className="tx-height">Block {height}</span>
                      ) : null}
                      {confirmations > 0 ? (
                        <span className="tx-confirms">{confirmations} Confirms</span>
                      ) : null}
                    </div>
                    <div className="tx-meta">
                      <span className="value">{timeAgo(h.timestamp)}</span>
                    </div>
                  </div>
                  <div className="stat">
                    <div style={{
                      flex: 1,
                      textAlign: 'right',
                      fontSize: '12px',
                      color: directionBadge.type === "incoming" ? "#38b36b" : 
                        directionBadge.type === "outgoing" ? "#d1495b" : "#8b8b8b"
                    }}>
                      {directionBadge.type === "outgoing" ? "-" : "+"}
                      {fmtTsar(h.amount || h.value || 0)}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
        
        {/* Pagination Controls */}
        {totalPages > 1 && (
          <div className="pagination-container">
            <button 
              onClick={() => handlePageChange(currentPage - 1)}
              disabled={currentPage === 1}
              className="pagination-btn"
            >
              &lt;
            </button>
            
            {getPageNumbers().map((pageNum, idx) => (
              pageNum === '...' ? (
                <span key={`ellipsis-${idx}`} className="pagination-ellipsis">...</span>
              ) : (
                <button
                  key={`page-${pageNum}`}
                  onClick={() => handlePageChange(pageNum)}
                  className={`pagination-btn ${currentPage === pageNum ? 'active' : ''}`}
                >
                  {pageNum}
                </button>
              )
            ))}
            
            <button 
              onClick={() => handlePageChange(currentPage + 1)}
              disabled={currentPage === totalPages}
              className="pagination-btn"
            >
              &gt;
            </button>
          </div>
        )}
      </div>
    </>
  );
};

export { ResultAddress };