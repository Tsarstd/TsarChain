import { useState, useEffect } from "react";
import { ClickableValue } from ".././SearchResults";
import { fmtTsar } from "../../../utils/format";
import { getStatusBadge, getDirectionBadge } from "../SearchUX";

const ResultAddress = ({ data, onSearchClick }) => {
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(10);
  
  useEffect(() => {
    setCurrentPage(1);
  }, [data?.address]);
  
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

  return (
    <div className="card">
      <span className="address-details">{data?.address ?? "-"}</span>
      <div className="divider" />
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
          <span className="value">{data?.utxos?.length || 0}</span>
        </div>
      </div>
      <div className="divider2" />
      <div className="stat">
        <span className="value">
          Recent Activity: {totalItems} transactions 
          {totalPages > 1 && ` (Page ${currentPage} of ${totalPages})`}
        </span>
      </div>
      <div className="card-list">
        {currentHistory.map((h, idx) => {
          const statusBadge = getStatusBadge(h.status);
          const directionBadge = getDirectionBadge(h.direction);
          const height = h.height;
          const confirmations = h.confirmations;
          
          return (
            <div className="tx-items" key={h.txid || h.id || idx}>
              <div className="tx-info">
                <div className="tx-info">
                  <ClickableValue value={h.txid || h.id || "-"} onSearchClick={onSearchClick} className="value muted">
                    {h.txid || h.id || "-"}
                  </ClickableValue>
                </div>
                <div className="tx-meta">
                  {height ? (
                    <span className="tx-height">Block {height}</span>
                  ) : null}
                  {confirmations > 0 ? (
                    <span className="tx-confirms">{confirmations} Confirms</span>
                  ) : null}
                </div>
              </div>
              
              <div className="tx-amount" style={{ 
                color: directionBadge.type === "incoming" ? "#38b36b" : 
                        directionBadge.type === "outgoing" ? "#d1495b" : "#8b8b8b"
              }}>
                {directionBadge.type === "outgoing" ? "-" : "+"}
                {fmtTsar(h.amount || h.value || 0)}
              </div>
              
              <div className="tx-badges">
                <span 
                  className="status-badge" 
                  style={{ backgroundColor: statusBadge.color }}
                >
                  {statusBadge.label}
                </span>
                <span 
                  className="direction-badge" 
                  style={{ backgroundColor: directionBadge.color }}
                >
                  {directionBadge.label}
                </span>
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
  );
};

export { ResultAddress };