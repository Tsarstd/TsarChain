import PropTypes from "prop-types";
import { FaCopy } from "react-icons/fa";
import { useState, useEffect } from "react";
import { getStatusBadge, getDirectionBadge } from "../SearchUX";
import { useRenderHelpers, copyToClipboard } from "../SearchHelpers";
import {  
  fmtAddress,
  fmtTimestamp,
  fmtTsar, 
  fmtTxid,
  timeAgo
} from "../../../utils/format"

const ResultAddress = ({ data, onSearchClick }) => {
  const { renderClickableHash } = useRenderHelpers();
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(10);
  const [copyStatus, setCopyStatus] = useState("");

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
    } else if (currentPage <= 3) {
      for (let i = 1; i <= 4; i++) {
        pageNumbers.push(i);
      }
      pageNumbers.push('...1', totalPages);
    } else if (currentPage >= totalPages - 2) {
      pageNumbers.push(1, '...2');
      for (let i = totalPages - 3; i <= totalPages; i++) {
        pageNumbers.push(i);
      }
    } else {
      pageNumbers.push(1, '...3', currentPage - 1, currentPage, currentPage + 1, '...4', totalPages);
    }
    
    return pageNumbers;
  };

  const renderAddressLabel = (direction, fromAddress, toAddress) => {
    if (direction === 'in') {
      if (fromAddress === 'coinbase') {
        return <span className="tx-address-label">From : Coinbase</span>;
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

  const splitAddressGrid = (address) => {
    if (!address) return [];
    
    const len = address.length;
    if (len !== 44 && len !== 64) return [];
    
    const rows = [];
    
    rows.push(address.substring(0, 4).split(''));
    
    for (let start = 4; start < len; start += 20) {
      const row = [];
      for (let i = start; i < Math.min(start + 20, len); i += 5) {
        row.push(address.substring(i, i + 5));
      }
      rows.push(row);
    }
    
    if (len === 44) {
      rows.push(["Citizen Address", "P2WPKH"]);
    } else {
      rows.push(["Pool Address", "P2WSH"]);
    }
    
    return rows;
  };

  const getHighlightPositions = (addressLength) => {
    if (addressLength === 44) { // P2WPKH
      return [
        [1, 0], [1, 2], // Baris 2, kolom 0 dan 2
        [2, 1], [2, 3]  // Baris 3, kolom 1 dan 3
      ];
    } else if (addressLength === 64) { // P2WSH
      return [
        [1, 0], [1, 2], // Baris 2, kolom 0 dan 2
        [2, 1], [2, 3], // Baris 3, kolom 1 dan 3
        [3, 0], [3, 2]  // Baris 4, kolom 0 dan 2
      ];
    }
    return [];
  };

  const renderAddressGrid = (address) => {
    if (!address) return <span>-</span>;
    
    const grid = splitAddressGrid(address);
    if (grid.length === 0) {
      return <span className="value wrap">{address}</span>;
    }

    const isP2WPKH = address.length === 44;
    const isP2WSH = address.length === 64;
    const highlightPositions = getHighlightPositions(address.length);
    const isHighlighted = (r, c) => highlightPositions.some(pos => pos[0] === r && pos[1] === c);

    const renderChunk = (cell, shouldHighlight, cellKey) => {
      const chars = cell.split('');
      const charElements = [];
      for (let i = 0; i < chars.length; i++) {
        charElements.push(<div key={`c-${i}`} className="address-chunk-char">{chars[i]}</div>);
      }
      return (
        <div key={cellKey} className="address-cell">
          <div className={`address-chunk-container ${shouldHighlight ? 'highlighted' : ''}`}>
            <div className="address-chunk-grid">{charElements}</div>
          </div>
        </div>
      );
    };

    const rows = [];
    for (let rIdx = 0; rIdx < grid.length; rIdx++) {
      const row = grid[rIdx];
      const rowKey = `row-${rIdx}`;
      const isLabelRow = (isP2WPKH && rIdx === 3) || (isP2WSH && rIdx === 4);
      
      if (isLabelRow) {
        const labelClass = isP2WPKH ? "address-label-p2wpkh" : "address-label-p2wsh";
        rows.push(
          <div key={rowKey} className="address-row">
            <div className="address-cell">
              <div className={labelClass}><span className="address-label">{row[0]}</span></div>
            </div>
            <div className="address-cell">
              <div className={labelClass}><span className="address-label">{row[1]}</span></div>
            </div>
          </div>
        );
        continue;
      }
      
      const isSingleCharRow = rIdx === 0;
      const cells = [];
      for (let cIdx = 0; cIdx < row.length; cIdx++) {
        const cell = row[cIdx];
        const cellKey = `cell-${rIdx}-${cIdx}`;
        if (isSingleCharRow) {
          cells.push(
            <div key={cellKey} className="address-cell">
              <div className="address-char-container"><span className="address-char">{cell}</span></div>
            </div>
          );
        } else {
          cells.push(renderChunk(cell, isHighlighted(rIdx, cIdx), cellKey));
        }
      }
      rows.push(<div key={rowKey} className="address-row">{cells}</div>);
    }
    return <div className="address-container">{rows}</div>;
  };

  return (
    <>
      {/* HEADER SECTION */}
      <div style={{ 
        display: 'flex', 
        flexDirection: 'column',
        alignItems: 'center',
        marginBottom: '20px',
        width: '100%'
      }}>
        {/* ADDRESS */}
        <h1 className="stat"> Address Info
        </h1>
        <h1 className="address-details">
          {renderAddressGrid(data?.address)}
          <div className="divider2" />
        </h1>
        
        {/* BUTTONS CONTAINER - CENTERED */}
        <div className="action-buttons">
          {/* COPY ADDRESS BUTTON */}
          <button
            onClick={() => copyToClipboard(data.address, setCopyStatus)}
            className={`action-button copy-button`}
          >
            <span><FaCopy /></span>
            {copyStatus || "Copy"}
          </button>
        </div>
      </div>

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
            
            let directionColor = "#8b8b8b";
            if (directionBadge.type === "incoming") directionColor = "#38b36b";
            else if (directionBadge.type === "outgoing") directionColor = "#d1495b";
            
            return (
              <div className="tx-item" key={h.txid || h.id || idx}>
                <div className="tx-items">
                  <div className="stat">
                    <span className="value">{fmtTimestamp(h.timestamp)}</span>
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
                      color: directionColor
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
            
            {getPageNumbers().map((pageNum) => (
              String(pageNum).startsWith('...') ? (
                <span key={pageNum} className="pagination-ellipsis">...</span>
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

ResultAddress.propTypes = {
  data: PropTypes.shape({
    address: PropTypes.string,
    balance: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    spendable: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    immature: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    incoming: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    outgoing: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    utxo_count: PropTypes.number,
    total_txs: PropTypes.number,
    history: PropTypes.arrayOf(
      PropTypes.shape({
        txid: PropTypes.string,
        timestamp: PropTypes.number,
        height: PropTypes.number,
        confirmations: PropTypes.number,
        direction: PropTypes.string,
        from: PropTypes.string,
        to: PropTypes.string,
        amount: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
        value: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
        status: PropTypes.string,
      })
    ),
  }),
  onSearchClick: PropTypes.func.isRequired,
};

export { ResultAddress };