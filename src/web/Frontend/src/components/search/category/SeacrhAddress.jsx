import PropTypes from "prop-types";
import { FaCopy, FaDownload } from "react-icons/fa";
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


const AddressHeaderCell = ({ val, cellKey }) => {
  return (
    <div key={cellKey} className="address-cell">
      <div className="address-char-container">
        <span className="address-char">{val}</span>
      </div>
    </div>
  );
};

AddressHeaderCell.propTypes = {
  val: PropTypes.string.isRequired,
  cellKey: PropTypes.string.isRequired,
};

const AddressChunk = ({ cell, shouldHighlight, cellKey }) => {
  return (
    <div key={cellKey} className="address-cell">
      <div className={`address-chunk-container ${shouldHighlight ? 'highlighted' : ''}`}>
        <div className="address-chunk-grid">
          {cell.chars.map((charObj) => (
            <div key={charObj.id} className="address-chunk-char">{charObj.val}</div>
          ))}
        </div>
      </div>
    </div>
  );
};

AddressChunk.propTypes = {
  cell: PropTypes.object.isRequired,
  shouldHighlight: PropTypes.bool.isRequired,
  cellKey: PropTypes.string.isRequired,
};


const ResultAddress = ({ data, onSearchClick }) => {
  const { renderClickableHash } = useRenderHelpers();
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(10);
  const [copyStatus, setCopyStatus] = useState("");
  const [isDownloading, setIsDownloading] = useState(false);

  const handleDownloadHistory = async () => {
    setIsDownloading(true);
    try {
      const response = await fetch(`/api/history_book?address=${data.address}`);
      const resData = await response.json();
      
      if (resData.status === "ok" && resData.data?.data_url) {
        const link = document.createElement("a");
        link.href = resData.data.data_url;
        link.download = resData.data.filename || `history_${data.address.substring(0, 16)}.pdf`;
        document.body.appendChild(link);
        link.click();
        link.remove();
      } else {
        alert(resData.data?.message || resData.error || "Failed to download history book.");
      }
    } catch (error) {
      console.error("Error downloading history book:", error);
      alert("Error downloading history book.");
    } finally {
      setIsDownloading(false);
    }
  };

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
    const isFromCoinbase = (fromAddress || "").toLowerCase() === "coinbase";
    const isToCoinbase = (toAddress || "").toLowerCase() === "coinbase";

    if (direction === 'in') {
      if (isFromCoinbase) {
        return <span className="tx-address-label">From : Coinbase</span>;
      } else {
        return (
          <>
            <span className="tx-address-label">From : </span>
            {renderClickableHash(
              fromAddress,
              onSearchClick,
              fromAddress,
              fmtAddress(fromAddress),
              true
            )}
          </>
        );
      }
    } else if (direction === 'out') {
      if (isToCoinbase) {
        return <span className="tx-address-label">To : Coinbase</span>;
      } else {
        return (
          <>
            <span className="tx-address-label">To : </span>
            {renderClickableHash(
              toAddress,
              onSearchClick,
              toAddress,
              fmtAddress(toAddress),
              true
            )}
          </>
        );
      }
    }
    return null;
  };

  const splitAddressGrid = (address) => {
    if (!address) return null;
    
    const len = address.length;
    if (len !== 44 && len !== 64) return null;
    
    const headerChars = address.substring(0, 4).split('').map((char, charIdx) => ({
      id: `header-char-${charIdx}`,
      val: char
    }));

    const bodyRows = [];
    let rowIndex = 1;
    for (let start = 4; start < len; start += 20) {
      const cells = [];
      let colIndex = 0;
      for (let i = start; i < Math.min(start + 20, len); i += 5) {
        const chunkVal = address.substring(i, i + 5);
        cells.push({
          id: `cell-${rowIndex}-${colIndex}`,
          rIdx: rowIndex,
          cIdx: colIndex,
          val: chunkVal,
          chars: chunkVal.split('').map((char, charIdx) => ({
            id: `cell-char-${rowIndex}-${colIndex}-${charIdx}`,
            val: char
          }))
        });
        colIndex++;
      }
      bodyRows.push({
        id: `row-${rowIndex}`,
        rIdx: rowIndex,
        cells
      });
      rowIndex++;
    }
    
    const isP2WPKH = len === 44;
    const addressType = isP2WPKH ? "P2WPKH" : "P2WSH";
    const labelType = isP2WPKH ? "Citizen Address" : "Pool Address";
    const badgeText = `${labelType} (${addressType})`;
    
    return {
      headerChars,
      bodyRows,
      isP2WPKH,
      badgeText,
      labelClass: isP2WPKH ? "address-label-p2wpkh" : "address-label-p2wsh"
    };
  };

  const getHighlightPositions = (addressLength) => {
    if (addressLength === 44) { // P2WPKH
      return [
        [1, 0], [1, 2], // Row 1, col 0 and 2
        [2, 1], [2, 3]  // Row 2, col 1 and 3
      ];
    } else if (addressLength === 64) { // P2WSH
      return [
        [1, 0], [1, 2], // Row 1, col 0 and 2
        [2, 1], [2, 3], // Row 2, col 1 and 3
        [3, 0], [3, 2]  // Row 3, col 0 and 2
      ];
    }
    return [];
  };

  const renderAddressGrid = (address) => {
    if (!address) return <span>-</span>;
    
    const gridData = splitAddressGrid(address);
    if (!gridData) {
      return <span className="value wrap">{address}</span>;
    }

    const { headerChars, bodyRows, badgeText, labelClass } = gridData;
    const highlightPositions = getHighlightPositions(address.length);
    const isHighlighted = (r, c) => highlightPositions.some(pos => pos[0] === r && pos[1] === c);

    return (
      <div className="address-grid-wrapper">
        <div className="address-container">
          {/* Row 0 Header ("tsar") */}
          <div className="address-row">
            {headerChars.map((charObj) => (
              <AddressHeaderCell key={charObj.id} val={charObj.val} cellKey={charObj.id} />
            ))}
          </div>
          {/* Body Rows */}
          {bodyRows.map((row) => (
            <div key={row.id} className="address-row">
              {row.cells.map((cell) => (
                <AddressChunk
                  key={cell.id}
                  cell={cell}
                  shouldHighlight={isHighlighted(row.rIdx, cell.cIdx)}
                  cellKey={cell.id}
                />
              ))}
            </div>
          ))}
        </div>
        {/* Centered Badge Row */}
        <div className="address-badge-row">
          <div className={labelClass}>
            <span className="address-label">{badgeText}</span>
          </div>
        </div>
      </div>
    );
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

          <button
            onClick={handleDownloadHistory}
            disabled={isDownloading}
            className={`action-button receipt-button ${isDownloading ? 'disabled' : ''}`}
            style={{ marginLeft: '10px' }}
          >
            <span><FaDownload /></span>
            {isDownloading ? "Generating..." : "Download Book"}
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