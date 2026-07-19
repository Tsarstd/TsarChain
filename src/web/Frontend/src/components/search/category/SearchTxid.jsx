import { useMemo, useState, useEffect } from "react";
import { useRenderHelpers, copyToClipboard } from "../SearchHelpers";
import PropTypes from "prop-types";
import { saveAs } from 'file-saver';
import { IoReceiptSharp } from "react-icons/io5";
import { FaCopy } from "react-icons/fa";

import {  
  fmtTsar, 
  fmtAddress,
  fmtTxid,
  fmtTimestamp
} from "../../../utils/format"

import { getVoutLabel, getAddressType } from "../SearchUX";


const TxidGridCell = ({ cell, isHighlightedCell }) => {
  const isLastRow = cell.row === 3;
  
  if (isLastRow) {
    return (
      <div className="txid-cell">
        <div className={`txid-single-char-container ${isHighlightedCell ? 'highlighted' : ''}`}>
          <span className="txid-single-char">
            {cell.value}
          </span>
        </div>
      </div>
    );
  }
  
  const chars = Array.from(cell.value).map((char, i) => ({
    id: `char-${cell.id}-${i}`,
    val: char
  }));

  return (
    <div className="txid-cell">
      <div className={`txid-chunk-container ${isHighlightedCell ? 'highlighted' : ''}`}>
        <div className="txid-chunk-grid">
          {chars.map((c) => (
            <div key={c.id} className="txid-chunk-char">
              {c.val}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

TxidGridCell.propTypes = {
  cell: PropTypes.shape({
    id: PropTypes.string.isRequired,
    value: PropTypes.string.isRequired,
    row: PropTypes.number.isRequired,
    col: PropTypes.number.isRequired,
  }).isRequired,
  isHighlightedCell: PropTypes.bool.isRequired,
};

const TxidGridRow = ({ row, highlightPositions }) => {
  const isHighlighted = (rowIdx, colIdx) => {
    return highlightPositions.some(pos => pos[0] === rowIdx && pos[1] === colIdx);
  };

  return (
    <div className="txid-row">
      {row.cells.map((cell) => (
        <TxidGridCell
          key={cell.id}
          cell={cell}
          isHighlightedCell={isHighlighted(cell.row, cell.col)}
        />
      ))}
    </div>
  );
};

TxidGridRow.propTypes = {
  row: PropTypes.shape({
    id: PropTypes.string.isRequired,
    cells: PropTypes.array.isRequired,
  }).isRequired,
  highlightPositions: PropTypes.array.isRequired,
};

const ResultTx = ({ data, onSearchClick }) => {
  const { renderClickableHash } = useRenderHelpers();
  const [isGeneratingReceipt, setIsGeneratingReceipt] = useState(false);
  const [copyStatus, setCopyStatus] = useState("");

  const blockDisplay = useMemo(() => {
    if (!data?.block_height && data?.block_height !== 0) {
      return "0";
    }
    if (data?.block_height === "-") {
      return "Genesis (0)";
    }
    return data?.block_height;
  }, [data?.block_height]);

  const downloadReceiptDirect = async () => {
    if (!data?.txid) return;
    
    setIsGeneratingReceipt(true);
    
    try {
      const response = await fetch(`/api/receipt?txid=${data.txid}`);
      const result = await response.json();
      
      if (response.ok && result.status === "ok") {
        const dataUrl = result.data.data_url;
        const base64Response = await fetch(dataUrl);
        const blob = await base64Response.blob();
        
        saveAs(blob, `${data.txid}.jpg`);
      } else {
        throw new Error(result.message || 'Failed to generate receipt');
      }
    } catch (error) {
      console.error('Error:', error);
      alert('Failed to download receipt: ' + error.message);
    } finally {
      setIsGeneratingReceipt(false);
    }
  };

  const groupedInputs = useMemo(() => {
    if (!data?.inputs) return [];
    
    const groups = {};
    data.inputs.forEach((inp, inpIdx) => {
      const address = inp.address || 'Unknown';
      if (!groups[address]) {
        groups[address] = {
          address,
          addressType: getAddressType(address),
          utxos: []
        };
      }
      groups[address].utxos.push({
        key: `utxo-${inp.txid || 'coinbase'}-${inpIdx}`,
        txid: inp.txid,
        amount: inp.amount,
        isCoinbase: inp.is_coinbase
      });
    });
    
    return Object.values(groups);
  }, [data?.inputs]);

  const fmtEventType = (eventType) => {
    if (!eventType) return "";
    
    const eventMap = {
      'POST': 'Post',
      'COMMENT': 'Comment', 
      'PAYOUT': 'Payout'
    };
    
    return eventMap[eventType] || eventType;
  };

  // GROUP OUTPUTS BY ADDRESS
  const groupedOutputs = useMemo(() => {
    if (!data?.outputs) return [];
    
    const groups = {};
    const inputAddresses = new Set(data.inputs?.map(inp => inp.address) || []);
    
    data.outputs.forEach((out, idx) => {
      const vout = out?.index ?? idx;
      const address = out?.address || 'OP_RETURN';
      const isOP_RETURN = address === 'OP_RETURN' || address === null;
      const isChange = !isOP_RETURN && inputAddresses.has(address);
      const hasEvent = out?.event !== null && out?.event !== undefined;
      const groupKey = isOP_RETURN ? 'OP_RETURN' : address;
      
      if (!groups[groupKey]) {
        const addressType = isOP_RETURN 
          ? { 
              type: "opreturn", 
              label: "Graffiti"
            }
          : getAddressType(address);
        
        let roleLabel = "Recipient";
        if (isOP_RETURN) {
          roleLabel = "Script";
        } else if (isChange) {
          roleLabel = "Change";
        }
        
        groups[groupKey] = {
          address: groupKey,
          addressType,
          isChange,
          isOP_RETURN,
          hasEvent: false,
          eventType: null,
          outputs: [],
          roleLabel
        };
      }
      
      groups[groupKey].outputs.push({
        vout,
        amount: out.amount,
        voutLabel: getVoutLabel(vout),
        event: out.event
      });
      
      if (hasEvent) {
        groups[groupKey].hasEvent = true;
        groups[groupKey].eventType = out.event;
      }
    });
    
    return Object.values(groups);
  }, [data?.outputs, data?.inputs]);

  useEffect(() => {
    console.log('Data dari backend:', data);
    console.log('Outputs dengan event:', data?.outputs?.filter(out => out.event));
    console.log('Grouped outputs akhir:', groupedOutputs);
    }, [data, groupedOutputs]);

  // COUNT UNIQUE RECIPIENTS
  const recipientCount = useMemo(() => {
    if (!groupedOutputs.length) return 0;
    
    const inputAddresses = new Set(data.inputs?.map(inp => inp.address) || []);
    
    return groupedOutputs.filter(group => {
      return group.address !== 'OP_RETURN' && !inputAddresses.has(group.address);
    }).length;
  }, [groupedOutputs, data?.inputs]);

  const splitTxidGrid = (txid) => {
    if (txid?.length !== 64) return [];
    
    const grid = [];
    // Row 0, 1, 2
    for (let r = 0; r < 3; r++) {
      const row = [];
      for (let c = 0; c < 4; c++) {
        const i = (r * 4 + c) * 5;
        row.push({
          id: `cell-${r}-${c}`,
          value: txid.substring(i, i + 5),
          row: r,
          col: c
        });
      }
      grid.push({
        id: `row-${r}`,
        cells: row
      });
    }
    
    // Row 3 (last 4 characters)
    const lastRow = [];
    const lastFour = txid.substring(60).split('');
    lastFour.forEach((char, c) => {
      lastRow.push({
        id: `cell-3-${c}`,
        value: char,
        row: 3,
        col: c
      });
    });
    grid.push({
      id: `row-3`,
      cells: lastRow
    });
    
    return grid;
  };

  const highlightPositions = [
    [0, 0], [0, 2], // Row 1, Column 1 & 3
    [1, 1], [1, 3], // Row 2, Column 2 & 4
    [2, 0], [2, 2], // Row 3, Column 1 & 3
    [3, 0]          // Row 4, Column 1
  ];

  const renderTxidGrid = (txid) => {
    if (!txid) return <span>-</span>;
    
    const grid = splitTxidGrid(txid);
    
    return (
      <div className="txid-container">
        {grid.map((row) => (
          <TxidGridRow
            key={row.id}
            row={row}
            highlightPositions={highlightPositions}
          />
        ))}
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
        marginBottom: '15px',
        width: '100%'
      }}>
        {/* TXID */}
        <h1 className="stat"> Transaction ID
        </h1>
        <h1 className="txid-details">
          {renderTxidGrid(data?.txid)}
          <div className="divider2" />
        </h1>
        {/* BUTTONS CONTAINER - CENTERED */}
        <div className="action-buttons">
          {/* DOWNLOAD RECEIPT BUTTON */}
          <button
            onClick={downloadReceiptDirect}
            disabled={isGeneratingReceipt}
            className={`action-button receipt-button ${isGeneratingReceipt ? 'disabled' : ''}`}
          >
            {isGeneratingReceipt ? (
              <>
                <span className="spinner"></span>
                {' '}Generating...
              </>
            ) : (
              <>
                <span><IoReceiptSharp /></span>
                {' '}Download Receipt
              </>
            )}
          </button>
          
          {/* COPY TXID BUTTON */}
          <button
            onClick={() => copyToClipboard(data.txid, setCopyStatus)}
            className={`action-button copy-button`}
          >
            <span><FaCopy /></span>
            {copyStatus || "Copy"}
          </button>
        </div>
      </div>
      
      <div className="divider" />
      
      {/* START OF TX INFO */}
      <div className="card">
        <div className="grid">
          <div className="stat">
            <span className="info-label">Status</span>
            <span className="value">{data?.status || "-"}</span>
          </div>
          <div className="stat">
            <span className="info-label">Block</span>
            <span className="value">{blockDisplay}</span>
          </div>
          <div className="stat">
            <span className="info-label">Timestamp</span>
            <span className="value">{fmtTimestamp(data?.timestamp ?? 0)}</span>
          </div>
          <div className="stat">
            <span className="info-label">Confirmations</span>
            <span className="value">{data?.confirmations ?? 0}</span>
          </div>
          <div className="stat">
            <span className="info-label">Fee</span>
            <span className="value">{fmtTsar(data?.fee || 0)}</span>
          </div>
          <div className="stat">
            <span className="info-label">Coinbase</span>
            <span className="value">{data?.is_coinbase ? "Yes" : "No"}</span>
          </div>
        </div>
        <div className="divider2" />

        {/* END OF TX INFO */}

        {/* START OF TX INPUTS */}

        <div style={{ display: 'flex' }}>
          <div className="stat">
            <span className="inputs-label">
              {data?.inputs?.length || 0} Inputs • {groupedInputs.length} Sender
            </span>
          </div>
        </div>
        
        <div className="list">
          {groupedInputs.map((group) => (
            <div className="tx-item" key={group.address}>
              
              {/* Sender Row */}
              <div className="stat">
                <span className="info-label">Sender</span>
                <div style={{ 
                  display: 'flex', 
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  width: '100%',
                  flexWrap: 'wrap',
                  gap: '8px',
                  marginTop: '4px'
                }}>
                  <div style={{ 
                    flex: 1, 
                    minWidth: '150px',
                    textOverflow: 'ellipsis'
                  }}>
                    {renderClickableHash(
                      group.address,
                      onSearchClick,
                      group.address,
                      fmtAddress(group.address) || "-"
                    )}
                  </div>
                  
                  {group.addressType && (
                    <div style={{ 
                      display: 'flex', 
                      alignItems: 'center', 
                      flexShrink: 0
                    }}>
                      <span className={`addr-badge addr-${group.addressType.type}`}>
                        {group.addressType.label}
                      </span>
                      <span className={`addr-badge addr-type-${group.addressType.type}`}>
                        {group.addressType.type}
                      </span>
                    </div>
                  )}
                </div>
              </div>
              <div className="divider" />
              
              {/* UTXOs List */}
              <div className="stat">
                <span className="info-label" style={{ marginBottom: '4px' }}>
                  Used {group.utxos.length} UTXO{group.utxos.length === 1 ? '' : '`s'}
                </span>
                {group.utxos.map((utxo) => (
                  <div key={utxo.key} className="tx-items">
                    <div style={{ 
                      display: 'flex', 
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      width: '100%'
                    }}>
                      <div style={{ flex: 1, marginRight: '12px' }}>
                        {renderClickableHash(
                          utxo.txid ? `${utxo.txid}` : "-",
                          onSearchClick,
                          utxo.txid ? `${utxo.txid}` : "-",
                          fmtTxid(utxo.txid ? `${utxo.txid}` : "-") || "-"
                        )}
                      </div>
                      <div style={{
                        flex: 1,
                        textAlign: 'right',
                        fontSize: '12.5px',
                        color: '#ffffff'
                      }}>
                        {fmtTsar(utxo.amount)}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
        
        {groupedInputs.length === 0 && (
          <div className="result-empty" style={{ padding: '12px', textAlign: 'center' }}>
            ⚠️ This Is a Coinbase Transaction, No Input ⚠️
          </div>
        )}
        
        <div className="divider2" />

        {/* END OF TX INPUTS */}

        {/* START OF TX OUTPUTS */}

        <div style={{ display: 'flex' }}>
          <div className="stat">
            <span className="outputs-label">
              {data?.outputs?.length || 0} Outputs • {recipientCount} Recipient{recipientCount === 1 ? '' : 's'}
            </span>
          </div>
        </div>
        
        <div className="list">
          {groupedOutputs.map((group) => (
            <div className="tx-item" key={group.address}>

              {/* Recipient Row */}
              <div className="stat">
                <span className="info-label">
                  {group.roleLabel}
                </span>
                <div style={{ 
                  display: 'flex', 
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  width: '100%',
                  flexWrap: 'wrap',
                  gap: '8px',
                  marginTop: '4px'
                }}>
                  <div style={{ 
                    flex: 1, 
                    minWidth: '150px',
                    textOverflow: 'ellipsis'
                  }}>
                    {group.isOP_RETURN ? (
                      <span className="value muted">OP_RETURN</span>
                    ) : (
                      renderClickableHash(
                        group.address,
                        onSearchClick,
                        group.address,
                        fmtAddress(group.address) || "-"
                      )
                    )}
                  </div>
                  {group.addressType && (
                    <div style={{ 
                      display: 'flex', 
                      alignItems: 'center', 
                      flexShrink: 0,
                    }}>
                      <span className={`addr-badge addr-${group.addressType.type}`}>
                        {group.addressType.label}
                      </span>
                      
                      {group.hasEvent && group.eventType && (
                        <span className={`event-badge event-${group.eventType.toLowerCase()}`}>
                          {fmtEventType(group.eventType)}
                        </span>
                      )}
                      
                      {!group.isOP_RETURN && (
                        <span className={`addr-badge addr-type-${group.addressType.type}`}>
                          {group.addressType.type}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>
              
              {/* Outputs List */}
              <div className="stat">
                <div className="tx-items">
                  {group.outputs.map((output) => (
                    <div key={output.vout} style={{ 
                      display: 'flex', 
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      width: '100%'
                    }}>
                      <div style={{ 
                        display: 'flex', 
                        alignItems: 'center',
                        gap: '8px'
                      }}>
                        <div className="tx-vout">
                          <span className={`vout-badge vout-${output.vout}`}>
                            {output.voutLabel}
                          </span>
                        </div>
                      </div>
                      <div style={{ flex: 1, textAlign: 'right', color: '#ffffff' }}>
                        <span className="value muted">{fmtTsar(output.amount)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
        
        {groupedOutputs.length === 0 && (
          <div className="result-empty" style={{ padding: '12px', textAlign: 'center' }}>
            No outputs found
          </div>
        )}

        {/* END OF TX OUTPUTS */}

      </div>
    </>
  );
};

ResultTx.propTypes = {
  data: PropTypes.shape({
    txid: PropTypes.string,
    inputs: PropTypes.arrayOf(
      PropTypes.shape({
        address: PropTypes.string,
        txid: PropTypes.string,
        amount: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
        is_coinbase: PropTypes.bool,
      })
    ),
    outputs: PropTypes.arrayOf(
      PropTypes.shape({
        address: PropTypes.string,
        amount: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
        index: PropTypes.number,
        event: PropTypes.string,
      })
    ),
    status: PropTypes.string,
    block_height: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    timestamp: PropTypes.number,
    confirmations: PropTypes.number,
    fee: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    is_coinbase: PropTypes.bool,
  }),
  onSearchClick: PropTypes.func.isRequired,
};

export { ResultTx }