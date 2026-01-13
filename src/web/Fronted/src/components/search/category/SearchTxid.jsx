import { ClickableValue } from ".././SearchResults";
import { useState, useEffect, useMemo } from "react";

import {  
  fmtTsar, 
  fmtAddress,
  fmtTxid,
  formatHashForDisplay,
  getMaxCharsPerLine 
} from "../../../utils/format"
import { getVoutLabel, getAddressType } from "../SearchUX";



const ResultTx = ({ data, onSearchClick }) => {
  const [isMobile, setIsMobile] = useState(false);
  const [maxCharsPerLine, setMaxCharsPerLine] = useState(getMaxCharsPerLine());

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

  const groupedInputs = useMemo(() => {
    if (!data?.inputs) return [];
    
    const groups = {};
    data.inputs.forEach((inp) => {
      const address = inp.address || 'Unknown';
      if (!groups[address]) {
        groups[address] = {
          address,
          addressType: getAddressType(address),
          utxos: []
        };
      }
      groups[address].utxos.push({
        txid: inp.txid,
        amount: inp.amount,
        isCoinbase: inp.is_coinbase
      });
    });
    
    return Object.values(groups);
  }, [data?.inputs]);

  // GROUP OUTPUTS BY ADDRESS
  const groupedOutputs = useMemo(() => {
    if (!data?.outputs) return [];
    
    const groups = {};
    const inputAddresses = new Set(data.inputs?.map(inp => inp.address) || []);
    
    data.outputs.forEach((out, idx) => {
      const vout = typeof out?.vout === "number" ? out.vout : idx;
      const address = out?.address || 'OP_RETURN';
      const isOP_RETURN = address === 'OP_RETURN';
      const isChange = !isOP_RETURN && inputAddresses.has(address);
      
      if (!groups[address]) {
        const addressType = !isOP_RETURN 
          ? getAddressType(address)
          : { type: "opreturn", label: "Graffiti" };
        
        groups[address] = {
          address,
          addressType,
          isChange,
          isOP_RETURN,
          outputs: []
        };
      }
      
      groups[address].outputs.push({
        vout,
        amount: out.amount,
        voutLabel: getVoutLabel(vout)
      });
    });
    
    return Object.values(groups);
  }, [data?.outputs, data?.inputs]);

  // COUNT UNIQUE RECIPIENTS
  const recipientCount = useMemo(() => {
    if (!groupedOutputs.length) return 0;
    
    const inputAddresses = new Set(data.inputs?.map(inp => inp.address) || []);
    
    return groupedOutputs.filter(group => {
      return group.address !== 'OP_RETURN' && !inputAddresses.has(group.address);
    }).length;
  }, [groupedOutputs, data?.inputs]);

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




  return (
    <>
      <h1 className="txid-details">{renderHash(data?.txid, "wrap")}</h1>
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
            <span className="value">
              {!data?.block_height && data?.block_height !== 0 ? "0" : 
              data?.block_height === "-" ? "Genesis (0)" :
              data?.block_height}
            </span>
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
          {groupedInputs.map((group, groupIdx) => (
            <div className="tx-item" key={groupIdx}>
              
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
                  Used {group.utxos.length} UTXO{group.utxos.length !== 1 ? '`s' : ''}
                </span>
                {group.utxos.map((utxo, idx) => (
                  <div key={idx} className="tx-items">
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
              {data?.outputs?.length || 0} Outputs • {recipientCount} Recipient{recipientCount !== 1 ? 's' : ''}
            </span>
          </div>
        </div>
        
        <div className="list">
          {groupedOutputs.map((group, groupIdx) => (
            <div className="tx-item" key={groupIdx}>

              {/* Recipient Row */}
              <div className="stat">
                <span className="info-label">
                  {group.isOP_RETURN ? "Script" : 
                  group.isChange ? "Change" : 
                  "Recipient"}
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
                    {group.address !== 'OP_RETURN' ? (
                      renderClickableHash(
                        group.address,
                        onSearchClick,
                        group.address,
                        fmtAddress(group.address) || "-"
                      )
                    ) : (
                      <span className="value muted">OP_RETURN</span>
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
                      {group.address !== 'OP_RETURN' && (
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
                    <div style={{ 
                      display: 'flex', 
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      width: '100%'
                    }}>
                      <div className="tx-vout">
                        <span className={`vout-badge vout-${output.vout}`}>
                          {output.voutLabel}
                        </span>
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

export { ResultTx }