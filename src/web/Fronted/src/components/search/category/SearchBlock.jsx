import { ClickableValue } from ".././SearchResults";
import { useState, useEffect } from 'react';
import { 
  fmtBytes, 
  fmtTimestamp, 
  fmtTsar, 
  fmtChainwork,
  fmtHash,
  fmtTxid,
  fmtAddress,
  formatHashForDisplay,
  getMaxCharsPerLine
} from "../../../utils/format"


const ResultBlock = ({ data, onSearchClick }) => {
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

  const payouts = Array.isArray(data?.payouts)
    ? data.payouts
    : Array.isArray(data?._meta?.payouts)
      ? data._meta.payouts
      : [];
  const payoutCount =
    data?.payout_count ?? data?._meta?.payout_count ?? payouts.length ?? 0;

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
    <div className="card">
      <span className="block-details">Block Details #{data?.height ?? "-"}</span>
      <div className="divider" />

      {/* START OF BLOCK HEADER INFO */}

        <div className="stat">
          <span className="info-label">Block ID</span>
          {data?.block_id?.startsWith('graf') ? (
            <ClickableValue
              value={data.block_id}
              onSearchClick={onSearchClick}
              className="value muted"
              info="Click To See Graffiti Post"
              style={isMobile ? {whiteSpace: 'pre-wrap'} : {}}
            >
              {isMobile ? formatHashForDisplay((data.block_id) || "-", maxCharsPerLine) : (data.block_id) || "-"}
            </ClickableValue>
          ) : (
            renderHash(data?.block_id || "-")
          )}
        </div>

        <div className="divider2" />

        <div className="grid">
          <div className="stat">
            <span className="info-label">Hash</span>
            {renderHash(data?.hash, "wrap")}
          </div>
          <div className="stat">
            <span className="info-label">Prev Hash</span>
            {renderClickableHash(
              data?.prev_block_hash,
              onSearchClick,
              data?.prev_block_hash,
              fmtHash(data?.prev_block_hash) || "-"
            )}
          </div>
        </div>

        <div className="grid">
          <div className="stat">
            <span className="info-label">Timestamp</span>
            <span className="value">{fmtTimestamp(data?.timestamp)}</span>
          </div>
          <div className="stat">
            <span className="info-label">Nonce</span>
            <span className="value">{data?.nonce ?? "-"}</span>
          </div>
          <div className="stat">
            <span className="info-label">Difficulty</span>
            <span className="value">{data?.difficulty ?? "-"}</span>
          </div>
          <div className="stat">
            <span className="info-label">Size</span>
            <span className="value">{fmtBytes(data?.size_bytes)}</span>
          </div>
          <div className="stat">
            <span className="info-label">Chainwork</span>
            <span className="value">
              {fmtChainwork(data?.chainwork ?? "-")}
            </span>
          </div>
          <div className="stat">
            <span className="info-label">Bits</span>
            <span className="value">{data?.bits ?? "-"}</span>
          </div>
          <div className="stat">
            <span className="info-label">Version</span>
            <span className="value">{data?.version ?? "-"}</span>
          </div>
        </div>
        <div className="grid">
          <div className="stat">
            <span className="info-label">Merkle Root</span>
            {renderHash(data?.merkle_root ?? "-", "wrap")}
          </div>
        </div> 

        <div className="divider2" />

      {/* END OF BLOCK HEADER INFO */}

      {/* START OF GRAFFITI POST */}

        {data?.graffiti?.length ? <>
          <div className="stat">
            <span className="value">
              Graffiti Post
            </span>
          </div>
          <div className="tx-item">
            {(data?.graffiti || []).map((g, idx) => (
              <div className="stat" key={`graf-${idx}`}>
                <div className="grid">
                  <div className="stat">
                    <div className="info-label">Creator</div>
                    <div className="value">
                      {renderClickableHash(
                        g.creator,
                        onSearchClick,
                        g.creator,
                        fmtAddress(g.creator) || "-"
                      )}
                    </div>
                  </div>
                  <div className="stat">
                    <div className="info-label">Transaction ID</div>
                    {renderClickableHash(
                      g.txid,
                      onSearchClick,
                      g.txid,
                      fmtTxid(g.txid) || "-"
                    )}
                  </div>
                </div>
                <div className="info-label">Graffiti SHA256</div>
                <div className="value hash-multiline wrap">
                  {isMobile ? formatHashForDisplay(g.sha256 || g.hash || "-", maxCharsPerLine) : g.sha256 || g.hash || "-"}
                </div>
              </div>
            ))}
          </div>
          <div className="divider" />
        </> : null}

      {/* END OF GRAFFITI POST */}

      {/* START OF TRANSACTION LIST */}

      <div className="stat">
        <span className="value">{data?.transactions?.length || 0} Transactions</span>
      </div>
      <div className="list">
        {(data?.transactions || []).map((tx, index) => {
          const isCoinbase = index === 0;
          
          return (
            <div className="tx-item" key={tx.txid}>
                <div className="stat">
                  <span className="info-label">Transaction ID</span>
                    {renderClickableHash(
                      tx.txid,
                      onSearchClick,
                      tx.txid,
                      fmtTxid(tx.txid) || "-"
                    )}
                </div>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <div className="stat">
                  <span className="inputs-label">
                    {isCoinbase ? 0 : (tx.inputs?.length || 0)} Inputs 
                  </span>
                </div>
                <div className="stat">
                  <span className="outputs-label">{tx.outputs?.length || 0} Outputs</span>
                </div>
                <div className="stat">
                  {isCoinbase && (
                    <span className="coinbase-label">
                      Mining Reward
                    </span>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* END OF TRANSACTION LIST */}


      {/* START OF COMMENTS LIST */}

        {data?.comments?.length ? <>
          <div className="divider" />
          <div className="stat">
            <span className="value">
              {(data?.comments?.length || 0)} Comments
            </span>
          </div>
          <div className="tx-item">
            {(data?.comments || []).map((c) => (
                <div className="stat">
                  <div className="grid">
                      <div className="stat">
                        <div className="info-label">Citizen</div>
                          {renderClickableHash(
                            c.commenter,
                            onSearchClick,
                            c.commenter,
                            fmtAddress(c.commenter) || "-"
                          )}
                      </div>
                      <div className="stat">
                        <div className="info-label">Comment length {c.comment_len || "-"}</div>
                          {renderClickableHash(
                            c.art_id,
                            onSearchClick,
                            c.art_id,
                            fmtHash(c.art_id) || "-"
                          )}
                      </div>
                    <div className="stat">
                      <div className="info-label">Transaction ID</div>
                        {renderClickableHash(
                          c.txid,
                          onSearchClick,
                          c.txid,
                          fmtTxid(c.txid) || "-"
                        )}
                    </div>
                  </div>
                </div>
            ))}
          </div>
        </> : null}

      {/* END OF COMMENTS LIST */}

      {/* START OF PAYOUTS LIST */}

        {payouts.length ? <>
            <div className="divider" />
            <div className="stat">
              <span className="value">{payoutCount} Payouts</span>
            </div>
            <div className="list">
              {payouts.map((payout, idx) => (
                <div className="tx-item" key={payout?.txid || `payout-${idx}`}>
                  <div className="stat">
                    <span className="value">Epoch {payout?.epoch ?? "-"}</span>
                  </div>
                  <div className="grid">
                    <div className="stat">
                      <span className="info-label">Payout Transaction ID</span>
                        {renderClickableHash(
                          payout?.txid,
                          onSearchClick,
                          payout?.txid,
                          fmtTxid(payout?.txid) || "-"
                        )}
                    </div>
                    <div className="stat">
                      <span className="info-label">Graffiti ID</span>
                        {renderClickableHash(
                          payout?.art_id,
                          onSearchClick,
                          payout?.art_id,
                          fmtHash(payout?.art_id) || "-"
                        )}
                    </div>
                  </div>
                  <div className="divider2" />
                  <div className="stat">
                    <span className="value">
                      {payout?.recipients?.length || 0} Recipients 
                    </span>
                  </div>
                  <div className="list">
                    {(payout?.recipients || []).map((rcpt) => (
                      <div className="stat">
                        {renderClickableHash(
                          rcpt?.addr,
                          onSearchClick,
                          rcpt?.addr,
                          fmtAddress(rcpt?.addr) || "-"
                        )}
                        <div className="muted">{fmtTsar(rcpt?.amount || 0)}</div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
        </> : null}

      {/* END OF PAYOUTS LIST */}

    </div>
  );
};

export { ResultBlock }