import PropTypes from "prop-types";
import { useState } from "react";
import { ClickableValue } from ".././SearchResults";
import { useRenderHelpers, useMobile } from "../SearchHelpers";
import { 
  fmtBytes, 
  fmtTimestamp, 
  fmtTsar, 
  fmtChainwork,
  fmtHash,
  fmtTxid,
  fmtAddress,
  formatHashForDisplay
} from "../../../utils/format";
import { 
  FaCube, 
  FaClock, 
  FaHdd, 
  FaTachometerAlt, 
  FaHashtag, 
  FaNetworkWired, 
  FaExchangeAlt, 
  FaPalette, 
  FaComments, 
  FaCoins, 
  FaAward, 
  FaChevronDown, 
  FaChevronUp,
  FaCogs
} from "react-icons/fa";


const ResultBlock = ({ data, onSearchClick }) => {
  const { renderHash, renderClickableHash } = useRenderHelpers();
  const { isMobile, maxCharsPerLine } = useMobile();
  const [showAllTxs, setShowAllTxs] = useState(false);

  let payouts = [];
  if (Array.isArray(data?.payouts)) {
    payouts = data.payouts;
  } else if (Array.isArray(data?._meta?.payouts)) {
    payouts = data._meta.payouts;
  }
  const payoutCount =
    data?.payout_count ?? data?._meta?.payout_count ?? payouts.length ?? 0;

  const txs = data?.transactions || [];
  const visibleTxs = showAllTxs ? txs : txs.slice(0, 10);

  return (
    <div className="block-details-container card">
      {/* HERO BLOCK HEADER BANNER */}
      <div className="block-hero-banner">
        <div className="block-hero-main">
          <div className="block-hero-badge">
            <FaCube className="block-hero-icon" />
            <span className="block-hero-height">Block #{data?.height ?? "-"}</span>
          </div>
          {data?.prev_block_hash && (
            <div className="block-prev-nav">
              <span className="prev-label">Prev Block:</span>
              {renderClickableHash(
                data?.prev_block_hash,
                onSearchClick,
                data?.prev_block_hash,
                fmtHash(data?.prev_block_hash) || "-",
                true
              )}
            </div>
          )}
        </div>

        <div className="block-hash-card">
          <div className="stat" style={{ marginBottom: '12px' }}>
            <span className="info-label">Block ID</span>
            {data?.block_id && String(data.block_id).toLowerCase().startsWith('graf') ? (
              <ClickableValue
                value={data.block_id}
                onSearchClick={onSearchClick}
                className="value block-id-clickable"
                info="Click To See Graffiti Post"
                isCopyable={true}
              >
                {isMobile ? formatHashForDisplay((data.block_id) || "-", maxCharsPerLine) : (data.block_id) || "-"}
              </ClickableValue>
            ) : (
              <div className="value hash-multiline wrap">
                {isMobile ? formatHashForDisplay(data?.block_id || "-", maxCharsPerLine) : data?.block_id || "-"}
              </div>
            )}
          </div>

          <div className="stat">
            <span className="info-label">Block Hash</span>
            {renderHash(data?.hash, "wrap", false)}
          </div>
        </div>
      </div>

      {/* DASHBOARD METRIC GRID CARDS */}
      <div className="block-metrics-grid">
        <div className="metric-card">
          <div className="metric-icon-wrap time">
            <FaClock />
          </div>
          <div className="metric-info">
            <span className="metric-label">Timestamp</span>
            <span className="metric-value">{fmtTimestamp(data?.timestamp)}</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon-wrap size">
            <FaHdd />
          </div>
          <div className="metric-info">
            <span className="metric-label">Size</span>
            <span className="metric-value">{fmtBytes(data?.size_bytes)}</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon-wrap diff">
            <FaTachometerAlt />
          </div>
          <div className="metric-info">
            <span className="metric-label">Difficulty</span>
            <span className="metric-value">{data?.difficulty ?? "-"}</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon-wrap nonce">
            <FaHashtag />
          </div>
          <div className="metric-info">
            <span className="metric-label">Nonce</span>
            <span className="metric-value">{data?.nonce ?? "-"}</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon-wrap version">
            <FaCogs />
          </div>
          <div className="metric-info">
            <span className="metric-label">Version / Bits</span>
            <span className="metric-value">v{data?.version ?? "-"} ({data?.bits ?? "-"})</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon-wrap chainwork">
            <FaNetworkWired />
          </div>
          <div className="metric-info">
            <span className="metric-label">Chainwork</span>
            <span className="metric-value">{fmtChainwork(data?.chainwork ?? "-")}</span>
          </div>
        </div>
      </div>

      {/* MERKLE ROOT BANNER */}
      <div className="block-merkle-banner">
        <span className="info-label">Merkle Root</span>
        <div className="merkle-value-wrap">
          {renderHash(data?.merkle_root ?? "-", "wrap", false)}
        </div>
      </div>

      {/* START OF GRAFFITI POST SECTION */}
      {data?.graffiti?.length ? (
        <div className="block-section">
          <div className="section-title-banner">
            <div className="title-left">
              <FaPalette className="section-icon graffiti" />
              <span>Graffiti Post</span>
              <span className="section-count-badge">{data.graffiti.length}</span>
            </div>
          </div>
          <div className="section-content-list">
            {data.graffiti.map((g, idx) => (
              <div className="section-card-item" key={g.txid || g.creator || idx}>
                <div className="card-item-row">
                  <div className="stat">
                    <span className="info-label">Creator</span>
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
                    <span className="info-label">Transaction ID</span>
                    {renderClickableHash(
                      g.txid,
                      onSearchClick,
                      g.txid,
                      fmtTxid(g.txid) || "-"
                    )}
                  </div>
                </div>
                <div className="card-item-row">
                  <div className="stat">
                    <span className="info-label">SHA256 Hash</span>
                    <div className="value hash-multiline wrap">
                      {isMobile ? formatHashForDisplay(g.sha256 || g.hash || "-", maxCharsPerLine) : g.sha256 || g.hash || "-"}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {/* START OF TRANSACTIONS SECTION */}
      <div className="block-section">
        <div className="section-title-banner">
          <div className="title-left">
            <FaExchangeAlt className="section-icon txs" />
            <span>Transactions</span>
            <span className="section-count-badge">{txs.length}</span>
          </div>
        </div>

        <div className="section-content-list">
          {visibleTxs.map((tx, index) => {
            const isCoinbase = index === 0;
            const inputCount = isCoinbase ? 0 : (tx.inputs?.length || 0);
            const outputCount = tx.outputs?.length || 0;

            return (
              <div className={`tx-card-item ${isCoinbase ? 'coinbase-item' : ''}`} key={tx.txid || index}>
                <div className="tx-card-main">
                  <div className="stat">
                    <span className="info-label">Transaction ID</span>
                    {renderClickableHash(
                      tx.txid,
                      onSearchClick,
                      tx.txid,
                      fmtTxid(tx.txid) || "-"
                    )}
                  </div>

                  <div className="tx-badges-group">
                    {isCoinbase ? (
                      <span className="coinbase-gold-badge" title="Mining Reward / Coinbase Transaction">
                        <FaAward className="award-icon" /> Mining Reward
                      </span>
                    ) : (
                      <span className="io-badge input-badge">
                        {inputCount} {inputCount === 1 ? 'Input' : 'Inputs'}
                      </span>
                    )}

                    <span className="io-badge output-badge">
                      {outputCount} {outputCount === 1 ? 'Output' : 'Outputs'}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}

          {txs.length > 10 && (
            <button
              type="button"
              className="comments-toggle-btn"
              onClick={() => setShowAllTxs((prev) => !prev)}
            >
              {showAllTxs ? (
                <>
                  <FaChevronUp /> Show Less
                </>
              ) : (
                <>
                  <FaChevronDown /> Show All {txs.length} Transactions
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {/* START OF COMMENTS SECTION */}
      {data?.comments?.length ? (
        <div className="block-section">
          <div className="section-title-banner">
            <div className="title-left">
              <FaComments className="section-icon comments" />
              <span>Comments</span>
              <span className="section-count-badge">{data.comments.length}</span>
            </div>
          </div>
          <div className="section-content-list">
            {data.comments.map((c, idx) => (
              <div className="section-card-item" key={c.txid || idx}>
                <div className="card-item-row">
                  <div className="stat">
                    <span className="info-label">Citizen</span>
                    {renderClickableHash(
                      c.commenter,
                      onSearchClick,
                      c.commenter,
                      fmtAddress(c.commenter) || "-"
                    )}
                  </div>
                  <div className="stat">
                    <span className="info-label">Graffiti Target</span>
                    {renderClickableHash(
                      c.art_id,
                      onSearchClick,
                      c.art_id,
                      fmtHash(c.art_id) || "-"
                    )}
                  </div>
                  <div className="stat">
                    <span className="info-label">Transaction ID</span>
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
        </div>
      ) : null}

      {/* START OF PAYOUTS SECTION */}
      {payouts.length ? (
        <div className="block-section">
          <div className="section-title-banner">
            <div className="title-left">
              <FaCoins className="section-icon payouts" />
              <span>Payouts</span>
              <span className="section-count-badge">{payoutCount}</span>
            </div>
          </div>
          <div className="section-content-list">
            {payouts.map((payout, idx) => (
              <div className="section-card-item payout-card" key={payout?.txid || `payout-${idx}`}>
                <div className="payout-header">
                  <span className="epoch-tag">Epoch {payout?.epoch ?? "-"}</span>
                  <div className="payout-txid">
                    <span className="info-label">Tx:</span>
                    {renderClickableHash(
                      payout?.txid,
                      onSearchClick,
                      payout?.txid,
                      fmtTxid(payout?.txid) || "-"
                    )}
                  </div>
                </div>

                <div className="stat" style={{ marginBottom: '8px' }}>
                  <span className="info-label">Graffiti ID</span>
                  {renderClickableHash(
                    payout?.art_id,
                    onSearchClick,
                    payout?.art_id,
                    fmtHash(payout?.art_id) || "-"
                  )}
                </div>

                {payout?.recipients?.length ? (
                  <div className="recipients-list">
                    {payout.recipients.map((rcpt, rIdx) => (
                      <div className="recipient-row" key={rcpt?.addr || rIdx}>
                        {renderClickableHash(
                          rcpt?.addr,
                          onSearchClick,
                          rcpt?.addr,
                          fmtAddress(rcpt?.addr) || "-"
                        )}
                        <span className="recipient-amount">{fmtTsar(rcpt?.amount || 0)}</span>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
};

ResultBlock.propTypes = {
  data: PropTypes.shape({
    // Base
    height: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    block_id: PropTypes.string,
    hash: PropTypes.string,
    prev_block_hash: PropTypes.string,
    timestamp: PropTypes.number,
    nonce: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    difficulty: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    size_bytes: PropTypes.number,
    chainwork: PropTypes.string,
    bits: PropTypes.string,
    version: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    merkle_root: PropTypes.string,

    // Graffiti (array of objects)
    graffiti: PropTypes.arrayOf(
      PropTypes.shape({
        creator: PropTypes.string,
        txid: PropTypes.string,
        sha256: PropTypes.string,
        hash: PropTypes.string, // fallback
      })
    ),

    // Transactions
    transactions: PropTypes.arrayOf(
      PropTypes.shape({
        txid: PropTypes.string,
        inputs: PropTypes.array,
        outputs: PropTypes.array,
      })
    ),

    // Comments
    comments: PropTypes.arrayOf(
      PropTypes.shape({
        commenter: PropTypes.string,
        art_id: PropTypes.string,
        txid: PropTypes.string,
        comment_len: PropTypes.number,
      })
    ),

    // Payouts & metada
    payouts: PropTypes.arrayOf(
      PropTypes.shape({
        txid: PropTypes.string,
        art_id: PropTypes.string,
        epoch: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
        recipients: PropTypes.arrayOf(
          PropTypes.shape({
            addr: PropTypes.string,
            amount: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
          })
        ),
      })
    ),
    payout_count: PropTypes.number,

    // Meta
    _meta: PropTypes.shape({
      payouts: PropTypes.array,
      payout_count: PropTypes.number,
    }),
  }),
  onSearchClick: PropTypes.func.isRequired,
};

export { ResultBlock }