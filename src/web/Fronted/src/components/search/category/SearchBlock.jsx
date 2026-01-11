import { ClickableValue } from ".././SearchResults";
import { 
  fmtBytes, 
  fmtTimestamp, 
  fmtTsar, 
  fmtChainwork,
  fmtHash,
  fmtTxid,
  fmtAddress 
} from "../../../utils/format"


const ResultBlock = ({ data, onSearchClick }) => {
  const payouts = Array.isArray(data?.payouts)
    ? data.payouts
    : Array.isArray(data?._meta?.payouts)
      ? data._meta.payouts
      : [];
  const payoutCount =
    data?.payout_count ?? data?._meta?.payout_count ?? payouts.length ?? 0;

  return (
    <div className="card">
      <span className="block-details">Block Details #{data?.height ?? "-"}</span>
      <div className="divider" />

      {/* START OF BLOCK HEADER INFO */}

        <div className="stat">
          <span className="info-label">Block ID</span>
            {data?.block_id?.startsWith('graf') ? (
              <ClickableValue value={data.block_id} onSearchClick={onSearchClick} className="value muted">
                {data.block_id}
              </ClickableValue>
            ) : (
              <span className="value">{data?.block_id || "-"}</span>
            )}
        </div>
        <div className="divider2" />
        <div className="grid">
          <div className="stat">
            <span className="info-label">Hash</span>
            <span className="value">{data?.hash}</span>
          </div>
          <div className="stat">
            <span className="info-label">Prev Hash</span>
              <ClickableValue 
                value={data?.prev_block_hash} 
                onSearchClick={onSearchClick} 
                className="value muted"
                info={data?.prev_block_hash}
              >
                {fmtHash(data?.prev_block_hash) || "-"}
              </ClickableValue>
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
            <span className="value">{data?.merkle_root ?? "-"}</span>
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
                      <ClickableValue 
                        value={g.creator} 
                        onSearchClick={onSearchClick} 
                        className="value muted"
                        info={g.creator}
                      >
                        {fmtAddress(g.creator) || "-"}
                      </ClickableValue>
                    </div>
                  </div>
                  <div className="stat">
                    <div className="info-label">Transaction ID</div>
                      <ClickableValue 
                        value={g.txid} 
                        onSearchClick={onSearchClick} 
                        className="value muted"
                        info="Click For More Details"
                      >
                        {fmtTxid(g.txid) || "-"}
                      </ClickableValue>
                  </div>
                </div>
                  <div className="info-label">Graffiti SHA256</div>
                  <div className="value">{g.sha256 || g.hash || "-"}</div>
              </div>
            ))}
          </div>
          <div className="divider" />
        </> : null}

      {/* END OF GRAFFITI POST */}

      {/* START OF TRANSACTION LIST */}

      <div className="stat">
        <span className="value">Transactions {data?.transactions?.length || 0}</span>
      </div>
      <div className="list">
        {(data?.transactions || []).map((tx, index) => {
          const isCoinbase = index === 0;
          
          return (
            <div className="tx-item" key={tx.txid}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div className="stat">
                  <span className="info-label">Transaction ID</span>
                    <ClickableValue 
                      value={tx.txid} 
                      onSearchClick={onSearchClick} 
                      className="value muted"
                      info="Click For More Details"
                    >
                      {fmtTxid(tx.txid) || "-"}
                    </ClickableValue>
                </div>
                {isCoinbase && (
                  <span className="coinbase-label">
                    Mining Reward
                  </span>
                )}
              </div>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <div className="stat">
                  <span className="inputs-label">
                    Inputs {isCoinbase ? 0 : (tx.inputs?.length || 0)}
                  </span>
                </div>
                <div className="stat">
                  <span className="outputs-label">Outputs {tx.outputs?.length || 0}</span>
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
              Comments {(data?.comments?.length || 0)}
            </span>
          </div>
          <div className="tx-item">
            {(data?.comments || []).map((c) => (
                <div className="stat">
                  <div className="grid">
                      <div className="stat">
                        <div className="info-label">Commenter</div>
                          <ClickableValue 
                            value={c.commenter} 
                            onSearchClick={onSearchClick} 
                            className="value muted"
                          >
                            {fmtAddress(c.commenter) || "-"}
                          </ClickableValue>
                      </div>
                      <div className="stat">
                        <div className="info-label">Put Comment in</div>
                          <ClickableValue 
                            value={c.art_id} 
                            onSearchClick={onSearchClick} 
                            className="value muted"
                          >
                            {fmtHash(c.art_id) || "-"}
                          </ClickableValue>
                      </div>
                  </div>
                  <div className="grid">
                    <div className="stat">
                      <div className="info-label">Transaction ID</div>
                          <ClickableValue 
                            value={c.txid} 
                            onSearchClick={onSearchClick} 
                            className="value muted"
                          >
                            {fmtTxid(c.txid) || "-"}
                          </ClickableValue>
                    </div>
                    <div className="stat">
                      <div className="value">Comment length {c.comment_len || "-"}</div>
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
              <span className="value">Payouts {payoutCount}</span>
            </div>
            <div className="list">
              {payouts.map((payout, idx) => (
                <div className="tx-item" key={payout?.txid || `payout-${idx}`}>
                  <div className="grid">
                    <div className="stat">
                      <span className="info-label">Payout Transaction ID</span>
                        <ClickableValue 
                          value={payout?.txid} 
                          onSearchClick={onSearchClick} 
                          className="value muted"
                        >
                          {fmtTxid(payout?.txid) || "-"}
                        </ClickableValue>
                    </div>
                    <div className="stat">
                      <span className="info-label">Graffiti ID</span>
                        <ClickableValue 
                          value={payout?.art_id} 
                          onSearchClick={onSearchClick} 
                          className="value muted"
                        >
                          {fmtHash(payout?.art_id) || "-"}
                        </ClickableValue>
                    </div>
                  </div>
                  <div className="stat">
                    <span className="value">Epoch {payout?.epoch ?? "-"}</span>
                  </div>
                  <div className="divider" />
                  <div className="stat">
                    <span className="value">
                      Recipients {payout?.recipients?.length || 0}
                    </span>
                  </div>
                  <div className="list">
                    {(payout?.recipients || []).map((rcpt, ridx) => (
                      <div
                        className="tx-items"
                        key={`${payout?.txid || idx}-${rcpt?.addr || ridx}`}
                      >
                        <ClickableValue 
                          value={rcpt?.addr} 
                          onSearchClick={onSearchClick} 
                          className="value muted"
                        >
                          {fmtAddress(rcpt?.addr) || "-"}
                        </ClickableValue>
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