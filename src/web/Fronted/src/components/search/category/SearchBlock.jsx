import { ClickableValue } from ".././SearchResults";
import { fmtBytes, fmtTimestamp, fmtTsar, fmtChainwork } from "../../../utils/format"
import "../search.css";


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
      <div className="stat">
        <span className="label">Block ID</span>
        <span className="value">{data?.block_id}</span>
      </div>
      <div className="divider" />
      <div className="grid">
        <div className="stat">
          <span className="label">Hash</span>
          <span className="value">{data?.hash}</span>
        </div>
        <div className="stat">
          <span className="label">Prev Hash</span>
          <ClickableValue value={data?.prev_block_hash} onSearchClick={onSearchClick} className="value muted">
            {data?.prev_block_hash || "-"}
          </ClickableValue>
        </div>
      </div>
      <div className="grid">
        <div className="stat">
          <span className="label">Timestamp</span>
          <span className="value">{fmtTimestamp(data?.timestamp)}</span>
        </div>
        <div className="stat">
          <span className="label">Nonce</span>
          <span className="value">{data?.nonce ?? "-"}</span>
        </div>
        <div className="stat">
          <span className="label">Difficulty</span>
          <span className="value">{data?.difficulty ?? "-"}</span>
        </div>
        <div className="stat">
          <span className="label">Size</span>
          <span className="value">{fmtBytes(data?.size_bytes)}</span>
        </div>
        <div className="stat">
          <span className="label">Chainwork</span>
          <span className="value">
            {fmtChainwork(data?.chainwork ?? "-")}
          </span>
        </div>
        <div className="stat">
          <span className="label">Bits</span>
          <span className="value">{data?.bits ?? "-"}</span>
        </div>
        <div className="stat">
          <span className="label">Version</span>
          <span className="value">{data?.version ?? "-"}</span>
        </div>
      </div>
      <div className="divider" />
      <div className="grid">
        <div className="stat">
          <span className="label">Merkle Root</span>
          <span className="value">{data?.merkle_root ?? "-"}</span>
        </div>
      </div>  
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
                <span className="label">TxID</span>
                <ClickableValue value={tx.txid} onSearchClick={onSearchClick} className="value muted">
                  {tx.txid || "-"}
                </ClickableValue>
              </div>
              {isCoinbase && (
                <span style={{
                  backgroundColor: '#848056ff',
                  color: '#16171a',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  fontWeight: 'bold'
                }}>
                  COINBASE
                </span>
              )}
            </div>
            <div className="grid">
              <div className="stat">
                <span className="value">
                  Inputs {isCoinbase ? 0 : (tx.inputs?.length || 0)}
                </span>
              </div>
              <div className="stat">
                <span className="value">Outputs {tx.outputs?.length || 0}</span>
              </div>
            </div>
          </div>
        );
      })}
      </div>
      {data?.graffiti?.length || data?.comments?.length ? (
        <>
          <div className="divider" />
          <div className="stat">
            <span className="value">
              Graffiti Activity {(data?.graffiti?.length || 0) + (data?.comments?.length || 0)}
            </span>
          </div>
          <div className="tx-item">
            {(data?.graffiti || []).map((g, idx) => (
              <div className="stat" key={`graf-${idx}`}>
                <div className="stat">
                  <div className="label">Creator</div>
                  <div className="value">
                  <ClickableValue value={g.creator} onSearchClick={onSearchClick} className="value muted">
                    {g.creator|| "-"}
                  </ClickableValue>
                </div>
                <div className="stat">
                  </div>
                  <div className="label">TXID</div>
                  <ClickableValue value={g.txid} onSearchClick={onSearchClick} className="value muted">
                    {g.txid|| "-"}
                  </ClickableValue>
                </div>
                <div className="stat">
                  <div className="label">Graffiti SHA256</div>
                  <div className="value">{g.sha256 || g.hash || "-"}</div>
                </div>
              </div>
            ))}
            {(data?.comments || []).map((c) => (
                <div className="stat">
                  <div className="grid">
                      <div className="stat">
                        <div className="label">Commenter:</div>
                          <ClickableValue value={c.commenter} onSearchClick={onSearchClick} className="value muted">
                            {c.commenter|| "-"}
                          </ClickableValue>
                      </div>
                      <div className="stat">
                        <div className="label">Put Comment in:</div>
                        <ClickableValue value={c.art_id} onSearchClick={onSearchClick} className="value muted">
                          {c.art_id|| "-"}
                        </ClickableValue>
                      </div>
                  </div>
                  <div className="grid">
                    <div className="stat">
                      <div className="label">TxID:</div>
                      <ClickableValue value={c.txid} onSearchClick={onSearchClick} className="value muted">
                        {c.txid|| "-"}
                      </ClickableValue>
                    </div>
                      <div className="value">Comment length {c.comment_len || c.comment || "-"}</div>
                  </div>
                </div>
            ))}
          </div>
        </>
      ) : null}
      {payouts.length ? (
        <>
          <div className="divider" />
          <div className="stat">
            <span className="value">Payouts {payoutCount}</span>
          </div>
          <div className="list">
            {payouts.map((payout, idx) => (
              <div className="tx-item" key={payout?.txid || `payout-${idx}`}>
                <div className="grid">
                  <div className="stat">
                    <span className="label">Payout TxID</span>
                    <ClickableValue value={payout?.txid} onSearchClick={onSearchClick} className="value muted">
                      {payout?.txid|| "-"}
                    </ClickableValue>
                  </div>
                  <div className="stat">
                    <span className="label">Art ID</span>
                    <ClickableValue value={payout?.art_id} onSearchClick={onSearchClick} className="value muted">
                      {payout?.art_id|| "-"}
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
                      <ClickableValue value={rcpt?.addr} onSearchClick={onSearchClick} className="value muted">
                        {rcpt?.addr|| "-"}
                      </ClickableValue>
                      <div className="muted">{fmtTsar(rcpt?.amount || 0)}</div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </>
      ) : null}
    </div>
  );
};

export { ResultBlock }