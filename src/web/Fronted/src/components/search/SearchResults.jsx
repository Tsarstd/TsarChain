import { useMemo } from "react";
import { fmtBytes, fmtTimestamp, fmtTsar, fmtChainwork } from "../../utils/format";
import { getAddressType, getStatusBadge, getDirectionBadge, getVoutLabel } from "./SearchUX";
import "./search.css";


const ResultBlock = ({ data }) => {
  const payouts = Array.isArray(data?.payouts)
    ? data.payouts
    : Array.isArray(data?._meta?.payouts)
      ? data._meta.payouts
      : [];
  const payoutCount =
    data?.payout_count ?? data?._meta?.payout_count ?? payouts.length ?? 0;

  return (
    <div className="card">
      <div className="stat">
        <span className="label">Block Height</span>
        <span className="value">{data?.height ?? "-"}</span>
      </div>
      <div className="stat">
        <span className="label">Block ID</span>
        <span className="value">{data?.block_id}</span>
      </div>
      <div className="divider" />
      <div className="grid">
        <div className="stat">
          <span className="label">Hash</span>
          <span className="value">{data?.hash || "-"}</span>
        </div>
        <div className="stat">
          <span className="label">Prev Hash</span>
          <span className="value muted">{data?.prev_block_hash || "-"}</span>
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
          <span className="label">VBytes</span>
          <span className="value">{data?.vbytes ?? "-"}</span>
        </div>
        <div className="stat">
          <span className="label">Weight</span>
          <span className="value">{data?.weight ?? "-"}</span>
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
        <div className="stat">
          <span className="label">Merkle Root</span>
          <span className="value">{data?.merkle_root ?? "-"}</span>
        </div>
      </div>
      <div className="divider" />
      <div className="stat">
        <span className="label">Transactions</span>
        <span className="value">{data?.transactions?.length || 0}</span>
      </div>
      <div className="list">
        {(data?.transactions || []).map((tx) => (
          <div className="tx-item" key={tx.txid}>
            <div className="stat">
              <span className="label">TxID</span>
              <span className="value">{tx.txid}</span>
            </div>
            <div className="stat">
              <span className="label">Inputs</span>
              <span className="value">{tx.inputs?.length || 0}</span>
            </div>
            <div className="stat">
              <span className="label">Outputs</span>
              <span className="value">{tx.outputs?.length || 0}</span>
            </div>
          </div>
        ))}
      </div>
      {data?.graffiti?.length || data?.comments?.length ? (
        <>
          <div className="divider" />
          <div className="stat">
            <span className="label">Graffiti Activity</span>
            <span className="value">
              {(data?.graffiti?.length || 0) + (data?.comments?.length || 0)}
            </span>
          </div>
          <div className="list">
            {(data?.graffiti || []).map((g, idx) => (
              <div className="tx-item" key={`graf-${idx}`}>
                <div className="muted">SHA256</div>
                <div className="value">{g.sha256 || g.hash || "-"}</div>
                <div className="divider" />
                <div className="muted">File</div>
                <div className="value">
                  {g.mime || "-"} x {fmtBytes(g.size)}
                </div>
                <div className="divider" />
                <div className="muted">TXID</div>
                <div className="value">{g.txid || "-"}</div>
              </div>
            ))}
            {(data?.comments || []).map((c, idx) => (
              <div className="comment-item" key={`cmt-${idx}`}>
                <div className="muted">Commenter:</div>
                <div className="value">{c.commenter || "-"}</div>
                <div className="divider" />
                <div className="muted">Comment length:</div>
                <div className="value">{c.comment_len || c.comment || "-"}</div>
                <div className="divider" />
                <div className="muted">Art ID:</div>
                <div className="value">{c.art_id || "-"}</div>
                <div className="divider" />
                <div className="muted">TXID:</div>
                <div className="value">{c.txid || "-"}</div>
              </div>
            ))}
          </div>
        </>
      ) : null}
      {payouts.length ? (
        <>
          <div className="divider" />
          <div className="stat">
            <span className="label">Payouts</span>
            <span className="value">{payoutCount}</span>
          </div>
          <div className="list">
            {payouts.map((payout, idx) => (
              <div className="tx-item" key={payout?.txid || `payout-${idx}`}>
                <div className="stat">
                  <span className="label">Payout TxID</span>
                  <span className="value">{payout?.txid || "-"}</span>
                </div>
                <div className="stat">
                  <span className="label">Art ID</span>
                  <span className="value">{payout?.art_id || "-"}</span>
                </div>
                <div className="stat">
                  <span className="label">Epoch</span>
                  <span className="value">{payout?.epoch ?? "-"}</span>
                </div>
                <div className="divider" />
                <div className="stat">
                  <span className="label">Recipients</span>
                  <span className="value">
                    {payout?.recipients?.length || 0}
                  </span>
                </div>
                <div className="list">
                  {(payout?.recipients || []).map((rcpt, ridx) => (
                    <div
                      className="tx-item"
                      key={`${payout?.txid || idx}-${rcpt?.addr || ridx}`}
                    >
                      <div className="value">{rcpt?.addr || "-"}</div>
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

const ResultTx = ({ data }) => (
  <div className="card">
    <div className="stat">
      <span className="label">TxID</span>
      <span className="value">{data?.txid || "-"}</span>
    </div>
    
    <div className="grid">
      <div className="stat">
        <span className="label">Status</span>
        <span className="value">{data?.status || "-"}</span>
      </div>
      <div className="stat">
        <span className="label">Block</span>
        <span className="value">{data?.block_height ?? "-"}</span>
      </div>
      <div className="stat">
        <span className="label">Confirmations</span>
        <span className="value">{data?.confirmations ?? 0}</span>
      </div>
      <div className="stat">
        <span className="label">Fee</span>
        <span className="value">{fmtTsar(data?.fee || 0)}</span>
      </div>
      <div className="stat">
        <span className="label">Coinbase</span>
        <span className="value">{data?.is_coinbase ? "Yes" : "No"}</span>
      </div>
    </div>
    <div className="divider" />
    <div className="stat">
      <span className="label">Inputs</span>
      <span className="value">{data?.inputs?.length || 0}</span>
    </div>
    <div className="list">
      {(data?.inputs || []).map((inp, idx) => {
        const vout = inp?.vout || 0;
        const voutLabel = getVoutLabel(vout);
        const addressType = getAddressType(inp?.address);
        const showMeta = Boolean(addressType) || Boolean(inp?.txid);

        return (
          <div className="tx-items" key={idx}>
            <div className="label mono wrap">
              <div className="tx-info">
                {inp.txid ? `${inp.txid}` : "-"}
              </div>
              <div className="muted">{inp.address || "-"}</div>
              <div className="tx-amount">{fmtTsar(inp.amount)}</div>
            </div>
            {showMeta ? (
              <div className="tx-vout">
                {addressType ? (
                  <span className={`addr-badge addr-${addressType.type}`}>
                    {addressType.label}
                  </span>
                ) : null}
                {inp.txid ? (
                  <span className={`vout-badge vout-${vout}`}>
                    {voutLabel}
                  </span>
                ) : null}
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
    <div className="divider" />
    <div className="stat">
      <span className="label">Outputs</span>
      <span className="value">{data?.outputs?.length || 0}</span>
    </div>
    <div className="list">
      {(data?.outputs || []).map((out, idx) => {
        const vout = typeof out?.vout === "number" ? out.vout : idx;
        const voutLabel = getVoutLabel(vout);
        const addressValue = out?.address || "";
        const addressType = addressValue
          ? getAddressType(addressValue)
          : { type: "opreturn", label: "OP_RETURN" };

        return (
          <div className="tx-items" key={idx}>
            <div className="label mono wrap">
              <div className="tx-info">{addressValue || "OP_RETURN"}</div>
              <div className="tx-amount">{fmtTsar(out.amount)}</div>
            </div>
            <div className="tx-vout">
              {addressType ? (
                <span className={`addr-badge addr-${addressType.type}`}>
                  {addressType.label}
                </span>
              ) : null}
              <span className={`vout-badge vout-${vout}`}>
                {voutLabel}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  </div>
);

const ResultAddress = ({ data }) => (
  <div className="card">
    <div className="stat">
      <span className="label">Address</span>
      <span className="value">{data?.address || "-"}</span>
    </div>
    <div className="grid">
      <div className="stat">
        <span className="label">Balance</span>
        <span className="value">{fmtTsar(data?.balance)}</span>
      </div>
      <div className="stat">
        <span className="label">Spendable</span>
        <span className="value">{fmtTsar(data?.spendable)}</span>
      </div>
      <div className="stat">
        <span className="label">Immature</span>
        <span className="value">{fmtTsar(data?.immature)}</span>
      </div>
    </div>
    <div className="divider" />
    <div className="stat">
      <span className="label">Outgoing</span>
      <span className="value">{fmtTsar(data?.outgoing)}</span>
    </div>
    <div className="stat">
      <span className="label">Incoming</span>
      <span className="value">{fmtTsar(data?.incoming)}</span>
    </div>
    <div className="stat">
      <span className="label">UTXO Set</span>
      <span className="value">{data?.utxos?.length || 0}</span>
    </div>
    <div className="divider" />
      <div className="stat">
        <span className="value">Recent Activity : {data?.history?.length || 0}</span>
      </div>
      <div className="card-list">
        {(data?.history || []).slice(0, 50).map((h, idx) => {
          const statusBadge = getStatusBadge(h.status);
          const directionBadge = getDirectionBadge(h.direction);
          const timestamp = h.timestamp || h.time || h.ts;
          const confirmations = h.confirmations || 0;
          
          return (
            <div className="tx-items" key={h.txid || h.id || idx}>
              <div className="tx-info">
                <div className="tx-info">{h.txid || h.id || "-"}</div>
                <div className="tx-meta">
                  {timestamp ? (
                    <span className="tx-time">{fmtTimestamp(timestamp)}</span>
                  ) : null}
                  {confirmations > 0 ? (
                    <span className="tx-confirms">({confirmations} confirms)</span>
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
    </div>
  );

const ResultGraffiti = ({ data }) => {
  const mime = String(data?.mime || "").toLowerCase();
  const isVideo = mime.includes("video") || mime.includes("mp4");
  return (
    <div className="card">
      <div className="stat">
          <span className="label">Graffiti ID</span>
          <span className="value">{data?.art_id || "-"}</span>
          <span className="label">Creator</span>
          <span className="value">{data?.creator || "-"}</span>
          <span className="label">Total Creator Income</span>
          <span className="value">{fmtTsar(data?.stats?.creator_paid)}</span>

        <div className="divider" />

        <div className="grid">
          <div className="stat">
            <span className="label">Upload Fee</span>
            <span className="value">{fmtTsar(data?.amount_paid)}</span>
          </div>
          <div className="stat">
            <span className="label">Anchoring at</span>
            <span className="value">Block {data?.block_height ?? "-"}</span>
          </div>
        </div>
          <span className="label">TxID</span>
          <span className="value">{data?.txid || "-"}</span>
      </div>


      <div className="divider" />

      <div className="stat">
        <div className="grid">
          <div className="stat">
            <span className="label">SHA256 File</span>
            <span className="value">{data?.sha256 || "-"}</span>
          </div>
          <div className="stat">
            <span className="label">File Size</span>
            <span className="value">{fmtBytes(data?.size || data?.size_bytes)}</span>
          </div>
        </div>
          <span className="label">Graffiti Merkle</span>
          <span className="value">{data?.mroot || "-"}</span>
        <div className="grid">
          <div className="stat">
            <span className="label">Merkle Chunk</span>
            <span className="value">{fmtBytes(data?.mchunk)}</span>
          </div>
          <div className="stat">
            <span className="label">Merkle Count</span>
            <span className="value">{data?.mcount || "-"}</span>
          </div>
        </div>
      </div>

      <div className="divider" />

      <div className="grid">
        <div className="stat">
          <span className="label">Pool Address</span>
          <span className="value">{data?.pool_address}</span>
        </div>
        <div className="stat">
          <span className="label">Pool Balance</span>
          <span className="value">{fmtTsar(data?.stats?.pool_balance)}</span>
        </div>
      </div>
      <div className="grid">
        <div className="stat">
          <span className="label">Storage Address</span>
          <span className="value">{data?.storer}</span>
        </div>
        <div className="stat">
          <span className="label">Storage Income From Comment</span>
          <span className="value">{fmtTsar(data?.stats?.storage_paid)}</span>
        </div>
      </div>
      <div className="grid">
        <div className="stat">
          <span className="label">Last Paid Epoch</span>
          <span className="value">Epoch {data?.stats?.last_paid_epoch}</span>
        </div>
        <div className="stat">
          <span className="label">Total Comments</span>
          <span className="value">{data?.stats?.comments ?? data?.comments?.length ?? 0}</span>
        </div>
      </div>

      <div className="divider" />

      {data?.preview_url ? (
        isVideo ? (
          <video
            className="media-preview"
            controls
            preload="metadata"
            src={data.preview_url}
          />
        ) : (
          <img
            className="media-preview"
            src={data.preview_url}
            alt="Graffiti preview"
            loading="lazy"
          />
        )
      ) : (
        <div className="muted">Preview is not available</div>
      )}

      <div className="divider" />

      <div className="list">
        {(data?.comments || []).slice(0, 6).map((c, idx) => (
          <div className="comment-item" key={idx}>
            <div className="muted">{fmtTimestamp(c.ts)}</div>
            <div className="value">{c.commenter || "-"}</div>
            <div className="divider" />
            <div className="value">{c.comment_text || c.comment || "-"}</div>
            <div className="divider" />
            <div className="muted">{fmtTsar(c.amount)} {c.tip ? ` - Tip ${fmtTsar(c.tip)}` : ""}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

const SearchResultPanel = ({ status, result, kind, message }) => {
  const body = useMemo(() => {
    if (status === "idle")
      return (
        <div className="result-empty">
          Mulai dengan mencari block / tx / address / graffiti.
        </div>
      );
    if (status === "loading")
      return <div className="result-empty">Mencari...</div>;
    if (status === "error")
      return (
        <div className="result-empty">{message || "Terjadi kesalahan."}</div>
      );
    if (!result)
      return (
        <div className="result-empty">Tidak ada data untuk pencarian ini.</div>
      );
    if (kind === "block" || kind === "block_height" || kind === "block_hash")
      return <ResultBlock data={result} />;
    if (kind === "tx" || kind === "txid_hash")
      return <ResultTx data={result} />;
    if (kind === "address") return <ResultAddress data={result} />;
    if (kind === "graffiti" || kind === "art_id")
      return <ResultGraffiti data={result} />;
    return <div className="result-empty">Jenis pencarian tidak dikenali.</div>;
  }, [status, result, kind, message]);

  return body;
};

export { ResultBlock };
export default SearchResultPanel;
