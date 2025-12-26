import React, { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { searchExplorer } from "../api/explorer";
import { guessKind } from "../utils/searchKind";
import { fmtBytes, fmtTimestamp, fmtTsar, fmtChainwork } from "../utils/format";

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
        <span className="value">#{data?.height ?? "-"}</span>
      </div>
      <div className="stat">
        <span className="label">Block ID</span>
        <span className="value mono wrap">{data?.block_id || "-"}</span>
      </div>
      <div className="divider" />
      <div className="grid">
        <div className="stat">
          <span className="label">Hash</span>
          <span className="value mono wrap">{data?.hash || "-"}</span>
        </div>
        <div className="stat">
          <span className="label">Prev Hash</span>
          <span className="value mono wrap muted">
            {data?.prev_block_hash || "-"}
          </span>
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
          <span className="value mono wrap">
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
          <span className="value mono wrap">{data?.merkle_root ?? "-"}</span>
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
              <span className="value mono wrap">{tx.txid}</span>
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
                <div className="value mono wrap">{g.sha256 || g.hash || "-"}</div>
                <div className="muted">{"-------------------"}</div>
                <div className="muted">File</div>
                <div className="value mono wrap">
                  {g.mime || "-"} · {fmtBytes(g.size)}
                </div>
                <div className="muted">{"-------------------"}</div>
                <div className="muted">TXID</div>
                <div className="value mono wrap">{g.txid || "-"}</div>
              </div>
            ))}
            {(data?.comments || []).map((c, idx) => (
              <div className="comment-item" key={`cmt-${idx}`}>
                <div className="muted">Commenter:</div>
                <div className="value">{c.commenter || "-"}</div>
                <div className="muted">{"-------------------"}</div>
                <div className="muted">Comment:</div>
                <div className="value">{c.comment_text || c.comment || "-"}</div>
                <div className="muted">{"-------------------"}</div>
                <div className="muted">Base & Tip:</div>
                <div className="value">
                  {fmtTsar(c.amount)} {c.tip ? `- Tip ${fmtTsar(c.tip)}` : ""}
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
            <span className="label">Payouts</span>
            <span className="value">{payoutCount}</span>
          </div>
          <div className="list">
            {payouts.map((payout, idx) => (
              <div className="tx-item" key={payout?.txid || `payout-${idx}`}>
                <div className="stat">
                  <span className="label">Payout TxID</span>
                  <span className="value mono wrap">{payout?.txid || "-"}</span>
                </div>
                <div className="stat">
                  <span className="label">Art ID</span>
                  <span className="value mono wrap">{payout?.art_id || "-"}</span>
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
                      <div className="value mono wrap">{rcpt?.addr || "-"}</div>
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
      <span className="value mono wrap">{data?.txid || "-"}</span>
    </div>
    <div className="grid">
      <div className="stat">
        <span className="label">Status</span>
        <span className="value">{data?.status || "-"}</span>
      </div>
      <div className="stat">
        <span className="label">Block</span>
        <span className="value">#{data?.block_height ?? "-"}</span>
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
      {(data?.inputs || []).map((inp, idx) => (
        <div className="tx-item" key={idx}>
          <div className="value mono wrap">
            {inp.txid ? `${inp.txid}:${inp.vout}` : "-"}
          </div>
          <div className="muted">{inp.address || "-"}</div>
          <div className="muted">{fmtTsar(inp.amount)}</div>
        </div>
      ))}
    </div>
    <div className="divider" />
    <div className="stat">
      <span className="label">Outputs</span>
      <span className="value">{data?.outputs?.length || 0}</span>
    </div>
    <div className="list">
      {(data?.outputs || []).map((out, idx) => (
        <div className="tx-item" key={idx}>
          <div className="value mono wrap">{out.address || "OP_RETURN"}</div>
          <div className="muted">{fmtTsar(out.amount)}</div>
        </div>
      ))}
    </div>
  </div>
);

const ResultAddress = ({ data }) => (
  <div className="card">
    <div className="stat">
      <span className="label">Address</span>
      <span className="value mono wrap">{data?.address || "-"}</span>
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
      <div className="stat">
        <span className="label">Pending</span>
        <span className="value">{fmtTsar(data?.pending)}</span>
      </div>
    </div>
    <div className="divider" />
    <div className="stat">
      <span className="label">UTXO</span>
      <span className="value">{data?.utxos?.length || 0}</span>
    </div>
    <div className="list">
      {(data?.utxos || []).slice(0, 6).map((u) => (
        <div className="tx-item" key={`${u.txid}-${u.vout ?? u.index}`}>
          <div className="label mono wrap">{u.txid || "-"}</div>
          <div className="muted">vout {u.vout ?? u.index ?? "-"}</div>
          <div className="value">{fmtTsar(u.amount)}</div>
        </div>
      ))}
    </div>
    <div className="divider" />
    <div className="stat">
      <span className="label">Recent Activity</span>
      <span className="value">{data?.history?.length || 0}</span>
    </div>
    <div className="list">
      {(data?.history || []).slice(0, 6).map((h, idx) => (
        <div className="tx-item" key={h.txid || h.id || idx}>
          <div className="label mono wrap">{h.txid || h.id || "-"}</div>
          <div className="muted">{fmtTsar(h.amount || h.value || 0)}</div>
          <div className="value">{h.status || "-"}</div>
        </div>
      ))}
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
        <span className="value mono wrap">{data?.art_id || "-"}</span>
      </div>
      <div className="grid">
        <div className="stat">
          <span className="label">Creator</span>
          <span className="value mono wrap">{data?.creator || "-"}</span>
        </div>
        <div className="stat">
          <span className="label">Block</span>
          <span className="value">#{data?.block_height ?? "-"}</span>
        </div>
        <div className="stat">
          <span className="label">Size</span>
          <span className="value">
            {fmtBytes(data?.size || data?.size_bytes)}
          </span>
        </div>
        <div className="stat">
          <span className="label">TxID</span>
          <span className="value mono wrap">{data?.txid || "-"}</span>
        </div>
        <div className="stat">
          <span className="label">Pool Balance</span>
          <span className="value">{fmtTsar(data?.stats?.pool_balance)}</span>
        </div>
        <div className="stat">
          <span className="label">Comments</span>
          <span className="value">
            {data?.stats?.comments ?? data?.comments?.length ?? 0}
          </span>
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
        <div className="muted">Preview tidak tersedia.</div>
      )}
      <div className="divider" />
      <div className="list">
        {(data?.comments || []).slice(0, 6).map((c, idx) => (
          <div className="comment-item" key={idx}>
            <div className="muted">{fmtTimestamp(c.ts)}</div>
            <div className="value">{c.commenter || "-"}</div>
            <div className="value">{"-----------"}</div>
            <div className="value">{c.comment_text || c.comment || "-"}</div>
            <div className="value">{"-----------"}</div>
            <div className="muted">
              {fmtTsar(c.amount)} {c.tip ? ` - Tip ${fmtTsar(c.tip)}` : ""}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

const Home = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState("unknown");
  const [result, setResult] = useState(null);
  const [status, setStatus] = useState("idle");
  const [message, setMessage] = useState("");

  const runSearch = async (q) => {
    if (!q.trim()) return;
    const inferred = guessKind(q);
    setKind(inferred);
    setStatus("loading");
    setMessage("");
    try {
      const resp = await searchExplorer(q);
      setResult(resp.data);
      setKind(resp.kind || inferred);
      setStatus("done");
    } catch (err) {
      setResult(null);
      setStatus("error");
      setMessage(err.message || "Gagal memuat data.");
    }
  };

  useEffect(() => {
    const q = (searchParams.get("q") || "").trim();
    if (!q) {
      setStatus("idle");
      setResult(null);
      setKind("unknown");
      setMessage("");
      return;
    }
    setQuery(q);
    runSearch(q);
  }, [searchParams]);

  const handleSearch = () => {
    const q = query.trim();
    if (!q) {
      setMessage("Isi kata kunci pencarian.");
      return;
    }
    const current = (searchParams.get("q") || "").trim();
    if (current !== q) {
      setSearchParams({ q });
      return;
    }
    runSearch(q);
  };

  const renderResult = useMemo(() => {
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

  return (
    <main className="page">
      <section className="hero">
        <div>
          <h1>TsarChain Explorer</h1>
          <p>Cari block height/hash, TXID, address, atau Graffiti ID.</p>
        </div>
        <div className="hero-actions">
          <input
            type="text"
            placeholder="contoh: 128 atau 00abc... atau tsar1..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSearch()}
          />
          <button className="btn-primary" onClick={handleSearch}>
            Search
          </button>
        </div>
        <div className="chips">
          <span className="chip">Block Height</span>
          <span className="chip">Block Hash</span>
          <span className="chip">Txid</span>
          <span className="chip">Address</span>
          <span className="chip">Graffiti Id</span>
        </div>
        <div className="status-bar">
          {status === "loading"
            ? "Loading..."
            : message || `Deteksi jenis: ${kind}`}
        </div>
      </section>

      <section className="section">
        <h2>Hasil Pencarian</h2>
        {renderResult}
      </section>
    </main>
  );
};

export default Home;
