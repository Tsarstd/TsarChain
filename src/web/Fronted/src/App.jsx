import React, { useEffect, useMemo, useState } from "react";
import Navbar from "./components/navbar/nav_bar";
import { searchExplorer, fetchNetwork } from "./api/explorer";
import { guessKind } from "./utils/searchKind";
import "./App.css";

const fmtTsar = (sat) => {
  const n = Number(sat || 0);
  const whole = Math.trunc(n / 1e8);
  const frac = Math.abs(n % 1e8).toString().padStart(8, "0").replace(/0+$/, "");
  return `${whole.toLocaleString("id-ID")}${frac ? "," + frac : ""} TSAR`;
};

const short = (s, n = 8) => {
  if (!s) return "-";
  const str = String(s);
  return str.length <= n * 2 ? str : `${str.slice(0, n)}…${str.slice(-n)}`;
};

const fmtBytes = (b) => {
  const units = ["B", "KB", "MB", "GB"];
  let val = Number(b || 0);
  let i = 0;
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024;
    i += 1;
  }
  return i === 0 ? `${val} ${units[i]}` : `${val.toFixed(2)} ${units[i]}`;
};

const ResultBlock = ({ data }) => (
  <div className="card">
    <div className="stat">
      <span className="label">Block Height</span>
      <span className="value">#{data?.height ?? "-"}</span>
    </div>
    <div className="divider" />
    <div className="stat">
      <span className="label">Hash</span>
      <span className="value">{short(data?.hash)}</span>
    </div>
    <div className="stat">
      <span className="label">Prev Hash</span>
      <span className="value muted">{short(data?.prev_block_hash)}</span>
    </div>
    <div className="grid">
      <div className="stat">
        <span className="label">Difficulty</span>
        <span className="value">{data?.difficulty ?? "-"}</span>
      </div>
      <div className="stat">
        <span className="label">Size</span>
        <span className="value">{fmtBytes(data?.size_bytes)}</span>
      </div>
      <div className="stat">
        <span className="label">Timestamp</span>
        <span className="value">{data?.timestamp ? new Date(data.timestamp * 1000).toLocaleString() : "-"}</span>
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
            <span className="value">{short(tx.txid)}</span>
          </div>
          <div className="stat">
            <span className="label">Outputs</span>
            <span className="value">{tx.outputs?.length || 0}</span>
          </div>
        </div>
      ))}
    </div>
  </div>
);

const ResultTx = ({ data }) => (
  <div className="card">
    <div className="stat">
      <span className="label">TxID</span>
      <span className="value">{short(data?.txid, 12)}</span>
    </div>
    <div className="grid">
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
    </div>
    <div className="divider" />
    <div className="stat">
      <span className="label">Inputs</span>
      <span className="value">{data?.inputs?.length || 0}</span>
    </div>
    <div className="list">
      {(data?.inputs || []).map((inp, idx) => (
        <div className="tx-item" key={idx}>
          <div className="label">Dari</div>
          <div className="value">{inp.address}</div>
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
          <div className="label">Ke</div>
          <div className="value">{out.address}</div>
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
      <span className="value">{short(data?.address, 14)}</span>
    </div>
    <div className="grid">
      <div className="stat">
        <span className="label">Balance</span>
        <span className="value">{fmtTsar(data?.balance)}</span>
      </div>
      <div className="stat">
        <span className="label">Total Received</span>
        <span className="value">{fmtTsar(data?.received)}</span>
      </div>
      <div className="stat">
        <span className="label">Total Spent</span>
        <span className="value">{fmtTsar(data?.spent)}</span>
      </div>
    </div>
    <div className="divider" />
    <div className="stat">
      <span className="label">UTXO</span>
      <span className="value">{data?.utxos?.length || 0}</span>
    </div>
    <div className="list">
      {(data?.utxos || []).map((u) => (
        <div className="tx-item" key={`${u.txid}-${u.vout}`}>
          <div className="label">{short(u.txid)}</div>
          <div className="muted">vout {u.vout}</div>
          <div className="value">{fmtTsar(u.amount)}</div>
        </div>
      ))}
    </div>
  </div>
);

const ResultGraffiti = ({ data }) => (
  <div className="card">
    <div className="stat">
      <span className="label">Graffiti ID</span>
      <span className="value">{short(data?.art_id, 12)}</span>
    </div>
    <div className="grid">
      <div className="stat">
        <span className="label">Creator</span>
        <span className="value">{short(data?.creator, 12)}</span>
      </div>
      <div className="stat">
        <span className="label">Block</span>
        <span className="value">#{data?.block_height ?? "-"}</span>
      </div>
      <div className="stat">
        <span className="label">Size</span>
        <span className="value">{fmtBytes(data?.size)}</span>
      </div>
    </div>
    <div className="divider" />
    {data?.preview_url ? (
      <img src={data.preview_url} alt="Graffiti preview" style={{ width: "100%", borderRadius: 12 }} />
    ) : (
      <div className="muted">Preview tidak tersedia.</div>
    )}
    <div className="divider" />
    <div className="stat">
      <span className="label">Comments</span>
      <span className="value">{data?.comments?.length || 0}</span>
    </div>
    <div className="list">
      {(data?.comments || []).map((c, idx) => (
        <div className="comment-item" key={idx}>
          <div className="value">{c.comment}</div>
          <div className="muted">
            {c.commenter} • {fmtTsar(c.amount)}
          </div>
        </div>
      ))}
    </div>
  </div>
);

const NetworkCards = ({ snap }) => {
  if (!snap) return null;
  const stats = [
    { label: "Height", value: `#${snap.height ?? "-"}` },
    { label: "Peers", value: snap.peers ?? "-" },
    { label: "Mempool", value: snap.mempool_count ?? snap.txpool_size ?? "-" },
    { label: "Hashrate", value: `${snap.est_network_hashrate_hps_window ?? 0} H/s` },
    { label: "Difficulty", value: snap.difficulty ?? "-" },
    { label: "Block Time", value: `${snap.avg_block_time_sec_window ?? "-"} s` },
  ];
  return (
    <div className="card">
      <h3 style={{ marginBottom: 12 }}>Network Info</h3>
      <div className="network-grid">
        {stats.map((s) => (
          <div className="stat" key={s.label}>
            <span className="label">{s.label}</span>
            <span className="value">{s.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

const App = () => {
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState("unknown");
  const [result, setResult] = useState(null);
  const [network, setNetwork] = useState(null);
  const [status, setStatus] = useState("idle");
  const [message, setMessage] = useState("");

  useEffect(() => {
    fetchNetwork()
      .then((res) => setNetwork(res.data))
      .catch(() => setNetwork(null));
  }, []);

  const handleSearch = async () => {
    if (!query.trim()) {
      setMessage("Isi kata kunci pencarian.");
      return;
    }
    const inferred = guessKind(query);
    setKind(inferred);
    setStatus("loading");
    setMessage("");
    try {
      const resp = await searchExplorer(query);
      setResult(resp.data);
      setKind(resp.kind || inferred);
      setStatus("done");
    } catch (err) {
      setResult(null);
      setStatus("error");
      setMessage(err.message || "Gagal memuat data.");
    }
  };

  const renderResult = useMemo(() => {
    if (status === "idle") return <div className="result-empty">Mulai dengan mencari block / tx / address / graffiti.</div>;
    if (status === "loading") return <div className="result-empty">Mencari...</div>;
    if (status === "error") return <div className="result-empty">{message || "Terjadi kesalahan."}</div>;
    if (!result) return <div className="result-empty">Tidak ada data untuk pencarian ini.</div>;
    if (kind === "block" || kind === "block_height" || kind === "block_hash") return <ResultBlock data={result} />;
    if (kind === "tx" || kind === "txid_hash") return <ResultTx data={result} />;
    if (kind === "address") return <ResultAddress data={result} />;
    if (kind === "graffiti" || kind === "art_id") return <ResultGraffiti data={result} />;
    return <div className="result-empty">Jenis pencarian tidak dikenali.</div>;
  }, [status, result, kind, message]);

  return (
    <div className="app">
      <Navbar query={query} onQueryChange={setQuery} onSearch={handleSearch} />
      <main className="page">
        <section className="hero">
          <div>
            <h1>TsarChain Explorer</h1>
            <p>Cari block height/hash, TXID, address, atau Graffiti ID. Tema gelap dengan aksen oranye seperti wallet.</p>
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
            {status === "loading" ? "Loading..." : message || `Deteksi jenis: ${kind}`}
          </div>
        </section>

        <section className="section">
          <h2>Hasil Pencarian</h2>
          {renderResult}
        </section>

        <section className="section">
          <h2>Network</h2>
          <NetworkCards snap={network?.data || network} />
        </section>
      </main>
    </div>
  );
};

export default App;
