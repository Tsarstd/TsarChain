import React, { useEffect, useMemo, useState } from "react";
import { fetchNetwork } from "../api/explorer";
import { fmtBytes, fmtHashrate, fmtNumber, fmtTimestamp, fmtTsar } from "../utils/format";

const getPeersCount = (snap, fallback = 0) => {
  const peers = snap?.peers;
  if (Array.isArray(peers)) return peers.length;
  if (typeof peers === "number") return peers;
  if (peers && typeof peers === "object") {
    if (peers.count !== undefined) return Number(peers.count) || 0;
    if (peers.total !== undefined) return Number(peers.total) || 0;
    const values = Object.values(peers);
    if (values.length === 1) return Number(values[0]) || 0;
  }
  return fallback;
};

const normalizeSnapshot = (raw) => {
  if (!raw || typeof raw !== "object") return null;
  const snap = raw.data && typeof raw.data === "object" ? raw.data : raw;
  const identity = snap.identity || {};
  const chain = snap.chain || {
    tip_height: snap.tip_height ?? snap.height,
    total_blocks: snap.total_blocks ?? snap.blocks,
    tip_hash: snap.tip_hash ?? snap.best_hash,
    tip_target_hex: snap.tip_target_hex ?? snap.target,
    tip_difficulty: snap.tip_difficulty ?? snap.difficulty,
    avg_block_time_sec_window: snap.avg_block_time_sec_window,
    est_network_hashrate_hps_window: snap.est_network_hashrate_hps_window,
  };
  const supply = snap.supply || {};
  const transactions = snap.transactions || {};
  const utxo = snap.utxo || {};
  const graffiti = snap.graffiti || {};
  const miners = snap.miners_snapshot || {};
  return { ...snap, identity, chain, supply, transactions, utxo, graffiti, miners_snapshot: miners };
};

const fmtLastUpdate = (val) => {
  if (!val) return "-";
  if (typeof val === "number") return fmtTimestamp(val);
  const date = new Date(String(val));
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString("id-ID");
};

const InfoGrid = ({ items }) => (
  <div className="network-grid">
    {items.map((item) => (
      <div className="stat" key={item.label}>
        <span className="label">{item.label}</span>
        <span className="value">{item.value}</span>
      </div>
    ))}
  </div>
);

const Network = () => {
  const [snap, setSnap] = useState(null);
  const [status, setStatus] = useState("loading");
  const [message, setMessage] = useState("");

  useEffect(() => {
    fetchNetwork()
      .then((resp) => {
        setSnap(resp.data || null);
        setStatus("done");
      })
      .catch((err) => {
        setMessage(err.message || "Gagal memuat data network.");
        setStatus("error");
      });
  }, []);

  const view = useMemo(() => normalizeSnapshot(snap), [snap]);

  if (status === "loading") {
    return (
      <main className="page">
        <div className="result-empty">Memuat network info...</div>
      </main>
    );
  }

  if (status === "error" || !view) {
    return (
      <main className="page">
        <div className="result-empty">{message || "Network info tidak tersedia."}</div>
      </main>
    );
  }

  const peersCount = getPeersCount(view, 0);
  const chain = view.chain || {};
  const supply = view.supply || {};
  const txs = view.transactions || {};
  const utxo = view.utxo || {};
  const graffiti = view.graffiti || {};
  const miners = view.miners_snapshot || {};

  return (
    <main className="page network-page">
      <section className="section">
        <h2>Network Info</h2>
        <p className="muted">Ringkasan status jaringan TsarChain, setara Network tab di wallet.</p>
      </section>

      <section className="section card network-summary">
        <div className="stat">
          <span className="label">Last Update</span>
          <span className="value">{fmtLastUpdate(view.last_updated)}</span>
        </div>
        <div className="stat">
          <span className="label">Schema Version</span>
          <span className="value">{view.schema_version ?? "-"}</span>
        </div>
        <div className="stat">
          <span className="label">Peers</span>
          <span className="value">{fmtNumber(peersCount)}</span>
        </div>
      </section>

      <section className="section">
        <h3>Network Identity</h3>
        <InfoGrid
          items={[
            { label: "Network ID", value: view.identity?.network_id || "-" },
            { label: "Network Magic", value: view.identity?.network_magic_hex || "-" },
            { label: "Address Prefix", value: view.identity?.address_prefix || "-" },
          ]}
        />
      </section>

      <section className="section">
        <h3>Blockchain</h3>
        <InfoGrid
          items={[
            { label: "Genesis Message", value: chain.genesis_message || "-" },
            { label: "Genesis Hash", value: <span className="mono wrap">{chain.genesis_hash || "-"}</span> },
            { label: "Network Hashrate", value: fmtHashrate(chain.est_network_hashrate_hps_window) },
            { label: "Avg Block Time", value: `${chain.avg_block_time_sec_window ?? "-"} s` },
            { label: "Total Blocks", value: fmtNumber(chain.total_blocks) },
            { label: "Tip Height", value: fmtNumber(chain.tip_height) },
            { label: "Tip Hash", value: <span className="mono wrap">{chain.tip_hash || "-"}</span> },
            { label: "Tip Target", value: <span className="mono wrap">{chain.tip_target_hex || "-"}</span> },
            { label: "Tip Timestamp", value: fmtTimestamp(chain.tip_timestamp) },
            { label: "Tip Bits", value: chain.tip_bits ?? "-" },
            { label: "Tip Difficulty", value: fmtNumber(chain.tip_difficulty) },
            { label: "Total Block Size", value: fmtBytes(chain.total_block_size_bytes) },
          ]}
        />
      </section>

      <section className="section">
        <h3>Blockchain Economy</h3>
        <InfoGrid
          items={[
            { label: "Max Supply", value: fmtTsar(supply.max_supply) },
            { label: "Circulating Supply", value: fmtTsar(supply.circulating_estimate) },
            { label: "Coinbase Reward", value: fmtTsar(chain.current_block_subsidy || supply.current_block_subsidy) },
            { label: "Maturity Rule", value: `${supply.coinbase_maturity ?? "-"} Block` },
            { label: "Immature Coinbase", value: fmtTsar(supply.immature_coinbase) },
            { label: "Emitted Subsidy", value: fmtTsar(supply.emitted_subsidy) },
            { label: "Current Epoch", value: fmtNumber(supply.current_epoch) },
            { label: "Halving Height", value: fmtNumber(supply.next_halving_height) },
            { label: "Blocks To Halving", value: fmtNumber(supply.blocks_to_halving) },
          ]}
        />
      </section>

      <section className="section">
        <h3>Transactions</h3>
        <InfoGrid
          items={[
            { label: "Mempool Txs", value: fmtNumber(txs.mempool_txs) },
            { label: "Mempool VBytes", value: fmtNumber(txs.mempool_vbytes_estimate) },
            { label: "Total Fees Paid", value: fmtTsar(txs.total_fees_paid) },
            { label: "Total Transactions", value: fmtNumber(txs.total_txs) },
            { label: "Non-Coinbase Txs", value: fmtNumber(txs.total_non_coinbase_txs ?? txs.total_txs) },
            { label: "UTXO Set Size", value: fmtNumber(utxo.utxo_set_size) },
          ]}
        />
      </section>

      <section className="section">
        <h3>Graffiti</h3>
        <InfoGrid
          items={[
            { label: "Total Graffiti", value: fmtNumber(graffiti.posts) },
            { label: "Total Comments", value: fmtNumber(graffiti.comments) },
            { label: "Pool Balances", value: fmtTsar(graffiti.pool_balances) },
            { label: "Total Payouts", value: fmtNumber(graffiti.payouts) },
            { label: "Total Storage", value: fmtBytes(graffiti.total_graffiti_storage) },
            { label: "Graffiti on Mempool", value: fmtNumber(graffiti.graffiti_on_mempool) },
          ]}
        />
      </section>

      <section className="section">
        <h3>Top Miners</h3>
        <div className="card">
          <div className="list">
            {(miners.top_miners || []).slice(0, 10).map(([addr, found], idx) => (
              <div className="tx-item" key={`${addr}-${idx}`}>
                <div className="label">Rank {idx + 1}</div>
                <div className="value mono wrap">{addr}</div>
                <div className="muted">{fmtNumber(found)} blocks</div>
              </div>
            ))}
            {(!miners.top_miners || miners.top_miners.length === 0) && (
              <div className="muted">Tidak ada data miners.</div>
            )}
          </div>
        </div>
      </section>
    </main>
  );
};

export default Network;
