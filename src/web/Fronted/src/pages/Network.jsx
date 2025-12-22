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
        <h1 className="sub-header">./network_identity</h1>
      </section>
      <section className="card">
        <InfoGrid
          items={[
            { label: "Last Update", value: fmtLastUpdate(view.last_updated)},
            { label: "Schema Version", value: (view.schema_version ?? "-")},
            { label: "Peers", value: fmtNumber(peersCount)},
            { label: "Network ID", value: view.identity?.network_id || "-"},
            { label: "Network Magic", value: view.identity?.network_magic_hex || "-"},
          ]}
        />
      </section>
      <section className="section card network-summary">
        <InfoGrid
          items={[
            { label: "Genesis Hash", value: <span className="mono">{chain.genesis_hash || "-"}</span> },
          ]}
        />
      </section>
      <section className="section card network-summary">
        <InfoGrid
          items={[
            { label: "Genesis Message", value: chain.genesis_message || "-" },
          ]}
        />
      </section>
      <section className="section card network-summary">
        <InfoGrid
          items={[
            { label: "Address Prefix", value: view.identity?.address_prefix || "-" },
            { label: "Coinbase Maturity Rule", value: `${supply.coinbase_maturity ?? "-"} Block` },
            { label: "Coinbase Reward", value: fmtTsar(chain.current_block_subsidy || supply.current_block_subsidy) },
          ]}
        />
      </section>

      <section className="section">
        <h1 className="sub-header">./network_activity</h1>
      </section>
      <section className="card">
        <InfoGrid
          items={[
            { label: "Tip Timestamp", value: fmtTimestamp(chain.tip_timestamp) },
            { label: "Tip Height", value: fmtNumber(chain.tip_height) },
            { label: "Tip Bits", value: chain.tip_bits ?? "-" },
            { label: "Tip Difficulty", value: fmtNumber(chain.tip_difficulty) },
            { label: "Network Hashrate", value: fmtHashrate(chain.est_network_hashrate_hps_window) },
            { label: "Average Block Time", value: `${chain.avg_block_time_sec_window ?? "-"} s` },
          ]}
        />
      </section>
      <section className="section card network-summary">
        <InfoGrid
          items={[
            { label: "Tip Hash", value: <span className="mono wrap">{chain.tip_hash || "-"}</span> },
          ]}
        />
      </section>
      <section className="section card network-summary">
        <InfoGrid
          items={[
            { label: "Tip Target", value: <span className="mono wrap">{chain.tip_target_hex || "-"}</span> },
          ]}
        />
      </section>
      <section className="section">
        <h1 className="sub-header">./tokenomics</h1>
      </section>
      <section className="card">
        <InfoGrid
          items={[
            { label: "Max Supply", value: fmtTsar(supply.max_supply) },
            { label: "Circulating Supply", value: fmtTsar(supply.circulating_estimate) },
            { label: "Immature Coinbase", value: fmtTsar(supply.immature_coinbase) },
            { label: "Emitted Subsidy", value: fmtTsar(supply.emitted_subsidy) },
            { label: "Pool Balances", value: fmtTsar(graffiti.pool_balances) },
            { label: "Total Fees Paid", value: fmtTsar(txs.total_fees_paid) },
          ]}
        />
      </section>

      <section className="section">
        <h1 className="sub-header">./mempool</h1>
      </section>
      <section className="card">
        <InfoGrid
          items={[
            { label: "Transactions on Mempool", value: fmtNumber(txs.mempool_txs) },
            { label: "Graffiti on Mempool", value: fmtNumber(graffiti.graffiti_on_mempool) },
            { label: "Mempool VBytes", value: fmtNumber(txs.mempool_vbytes_estimate) },
          ]}
        />
      </section>

      <section className="section">
        <h1 className="sub-header">./halving</h1>
      </section>
      <section className="card">
        <InfoGrid
          items={[
            { label: "Halving Height", value: fmtNumber(supply.next_halving_height) },
            { label: "Blocks To Halving", value: fmtNumber(supply.blocks_to_halving) },
            { label: "Current Epoch", value: fmtNumber(supply.current_epoch) },
          ]}
        />
      </section>

      <section className="section">
        <h1 className="sub-header">./transactions</h1>
      </section>
      <section className="card">
        <InfoGrid
          items={[
            { label: "Total Transactions", value: fmtNumber(txs.total_txs) },
            { label: "Non-Coinbase Txs", value: fmtNumber(txs.total_non_coinbase_txs ?? txs.total_txs) },
            { label: "Total Graffiti", value: fmtNumber(graffiti.posts) },
            { label: "Total Comments", value: fmtNumber(graffiti.comments) },
            { label: "Total Archivist Payouts", value: fmtNumber(graffiti.payouts) },
          ]}
        />
      </section>

      <section className="section">
        <h1 className="sub-header">./database</h1>
      </section>
      <section className="card">
        <InfoGrid
          items={[
            { label: "Total Blocks", value: fmtNumber(chain.total_blocks) },
            { label: "UTXO Set", value: fmtNumber(utxo.utxo_set_size) },
            { label: "Total Block Size", value: fmtBytes(chain.total_block_size_bytes) },
            { label: "Total Graffiti Storage", value: fmtBytes(graffiti.total_graffiti_storage) },
          ]}
        />
      </section>

      <section className="section">
        <h1 className="sub-header">./top_miners</h1>
      </section>
      <section className="card">
        <div className="list">
          {(miners.top_miners || []).slice(0, 10).map(([addr, found], idx) => (
            <div className="tx-item" key={`${addr}-${idx}`}>
              <div className="label">Rank #{idx + 1}</div>
              <div className="value mono wrap">{addr}</div>
              <div className="muted">{fmtNumber(found)} blocks</div>
            </div>
          ))}
          {(!miners.top_miners || miners.top_miners.length === 0) && (
            <div className="muted">Tidak ada data miners.</div>
          )}
        </div>
      </section>
    </main>
  );
};

export default Network;
