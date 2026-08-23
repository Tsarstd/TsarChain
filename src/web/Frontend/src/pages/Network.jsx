import { useEffect, useMemo, useState, useCallback } from "react";
import PropTypes from "prop-types";
import { ClickableValue } from "../components/search/SearchResults";
import { fetchNetwork } from "../api/explorer";
import { fmtBytes, fmtHashrate, fmtNumber, fmtTimestamp, fmtTsar, fmtAddress } from "../utils/format";
import { SkeletonNetwork } from "../components/common/SkeletonLoader";
import { LiveIndicator } from "../components/common/LiveIndicator";
import Identicon from "../components/common/Identicon";

import { 
  RiGlobalLine, 
  RiDashboardLine, 
  RiMoneyDollarCircleLine,
  RiDatabaseLine,
  RiMegaphoneFill,
  RiHistoryLine,
  RiDatabase2Fill,
  RiBarChartBoxLine,
  RiUserStarLine,
  RiTimerLine
} from "react-icons/ri";

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

const StatCard = ({ icon: Icon, label, value, subtext, type = "normal" }) => (
  <div className={`stat-card ${type}`}>
    <div className="stat-card-header">
      {Icon && <Icon className="stat-icon" />}
      <span className="stat-label">{label}</span>
    </div>
    <div className="stat-value">
      {value}
    </div>
    {subtext && <div className="stat-subtext">{subtext}</div>}
  </div>
);

StatCard.propTypes = {
  icon: PropTypes.elementType,
  label: PropTypes.string.isRequired,
  value: PropTypes.node,
  subtext: PropTypes.string,
  type: PropTypes.oneOf(["normal", "primary", "accent", "warning", "critical"]), 
};

const SectionHeader = ({ icon: Icon, title, subtitle }) => (
  <div className="section-header">
    <div className="section-title">
      {Icon && <Icon className="section-icon" />}
      <h2>{title}</h2>
    </div>
    {subtitle && <p className="section-subtitle">{subtitle}</p>}
  </div>
);

SectionHeader.propTypes = {
  icon: PropTypes.elementType,
  title: PropTypes.string.isRequired,
  subtitle: PropTypes.string,
};

const InfoSection = ({ children, title, icon, cols = 2 }) => (
  <div className="info-section">
    <SectionHeader icon={icon} title={title} />
    <div className={`info-grid cols-${cols}`}>
      {children}
    </div>
  </div>
);

InfoSection.propTypes = {
  children: PropTypes.node.isRequired,
  title: PropTypes.string.isRequired,
  icon: PropTypes.elementType,
  cols: PropTypes.number,
};

const HashDisplay = ({ hash, label, onSearchClick, clickable = true }) => (
  <div className="hash-display">
    <span className="hash-label">{label}</span>
    <div className="hash-value mono wrap">
      {clickable && hash ? (
        <ClickableValue value={hash} onSearchClick={onSearchClick}>
          {hash}
        </ClickableValue>
      ) : (
        hash || "-"
      )}
    </div>
  </div>
);

HashDisplay.propTypes = {
  hash: PropTypes.string,
  label: PropTypes.string.isRequired,
  onSearchClick: PropTypes.func,
  clickable: PropTypes.bool,
};

// Studio tailored Tokenomics Supply Progress Meter
const SupplyProgressMeter = ({ circulating, maxSupply }) => {
  if (!maxSupply || maxSupply <= 0) return null;
  const circNum = Number(circulating || 0);
  const maxNum = Number(maxSupply || 1);
  const pct = Math.min(100, Math.max(0, (circNum / maxNum) * 100));

  return (
    <div className="supply-progress-card glass-panel" style={{ gridColumn: '1 / -1', padding: '18px 20px', borderRadius: '4px', marginTop: '6px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
        <span style={{ fontSize: '0.85rem', fontFamily: 'var(--font-newspaper)', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--color-tsar-cream)' }}>
          Circulating Supply Progress
        </span>
        <span style={{ fontSize: '0.95rem', fontFamily: 'var(--font-newspaper)', fontWeight: 700, color: 'var(--color-tsar-orange)' }}>
          {pct.toFixed(2)}% Mined
        </span>
      </div>
      <div style={{ height: '10px', background: '#121212', borderRadius: '2px', overflow: 'hidden', border: '1px solid rgba(255, 248, 240, 0.15)', boxShadow: 'inset 0 1px 3px rgba(0,0,0,0.8)' }}>
        <div 
          style={{ 
            height: '100%', 
            width: `${pct}%`, 
            background: 'linear-gradient(90deg, var(--color-tsar-orange) 0%, #ff7a45 50%, var(--color-tsar-cream) 100%)',
            borderRadius: '2px',
            boxShadow: '0 0 8px rgba(222, 85, 38, 0.5)',
            transition: 'width 0.8s ease-in-out' 
          }} 
        />
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', color: 'rgba(255, 248, 240, 0.65)', marginTop: '8px', fontFamily: 'monospace' }}>
        <span>Circulating: {fmtTsar(circulating)}</span>
        <span>Max Cap: {fmtTsar(maxSupply)}</span>
      </div>
    </div>
  );
};

SupplyProgressMeter.propTypes = {
  circulating: PropTypes.oneOfType([PropTypes.number, PropTypes.string]),
  maxSupply: PropTypes.oneOfType([PropTypes.number, PropTypes.string]),
};

const Network = ({ onSearchClick }) => {
  const [snap, setSnap] = useState(null);
  const [status, setStatus] = useState("loading");
  const [message, setMessage] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [isLive, setIsLive] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const loadData = useCallback(() => {
    return fetchNetwork()
      .then((resp) => {
        setSnap(resp.data || null);
        setStatus("done");
        setLastUpdated(new Date());
      })
      .catch((err) => {
        setMessage(err.message || "Failed to load network telemetry.");
        setStatus((prevStatus) => (prevStatus === "loading" ? "error" : prevStatus));
      });
  }, []);

  const handleRefresh = useCallback(async () => {
    setIsRefreshing(true);
    try {
      await loadData();
    } finally {
      setIsRefreshing(false);
    }
  }, [loadData]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    if (!isLive) return;
    const interval = setInterval(() => {
      handleRefresh();
    }, 30000);
    return () => clearInterval(interval);
  }, [isLive, handleRefresh]);

  const view = useMemo(() => normalizeSnapshot(snap), [snap]);

  if (status === "loading") {
    return (
      <main className="page-network">
        <SkeletonNetwork />
      </main>
    );
  }

  if (status === "error" || !view) {
    return (
      <main className="page">
        <div className="error-container">
          <div className="error-icon">⚠️</div>
          <div className="error-message">{message || "Network info not available."}</div>
          <button 
            type="button"
            className="retry-button"
            onClick={() => globalThis.location.reload()}
          >
            Retry
          </button>
        </div>
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

  // Adaptive network health status
  let networkHealth;
  let statusText;

  if (peersCount >= 3 || (peersCount >= 1 && chain.tip_height > 0)) {
    networkHealth = "healthy";
    statusText = peersCount > 5 ? "Operational" : `Devnet (${peersCount} Peers)`;
  } else if (peersCount > 0) {
    networkHealth = "warning";
    statusText = "Syncing Node";
  } else {
    networkHealth = "warning";
    statusText = "Standalone Node";
  }

  return (
    <main className="page-network">
      {/* Header dengan status network */}
      <header className="network-header">
        <div className="header-content">
          <div className="header-title">
            <h1>Network Overview</h1>
          </div>
          <div className="header-status" style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <LiveIndicator
              isLive={isLive}
              onToggleLive={() => setIsLive(prev => !prev)}
              onRefresh={handleRefresh}
              lastUpdated={lastUpdated}
              isRefreshing={isRefreshing}
              intervalSec={30}
              label="Live Sync"
            />
            <div className={`status-indicator ${networkHealth}`}>
              <div className="status-dot"></div>
              <span className="status-text">
                {statusText}
              </span>
            </div>
          </div>
        </div>

        {/* Summary stats bar */}
        <div className="summary-bar">
          <div className="summary-stat">
            <span className="summary-label">Height</span>
            <span className="summary-value highlight">{fmtNumber(chain.tip_height)}</span>
          </div>
          <div className="summary-stat">
            <span className="summary-label">Peers</span>
            <span className="summary-value">{fmtNumber(peersCount)}</span>
          </div>
          <div className="summary-stat">
            <span className="summary-label">Hashrate</span>
            <span className="summary-value">{fmtHashrate(chain.est_network_hashrate_hps_window)}</span>
          </div>
          <div className="summary-stat">
            <span className="summary-label">Circulating Supply</span>
            <span className="summary-value">{fmtTsar(supply.circulating_estimate)}</span>
          </div>
        </div>
      </header>

      {/* Blockchain Data */}
      <div className="hash-section">
        <HashDisplay 
          hash={chain.tip_hash} 
          label="Current Tip Hash"
          onSearchClick={onSearchClick}
        />
        <HashDisplay 
          hash={chain.tip_target_hex} 
          label="Current Target"
          clickable={false}
        />
      </div>

      <div className="divider" />

      <div className="network-content">
        {/* Network Identity */}
        <InfoSection title="Network Identity" icon={RiGlobalLine} cols={2}>
          <StatCard
            label="Network ID"
            value={view.identity?.network_id || "-"}
            subtext="Unique network identifier"
          />
          <StatCard
            label="Network Magic"
            value={view.identity?.network_magic_hex || "-"}
            subtext="Hex representation"
          />
          <StatCard
            label="Address Prefix"
            value={view.identity?.address_prefix || "-"}
            subtext="Address format prefix"
          />
          <StatCard
            label="Schema Version"
            value={view.schema_version ?? "-"}
            subtext="Data schema version"
          />
        </InfoSection>

        {/* Genesis Information */}
        <InfoSection title="Genesis Information" icon={RiHistoryLine}>
          <div className="full-width">
            <HashDisplay 
              hash={chain.genesis_hash}
              label="Genesis Hash"
              onSearchClick={onSearchClick}
            />
          </div>
          <div className="full-width">
            <div className="genesis-message">
              <span className="genesis-label">Genesis Message</span>
              <div className="genesis-text">{chain.genesis_message || "-"}</div>
            </div>
          </div>
        </InfoSection>

        {/* Network Activity */}
        <InfoSection title="Network Activity" icon={RiDashboardLine} cols={3}>
          <StatCard
            icon={RiTimerLine}
            label="Current Height"
            value={fmtNumber(chain.tip_height)}
            subtext={`Timestamp: ${fmtTimestamp(chain.tip_timestamp)}`}
            type="primary"
          />
          <StatCard
            label="Difficulty"
            value={fmtNumber(chain.tip_difficulty)}
            subtext="Current mining difficulty"
          />
          <StatCard
            label="Hashrate"
            value={fmtHashrate(chain.est_network_hashrate_hps_window)}
            subtext="Estimated network hashrate"
          />
          <StatCard
            label="Block Time"
            value={`${chain.avg_block_time_sec_window ?? "-"}s`}
            subtext="Average block time"
          />
          <StatCard
            label="Tip Bits"
            value={chain.tip_bits ?? "-"}
            subtext="Current block bits"
          />
        </InfoSection>

        {/* Tokenomics */}
        <InfoSection title="Tokenomics" icon={RiMoneyDollarCircleLine} cols={3}>
          <StatCard
            label="Max Supply"
            value={fmtTsar(supply.max_supply)}
            subtext="Total possible supply"
            type="primary"
          />
          <StatCard
            label="Circulating"
            value={fmtTsar(supply.circulating_estimate)}
            subtext="Currently in circulation"
          />
          <StatCard
            label="Emitted Subsidy"
            value={fmtTsar(supply.emitted_subsidy)}
            subtext="Total emitted subsidy"
          />
          <StatCard
            label="Immature Coinbase"
            value={fmtTsar(supply.immature_coinbase)}
            subtext="Awaiting maturity"
          />
          <StatCard
            label="Pool Balances"
            value={fmtTsar(graffiti.pool_balances)}
            subtext="Total storage pool balances"
          />
          <StatCard
            label="Total Fees"
            value={fmtTsar(txs.total_fees_paid)}
            subtext="All-time fees paid"
          />
          <SupplyProgressMeter
            circulating={supply.circulating_estimate}
            maxSupply={supply.max_supply}
          />
        </InfoSection>

        {/* Halving Information */}
        <InfoSection title="Halving Schedule" icon={RiBarChartBoxLine} cols={3}>
          <StatCard
            label="Current Epoch"
            value={fmtNumber(supply.current_epoch)}
            subtext="Current halving epoch"
            type="accent"
          />
          <StatCard
            label="Halving Height"
            value={fmtNumber(supply.next_halving_height)}
            subtext="Block height for next halving"
          />
          <StatCard
            label="Blocks Remaining"
            value={fmtNumber(supply.blocks_to_halving)}
            subtext="Blocks until next halving"
          />
        </InfoSection>

        {/* Mempool & Transactions */}
        <div className="two-column">
          <InfoSection title="Transactions & Mempool" icon={RiDatabaseLine}>
            <StatCard
              label="Total Transactions"
              value={fmtNumber(txs.total_txs)}
              subtext="All-time transactions"
            />
            <StatCard
              label="Non-Coinbase Txs"
              value={fmtNumber(txs.total_non_coinbase_txs ?? txs.total_txs)}
              subtext="Regular transactions"
            />
            <StatCard
              label="Mempool Size"
              value={fmtNumber(txs.mempool_vbytes_estimate)}
              subtext="Virtual bytes estimate"
            />
            <StatCard
              label="Pending Transactions"
              value={fmtNumber(txs.mempool_txs)}
              subtext="Transactions in mempool"
            />
          </InfoSection>

          <InfoSection title="Graffiti Activity" icon={RiMegaphoneFill}>
            <StatCard
              label="Graffiti Post"
              value={`${fmtNumber(graffiti.posts)}`}
              subtext="All-time graffiti post"
            />
            <StatCard
              label="Graffiti Comment"
              value={`${fmtNumber(graffiti.comments)}`}
              subtext="All-time comments activity"
            />
            <StatCard
              label="Graffiti Payouts"
              value={`${fmtNumber(graffiti.payouts)}`}
              subtext="All-time payouts activity"
            />
            <StatCard
              label="Pending Graffiti"
              value={fmtNumber(graffiti.graffiti_on_mempool)}
              subtext="Graffiti in mempool"
            />
          </InfoSection>
        </div>

        {/* Database Stats */}
        <InfoSection title="Database Statistics" icon={RiDatabase2Fill} cols={4}>
          <StatCard
            label="Total Blocks"
            value={fmtNumber(chain.total_blocks)}
            subtext="All blocks in chain"
          />
          <StatCard
            label="UTXO Set"
            value={fmtNumber(utxo.utxo_set_size)}
            subtext="Unspent transaction outputs"
          />
          <StatCard
            label="Total Block Size"
            value={fmtBytes(chain.total_block_size_bytes)}
            subtext="Cumulative block storage"
          />
          <StatCard
            label="Graffiti Storage"
            value={fmtBytes(graffiti.total_graffiti_storage)}
            subtext="Total graffiti data stored"
          />
        </InfoSection>

        {/* Top Miners with Identicons */}
        <InfoSection title="Top #10 Miners" icon={RiUserStarLine}>
          <div className="miners-table full-width">
            <div className="table-header">
              <div className="table-col rank">Rank</div>
              <div className="table-col address">Miner Address</div>
              <div className="table-col blocks">Blocks Found</div>
            </div>
            {(miners.top_miners || []).slice(0, 10).map(([addr, found], idx) => (
              <div className="table-row" key={`${addr}-${idx}`}>
                <div className="table-col rank">
                  <div className="rank-badge">{idx + 1}</div>
                </div>
                <div className="table-col address">
                  <div className="miner-address-wrap">
                    <Identicon value={addr} size={24} />
                    <ClickableValue
                      value={addr}
                      onSearchClick={onSearchClick}
                      className="value muted"
                      info={addr}
                    >
                      {fmtAddress(addr) || "-"}
                    </ClickableValue>
                  </div>
                </div>
                <div className="table-col blocks">
                  <span className="block-count">{fmtNumber(found)}</span>
                </div>
              </div>
            ))}
            {(!miners.top_miners || miners.top_miners.length === 0) && (
              <div className="table-empty">No miner data available</div>
            )}
          </div>
        </InfoSection>
      </div>
    </main>
  );
};

Network.propTypes = {
  onSearchClick: PropTypes.func,
};

export default Network;