import { useMemo } from "react";
import PropTypes from "prop-types";
import { FaCoins, FaArrowDown, FaArrowUp, FaPalette, FaComments, FaHandHoldingUsd } from "react-icons/fa";
import { RiBarChartFill } from "react-icons/ri";
import { fmtTsar } from "../../../utils/format";

// Global configurable thresholds for Persona Badges
export const PERSONA_THRESHOLDS = {
  GRAFFITI_CREATOR: 15,    // Minimal 15 Graffiti POSTs
  GRAFFITI_COMMENTER: 25,  // Minimal 25 Graffiti COMMENTs
  ROYALTY_EARNER: 25,      // Minimal 25 Graffiti PAYOUTs
  NETWORK_MINER: 30,       // Minimal 30 Coinbase Mining Rewards
};

export const AddressAnalytics = ({ history = [], spendable = 0, balance = 0 }) => {
  const stats = useMemo(() => {
    let receivedCount = 0;
    let receivedAmt = 0;
    let sentCount = 0;
    let sentAmt = 0;
    let coinbaseCount = 0;
    let coinbaseAmt = 0;
    let postCount = 0;
    let commentCount = 0;
    let payoutCount = 0;

    for (const item of history) {
      const isGraffiti = Boolean(item?.is_graffiti);
      const ev = (item?.event || "").toUpperCase();
      const dirn = item?.direction;
      const isCoinbase = item?.from === "coinbase" || item?.is_coinbase;
      const amt = item?.amount || 0;

      if (isGraffiti) {
        if (ev === "POST") postCount++;
        else if (ev === "COMMENT") commentCount++;
        else if (ev === "PAYOUT") payoutCount++;
      }

      if (isCoinbase) {
        coinbaseCount++;
        coinbaseAmt += amt;
      } else if (dirn === "in") {
        receivedCount++;
        receivedAmt += amt;
      } else if (dirn === "out") {
        sentCount++;
        sentAmt += amt;
      }
    }

    const totalTxs = history.length || 1;

    return {
      receivedCount,
      receivedAmt,
      sentCount,
      sentAmt,
      coinbaseCount,
      coinbaseAmt,
      postCount,
      commentCount,
      payoutCount,
      totalTxs: history.length,
      pctReceived: Math.round((receivedCount / totalTxs) * 100),
      pctSent: Math.round((sentCount / totalTxs) * 100),
      pctCoinbase: Math.round((coinbaseCount / totalTxs) * 100),
      pctPost: Math.round((postCount / totalTxs) * 100),
      pctComment: Math.round((commentCount / totalTxs) * 100),
      pctPayout: Math.round((payoutCount / totalTxs) * 100),
    };
  }, [history]);

  // Determine Persona Badges (Address can have multiple qualifying badges)
  const personaTags = useMemo(() => {
    const badges = [];

    if (stats.postCount >= PERSONA_THRESHOLDS.GRAFFITI_CREATOR) {
      badges.push({
        id: "creator",
        label: "Graffiti Creator",
        icon: <FaPalette />,
        color: "#e66c26",
      });
    }

    if (stats.commentCount >= PERSONA_THRESHOLDS.GRAFFITI_COMMENTER) {
      badges.push({
        id: "commenter",
        label: "Graffiti Commenter",
        icon: <FaComments />,
        color: "#38bdf8",
      });
    }

    if (stats.payoutCount >= PERSONA_THRESHOLDS.ROYALTY_EARNER) {
      badges.push({
        id: "earner",
        label: "The Archivist",
        icon: <FaHandHoldingUsd />,
        color: "#10b981",
      });
    }

    if (stats.coinbaseCount >= PERSONA_THRESHOLDS.NETWORK_MINER) {
      badges.push({
        id: "miner",
        label: "Network Miner",
        icon: <FaCoins />,
        color: "#eab308",
      });
    }

    return badges;
  }, [stats]);

  if (!history || history.length === 0) {
    return null;
  }

  return (
    <div className="address-analytics-card glass-panel">
      {/* Header Bar */}
      <div className="analytics-header">
        <div className="analytics-title-group">
          <RiBarChartFill className="analytics-icon" />
          <div>
            <h4>Address Flow & Graffiti Analytics</h4>
            <span className="analytics-subtitle">
              Portfolio Breakdown across recent {stats.totalTxs} transactions
            </span>
          </div>
        </div>
        {personaTags.length > 0 && (
          <div className="persona-badges-group">
            {personaTags.map((badge) => (
              <div
                key={badge.id}
                className="persona-badge"
                style={{ borderColor: badge.color, color: badge.color }}
              >
                <span className="persona-icon">{badge.icon}</span>
                <span>{badge.label}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Distribution Progress Meter */}
      <div className="analytics-meter-wrapper">
        <div className="analytics-meter-bar">
          {stats.pctReceived > 0 && (
            <div className="meter-seg seg-received" style={{ width: `${stats.pctReceived}%` }} title={`Received: ${stats.pctReceived}%`} />
          )}
          {stats.pctSent > 0 && (
            <div className="meter-seg seg-sent" style={{ width: `${stats.pctSent}%` }} title={`Sent: ${stats.pctSent}%`} />
          )}
          {stats.pctCoinbase > 0 && (
            <div className="meter-seg seg-coinbase" style={{ width: `${stats.pctCoinbase}%` }} title={`Coinbase Mining: ${stats.pctCoinbase}%`} />
          )}
          {stats.pctPost > 0 && (
            <div className="meter-seg seg-post" style={{ width: `${stats.pctPost}%` }} title={`Graffiti Posts: ${stats.pctPost}%`} />
          )}
          {stats.pctComment > 0 && (
            <div className="meter-seg seg-comment" style={{ width: `${stats.pctComment}%` }} title={`Graffiti Comments: ${stats.pctComment}%`} />
          )}
          {stats.pctPayout > 0 && (
            <div className="meter-seg seg-payout" style={{ width: `${stats.pctPayout}%` }} title={`Graffiti Payouts: ${stats.pctPayout}%`} />
          )}
        </div>
      </div>

      {/* 6 Grid Metric Cards */}
      <div className="analytics-grid">
        {/* 1. Received */}
        <div className="analytics-grid-card card-received">
          <div className="card-top">
            <span className="card-label"><FaArrowDown className="ic-in" /> Received</span>
            <span className="card-badge">{stats.receivedCount} txs</span>
          </div>
          <div className="card-value">{fmtTsar(stats.receivedAmt)}</div>
        </div>

        {/* 2. Sent */}
        <div className="analytics-grid-card card-sent">
          <div className="card-top">
            <span className="card-label"><FaArrowUp className="ic-out" /> Sent</span>
            <span className="card-badge">{stats.sentCount} txs</span>
          </div>
          <div className="card-value">{fmtTsar(stats.sentAmt)}</div>
        </div>

        {/* 3. Mining Coinbase */}
        <div className="analytics-grid-card card-coinbase">
          <div className="card-top">
            <span className="card-label"><FaCoins className="ic-coinbase" /> Mining Rewards</span>
            <span className="card-badge">{stats.coinbaseCount} txs</span>
          </div>
          <div className="card-value">{fmtTsar(stats.coinbaseAmt)}</div>
        </div>

        {/* 4. Graffiti Posts */}
        <div className="analytics-grid-card card-post">
          <div className="card-top">
            <span className="card-label"><FaPalette className="ic-post" /> Graffiti Posts</span>
            <span className="card-badge">{stats.postCount} created</span>
          </div>
          <div className="card-value">{stats.postCount} Art Achored</div>
        </div>

        {/* 5. Graffiti Comments */}
        <div className="analytics-grid-card card-comment">
          <div className="card-top">
            <span className="card-label"><FaComments className="ic-comment" /> Comments</span>
            <span className="card-badge">{stats.commentCount} posts</span>
          </div>
          <div className="card-value">{stats.commentCount} Comments</div>
        </div>

        {/* 6. Graffiti Payouts */}
        <div className="analytics-grid-card card-payout">
          <div className="card-top">
            <span className="card-label"><FaHandHoldingUsd className="ic-payout" /> Payouts</span>
            <span className="card-badge">{stats.payoutCount} payouts</span>
          </div>
          <div className="card-value">{stats.payoutCount} Earnings</div>
        </div>
      </div>
    </div>
  );
};

AddressAnalytics.propTypes = {
  history: PropTypes.array,
  spendable: PropTypes.number,
  balance: PropTypes.number,
};
