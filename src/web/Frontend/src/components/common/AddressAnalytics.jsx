import { useMemo } from "react";
import PropTypes from "prop-types";
import { FaCoins, FaPalette, FaComments, FaHandHoldingUsd } from "react-icons/fa";
import { RiBarChartFill } from "react-icons/ri";
import { fmtTsar } from "../../utils/format";

// Global configurable thresholds for Persona Badges
export const PERSONA_THRESHOLDS = {
  GRAFFITI_CREATOR: 15,    // Minimal 15 Graffiti POSTs
  GRAFFITI_COMMENTER: 25,  // Minimal 25 Graffiti COMMENTs
  ROYALTY_EARNER: 25,      // Minimal 25 Graffiti PAYOUTs
  NETWORK_MINER: 30,       // Minimal 30 Coinbase Mining Rewards
};

// Sub-component for rendering SVG Pie Chart with Legend & Totals
const PieChart = ({ title, items, totals = [], size = 180 }) => {
  const total = items.reduce((acc, item) => acc + (item.value || 0), 0);

  const cx = size / 2;
  const cy = size / 2;
  const radius = size * 0.4;
  const labelRadius = radius * 0.62;

  let cumulativeAngle = -90; // Start at top center (-90deg)

  const slices = items
    .filter((item) => item.value > 0)
    .map((item) => {
      const percentage = total > 0 ? (item.value / total) * 100 : 0;
      const angle = (percentage / 100) * 360;

      const startAngle = cumulativeAngle;
      const endAngle = cumulativeAngle + angle;
      const midAngle = startAngle + angle / 2;

      cumulativeAngle = endAngle;

      const startRad = (startAngle * Math.PI) / 180;
      const endRad = (endAngle * Math.PI) / 180;
      const midRad = (midAngle * Math.PI) / 180;

      const x1 = cx + radius * Math.cos(startRad);
      const y1 = cy + radius * Math.sin(startRad);
      const x2 = cx + radius * Math.cos(endRad);
      const y2 = cy + radius * Math.sin(endRad);

      const largeArcFlag = angle > 180 ? 1 : 0;

      const pathData =
        angle >= 359.99
          ? `M ${cx - radius} ${cy} A ${radius} ${radius} 0 1 0 ${cx + radius} ${cy} A ${radius} ${radius} 0 1 0 ${cx - radius} ${cy}`
          : `M ${cx} ${cy} L ${x1} ${y1} A ${radius} ${radius} 0 ${largeArcFlag} 1 ${x2} ${y2} Z`;

      const lx = cx + labelRadius * Math.cos(midRad);
      const ly = cy + labelRadius * Math.sin(midRad);

      return {
        ...item,
        percentage,
        pathData,
        lx,
        ly,
        showLabel: percentage >= 5,
      };
    });

  return (
    <div className="pie-chart-card">
      <h5 className="pie-chart-title">{title}</h5>
      <div className="pie-chart-body">
        <div className="pie-svg-container">
          {total === 0 ? (
            <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
              <circle
                cx={cx}
                cy={cy}
                r={radius}
                fill="none"
                stroke="rgba(255, 255, 255, 0.15)"
                strokeWidth="2"
                strokeDasharray="4 4"
              />
              <text
                x={cx}
                y={cy}
                textAnchor="middle"
                dominantBaseline="central"
                fill="#64748b"
                fontSize="12"
              >
                No Data
              </text>
            </svg>
          ) : (
            <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
              <g className="pie-slices">
                {slices.map((slice, i) => (
                  <g key={slice.id || i} className="pie-slice-group">
                    <path
                      d={slice.pathData}
                      fill={slice.color}
                      className="pie-slice-path"
                    >
                      <title>{`${slice.label}: ${slice.value} (${slice.percentage.toFixed(1)}%)`}</title>
                    </path>
                    {slice.showLabel && (
                      <text
                        x={slice.lx}
                        y={slice.ly}
                        textAnchor="middle"
                        dominantBaseline="central"
                        fill="#ffffff"
                        fontSize="11"
                        fontWeight="700"
                        className="pie-slice-text"
                      >
                        {`${Math.round(slice.percentage)}%`}
                      </text>
                    )}
                  </g>
                ))}
              </g>
            </svg>
          )}
        </div>

        {/* Legend Box */}
        <div className="pie-legend-box">
          <div className="pie-legend-header">Legend</div>
          <div className="pie-legend-list">
            {items.map((item) => {
              const pct = total > 0 ? ((item.value / total) * 100).toFixed(1) : "0.0";
              return (
                <div key={item.id} className="pie-legend-item">
                  <span
                    className="legend-color-badge"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="legend-label">{item.label}</span>
                  <span className="legend-value">{item.value} ({pct}%)</span>
                </div>
              );
            })}
          </div>

          {/* Totals Amount Section */}
          {totals.length > 0 && (
            <div className="pie-totals-section">
              <div className="pie-totals-header">Total</div>
              <div className="pie-totals-list">
                {totals.map((tot) => (
                  <div key={tot.id} className="pie-totals-item">
                    <span
                      className="legend-color-badge"
                      style={{ backgroundColor: tot.color }}
                    />
                    <span className="legend-label">{tot.label}</span>
                    <span className="totals-amount">{tot.amount}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

PieChart.propTypes = {
  title: PropTypes.string.isRequired,
  items: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.string.isRequired,
      label: PropTypes.string.isRequired,
      value: PropTypes.number.isRequired,
      color: PropTypes.string.isRequired,
    })
  ).isRequired,
  totals: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.string.isRequired,
      label: PropTypes.string.isRequired,
      amount: PropTypes.string.isRequired,
      color: PropTypes.string.isRequired,
    })
  ),
  size: PropTypes.number,
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

  const chart1Items = useMemo(
    () => [
      { id: "received", label: "Received", value: stats.receivedCount, color: "#10b981" },
      { id: "sent", label: "Sent", value: stats.sentCount, color: "#ef4444" },
    ],
    [stats.receivedCount, stats.sentCount]
  );

  const chart1Totals = useMemo(
    () => [
      { id: "received-amt", label: "Received", amount: fmtTsar(stats.receivedAmt), color: "#10b981" },
      { id: "sent-amt", label: "Sent", amount: fmtTsar(stats.sentAmt), color: "#ef4444" },
    ],
    [stats.receivedAmt, stats.sentAmt]
  );

  const chart2Items = useMemo(
    () => [
      { id: "mining", label: "Mining", value: stats.coinbaseCount, color: "#eab308" },
      { id: "posts", label: "Posts", value: stats.postCount, color: "#e66c26" },
      { id: "comments", label: "Comments", value: stats.commentCount, color: "#38bdf8" },
      { id: "payouts", label: "Payouts", value: stats.payoutCount, color: "#a855f7" },
    ],
    [stats.coinbaseCount, stats.postCount, stats.commentCount, stats.payoutCount]
  );

  const chart2Totals = useMemo(
    () => [
      { id: "mining-amt", label: "Mining", amount: fmtTsar(stats.coinbaseAmt), color: "#eab308" },
    ],
    [stats.coinbaseAmt]
  );

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

      {/* 2-Column Pie Charts with Legend & Totals */}
      <div className="analytics-charts-wrapper">
        <PieChart
          title="Transaction Flow (Received & Sent)"
          items={chart1Items}
          totals={chart1Totals}
        />
        <PieChart
          title="Network & Graffiti Activity"
          items={chart2Items}
          totals={chart2Totals}
        />
      </div>
    </div>
  );
};

AddressAnalytics.propTypes = {
  history: PropTypes.array,
  spendable: PropTypes.number,
  balance: PropTypes.number,
};
