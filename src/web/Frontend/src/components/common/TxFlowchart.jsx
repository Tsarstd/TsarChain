import { useMemo, useState } from "react";
import PropTypes from "prop-types";
import { FaArrowRight, FaCoins, FaExchangeAlt, FaShieldAlt, FaExternalLinkAlt } from "react-icons/fa";
import { RiNodeTree, RiSparklingLine } from "react-icons/ri";
import { fmtTsar, fmtAddress } from "../../utils/format";

const getOutputTagClass = (item) => {
  if (item.isChange) {
    return "tag-change";
  }
  if (item.isOpReturn) {
    return "tag-opreturn";
  }
  return "tag-recipient";
};

export const TxFlowchart = ({ data, onSearchClick }) => {
  const [hoveredNode, setHoveredNode] = useState(null);
  const [collapsed, setCollapsed] = useState(false);

  const isCoinbase = Boolean(data?.is_coinbase || data?.inputs?.[0]?.is_coinbase);

  // Group or map inputs
  const inputsList = useMemo(() => {
    if (isCoinbase) {
      return [
        {
          id: "coinbase-input",
          label: "Coinbase / Block Reward",
          address: "Block Coinbase Subsidy",
          amount: data?.total_out || data?.outputs?.reduce((acc, o) => acc + (o.amount || 0), 0) || 0,
          isCoinbase: true,
        },
      ];
    }

    if (!data?.inputs || data.inputs.length === 0) {
      return [
        {
          id: "unknown-input",
          label: "Unknown Sender",
          address: "Unknown Address",
          amount: data?.total_in || 0,
          isCoinbase: false,
        },
      ];
    }

    return data.inputs.map((inp, idx) => ({
      id: `in-${inp.address || "unknown"}-${idx}`,
      label: `Input #${idx}`,
      address: inp.address || "Unknown Address",
      amount: inp.amount || 0,
      prevTxid: inp.txid,
      isCoinbase: Boolean(inp.is_coinbase),
    }));
  }, [data, isCoinbase]);

  // Group or map outputs
  const inputAddressSet = useMemo(() => {
    return new Set(data?.inputs?.map((i) => i.address).filter(Boolean) || []);
  }, [data?.inputs]);

  const outputsList = useMemo(() => {
    if (!data?.outputs || data.outputs.length === 0) {
      return [];
    }

    return data.outputs.map((out, idx) => {
      const addr = out?.address;
      const isOpReturn = !addr || addr === "OP_RETURN";
      const isChange = !isOpReturn && inputAddressSet.has(addr);

      let tag = "Recipient";
      if (isOpReturn) tag = "Graffiti / Script";
      else if (isChange) tag = "Change";

      return {
        id: `out-${addr || "op_return"}-${idx}`,
        vout: out?.index ?? idx,
        address: isOpReturn ? "OP_RETURN Data" : addr,
        amount: out?.amount || 0,
        tag,
        isOpReturn,
        isChange,
        event: out?.event,
      };
    });
  }, [data?.outputs, inputAddressSet]);

  const totalIn = data?.total_in ?? inputsList.reduce((sum, i) => sum + (i.amount || 0), 0);
  const totalOut = data?.total_out ?? outputsList.reduce((sum, o) => sum + (o.amount || 0), 0);
  const fee = data?.fee ?? (totalIn > totalOut ? totalIn - totalOut : 0);

  const handleAddrClick = (addr) => {
    if (addr && !addr.includes("Coinbase") && !addr.includes("OP_RETURN") && onSearchClick) {
      onSearchClick(addr);
    }
  };

  return (
    <div className="utxo-flowchart-card glass-panel">
      {/* Header Bar */}
      <div className="utxo-flowchart-header">
        <div className="utxo-header-title">
          <RiNodeTree className="utxo-header-icon" />
          <div>
            <h4>UTXO Transaction Flowchart</h4>
          </div>
        </div>
        <div className="utxo-header-controls">
          <button
            type="button"
            className="utxo-toggle-btn"
            onClick={() => setCollapsed(!collapsed)}
            title={collapsed ? "Expand flowchart" : "Collapse flowchart"}
          >
            {collapsed ? "Show Visualizer" : "Hide Visualizer"}
          </button>
        </div>
      </div>

      {!collapsed && (
        <div className="utxo-flowchart-body">
          {/* Main Diagram Columns */}
          <div className="utxo-flow-diagram">
            {/* COLUMN 1: INPUTS */}
            <div className="utxo-column utxo-column--inputs">
              <div className="utxo-column-header">
                <span className="col-badge input-badge">INPUTS ({inputsList.length})</span>
              </div>
              <div className="utxo-nodes-stack">
                {inputsList.map((item) => (
                  <div
                    key={item.id}
                    className={`utxo-node utxo-node--input ${
                      hoveredNode === item.id ? "hovered" : ""
                    } ${item.isCoinbase ? "coinbase" : ""}`}
                    onMouseEnter={() => setHoveredNode(item.id)}
                    onMouseLeave={() => setHoveredNode(null)}
                  >
                    <div className="node-top">
                      <span className="node-tag">
                        {item.isCoinbase ? (
                          <>
                            <FaCoins className="tag-icon" /> Coinbase
                          </>
                        ) : (
                          item.label
                        )}
                      </span>
                      <span className="node-amount">{fmtTsar(item.amount)}</span>
                    </div>

                    {!item.isCoinbase && onSearchClick ? (
                      <button
                        type="button"
                        className="node-address clickable"
                        onClick={() => handleAddrClick(item.address)}
                        title={`Search address ${item.address}`}
                      >
                        <span>{fmtAddress(item.address, 8, 6)}</span>
                        <FaExternalLinkAlt className="ext-icon" />
                      </button>
                    ) : (
                      <div className="node-address" title={item.address}>
                        <span>{fmtAddress(item.address, 8, 6)}</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* FLOW INDICATOR 1 */}
            <div className="utxo-flow-connector">
              <div className="connector-line">
                <div className="flow-pulse" />
              </div>
              <FaArrowRight className="connector-arrow" />
            </div>

            {/* COLUMN 2: TRANSACTION CORE HUB */}
            <div className="utxo-column utxo-column--core">
              <div className="utxo-core-node glass-panel">
                <div className="core-icon-wrap">
                  <FaExchangeAlt className="core-icon" />
                </div>
                <h5 className="core-title">TX Core Hub</h5>
                <span className="core-txid" title={data?.txid}>
                  {fmtAddress(data?.txid || "TxID", 6, 6)}
                </span>

                <div className="core-metrics">
                  <div className="core-metric-item">
                    <span className="metric-lbl">Total Volume</span>
                    <span className="metric-val text-cyan">{fmtTsar(totalOut)}</span>
                  </div>
                  {!isCoinbase && (
                    <div className="core-metric-item">
                      <span className="metric-lbl">Network Fee</span>
                      <span className="metric-val text-amber">{fmtTsar(fee)}</span>
                    </div>
                  )}
                  <div className="core-metric-item">
                    <span className="metric-lbl">Status</span>
                    <span
                      className={`status-pill ${
                        data?.status === "confirmed" ? "confirmed" : "pending"
                      }`}
                    >
                      <FaShieldAlt className="status-ic" />
                      {data?.status?.toUpperCase() || "CONFIRMED"}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* FLOW INDICATOR 2 */}
            <div className="utxo-flow-connector">
              <div className="connector-line">
                <div className="flow-pulse" />
              </div>
              <FaArrowRight className="connector-arrow" />
            </div>

            {/* COLUMN 3: OUTPUTS */}
            <div className="utxo-column utxo-column--outputs">
              <div className="utxo-column-header">
                <span className="col-badge output-badge">OUTPUTS ({outputsList.length})</span>
                <span className="col-total">Total: {fmtTsar(totalOut)}</span>
              </div>
              <div className="utxo-nodes-stack">
                {outputsList.map((item) => (
                  <div
                    key={item.id}
                    className={`utxo-node utxo-node--output ${
                      hoveredNode === item.id ? "hovered" : ""
                    } ${item.isOpReturn ? "opreturn" : ""} ${item.isChange ? "change" : ""}`}
                    onMouseEnter={() => setHoveredNode(item.id)}
                    onMouseLeave={() => setHoveredNode(null)}
                  >
                    <div className="node-top">
                      <span className={`node-tag ${getOutputTagClass(item)}`}>
                        {item.isOpReturn ? (
                          <>
                            <RiSparklingLine className="tag-icon" /> {item.tag}
                          </>
                        ) : (
                          item.tag
                        )}
                        {item.event && <span className="event-badge">{item.event}</span>}
                      </span>
                      <span className="node-amount">{fmtTsar(item.amount)}</span>
                    </div>

                    {!item.isOpReturn && onSearchClick ? (
                      <button
                        type="button"
                        className="node-address clickable"
                        onClick={() => handleAddrClick(item.address)}
                        title={`Search address ${item.address}`}
                      >
                        <span>vout {item.vout}: {fmtAddress(item.address, 8, 6)}</span>
                        <FaExternalLinkAlt className="ext-icon" />
                      </button>
                    ) : (
                      <div className="node-address" title={item.address}>
                        <span>vout {item.vout}: {fmtAddress(item.address, 8, 6)}</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

TxFlowchart.propTypes = {
  data: PropTypes.shape({
    txid: PropTypes.string,
    is_coinbase: PropTypes.bool,
    status: PropTypes.string,
    confirmations: PropTypes.number,
    total_in: PropTypes.number,
    total_out: PropTypes.number,
    fee: PropTypes.number,
    inputs: PropTypes.array,
    outputs: PropTypes.array,
  }),
  onSearchClick: PropTypes.func,
};
