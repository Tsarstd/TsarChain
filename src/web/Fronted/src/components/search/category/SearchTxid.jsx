import { ClickableValue } from ".././SearchResults";
import { fmtTsar } from "../../../utils/format"
import { getVoutLabel, getAddressType } from "../SearchUX";
import "../search.css";
import "../label.css";

const ResultTx = ({ data, onSearchClick }) => (
  <div className="card">
    <span className="txid-details">{data?.txid || "-"}</span>
    <div className="divider" />
    
    <div className="grid">
      <div className="stat">
        <span className="info-label">Status</span>
        <span className="value">{data?.status || "-"}</span>
      </div>
      <div className="stat">
        <span className="info-label">Block</span>
        <span className="value">
          {!data?.block_height && data?.block_height !== 0 ? "0" : 
          data?.block_height === "-" ? "Genesis (0)" :
          data?.block_height}
        </span>
      </div>
      <div className="stat">
        <span className="info-label">Confirmations</span>
        <span className="value">{data?.confirmations ?? 0}</span>
      </div>
      <div className="stat">
        <span className="info-label">Fee</span>
        <span className="value">{fmtTsar(data?.fee || 0)}</span>
      </div>
      <div className="stat">
        <span className="info-label">Coinbase</span>
        <span className="value">{data?.is_coinbase ? "Yes" : "No"}</span>
      </div>
    </div>
    <div className="divider2" />
    <div className="stat">
      <span className="value">Inputs {data?.inputs?.length || 0}</span>
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
            <div className="grid">
              <div className="tx-info">
                <div className="stat">
                  <ClickableValue value={inp.address} onSearchClick={onSearchClick} className="value muted">
                    {inp.address || "-"}
                  </ClickableValue>
                </div>

                <div className="stat">
                  <ClickableValue value={inp.txid ? `${inp.txid}` : "-"} onSearchClick={onSearchClick} className="value muted">
                    {inp.txid ? `${inp.txid}` : "-"}
                  </ClickableValue>
                  <div className="tx-amount">{fmtTsar(inp.amount)}</div>
                </div>
              </div>
            </div>
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
    <div className="divider2" />
    <div className="stat">
      <span className="value">Outputs {data?.outputs?.length || 0}</span>
    </div>
    <div className="list">
      {(data?.outputs || []).map((out, idx) => {
        const vout = typeof out?.vout === "number" ? out.vout : idx;
        const voutLabel = getVoutLabel(vout);
        const addressValue = out?.address || "";
        const addressType = addressValue
          ? getAddressType(addressValue)
          : { type: "opreturn", label: "Graffiti Script" };

        return (
          <div className="tx-items" key={idx}>
            <div className="label mono wrap">
              <ClickableValue value={addressValue} onSearchClick={onSearchClick} className="value muted">
                {addressValue || "OP_RETURN"}
              </ClickableValue>
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

export { ResultTx }