import { useEffect, useState } from "react";
import PropTypes from "prop-types";
import { motion } from "motion/react";
import { fetchNetwork } from "../../api/explorer";
import { fmtNumber, fmtHashrate } from "../../utils/format";
import { RiDatabase2Line, RiCpuLine, RiBrushLine, RiHardDrive2Line } from "react-icons/ri";

const TelemetryTicker = ({ initialData }) => {
  const [data, setData] = useState(initialData || null);

  useEffect(() => {
    let isMounted = true;
    const load = async () => {
      try {
        const resp = await fetchNetwork();
        if (isMounted && resp) {
          setData(resp.data || resp);
        }
      } catch (err) {
        console.warn("Failed to fetch live network ticker:", err);
      }
    };

    load();
    const interval = setInterval(load, 15000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const height = data?.chain?.tip_height ?? data?.tip_height ?? null;
  const graffitiCount = data?.graffiti?.posts ?? data?.graffiti_posts ?? null;
  const difficulty = data?.chain?.tip_difficulty ?? data?.difficulty ?? null;
  const hashrate = data?.chain?.est_network_hashrate_hps_window ?? (data ? 0 : null);

  return (
    <motion.div 
      className="telemetry-ticker"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.2 }}
    >
      <div className="ticker-item">
        <span className="ticker-label">
          <RiDatabase2Line /> Tip Height
        </span>
        <div className="ticker-value">
          <span>{fmtNumber(height)}</span>
        </div>
      </div>

      <div className="ticker-item">
        <span className="ticker-label">
          <RiBrushLine /> Total Graffiti
        </span>
        <div className="ticker-value">
          <span>{fmtNumber(graffitiCount)}</span>
        </div>
      </div>

      <div className="ticker-item">
        <span className="ticker-label">
          <RiCpuLine /> Tip Difficulty
        </span>
        <div className="ticker-value">
          <span>{fmtNumber(difficulty)}</span>
        </div>
      </div>

      <div className="ticker-item">
        <span className="ticker-label">
          <RiHardDrive2Line /> Hashrate
        </span>
        <div className="ticker-value">
          <span>{fmtHashrate(hashrate)}</span>
        </div>
      </div>
    </motion.div>
  );
};

TelemetryTicker.propTypes = {
  initialData: PropTypes.object,
};

export default TelemetryTicker;
