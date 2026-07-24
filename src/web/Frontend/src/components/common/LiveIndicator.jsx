import { useState, useEffect } from "react";
import PropTypes from "prop-types";
import { RiRefreshLine, RiPauseCircleLine, RiPlayCircleLine } from "react-icons/ri";

const renderSyncMeta = (refreshing, updated, secs) => {
  if (refreshing) {
    return <span className="syncing-text">Syncing latest data...</span>;
  }
  if (updated) {
    return `Updated ${secs}s ago`;
  }
  return "Connecting...";
};

export const LiveIndicator = ({
  isLive,
  onToggleLive,
  onRefresh,
  lastUpdated,
  isRefreshing,
  intervalSec = 10,
  label = "LIVE SYNC"
}) => {
  const [secondsAgo, setSecondsAgo] = useState(0);

  useEffect(() => {
    if (!lastUpdated) return;
    const updateDiff = () => {
      const diff = Math.floor((Date.now() - new Date(lastUpdated).getTime()) / 1000);
      setSecondsAgo(Math.max(0, diff));
    };
    updateDiff();

    const timer = setInterval(updateDiff, 1000);
    return () => clearInterval(timer);
  }, [lastUpdated]);

  return (
    <div className="live-indicator-bar">
      <div className={`live-status-pill ${isLive ? "active" : "paused"}`}>
        <span className="live-dot-pulse">
          <span className="live-dot-core" />
          <span className="live-dot-ring" />
        </span>
        <span className="live-label">{isLive ? label : "SYNC PAUSED"}</span>
      </div>

      <div className="live-sync-meta">
        <span className="live-updated-time">
          {renderSyncMeta(isRefreshing, lastUpdated, secondsAgo)}
        </span>

        {isLive && intervalSec > 0 && !isRefreshing && (
          <div 
            className="live-progress-mini" 
            title={`Next auto-sync in ~${Math.max(0, intervalSec - (secondsAgo % intervalSec))}s`}
          >
            <div 
              className="live-progress-fill"
              style={{
                width: `${Math.min(100, (secondsAgo % intervalSec) * (100 / intervalSec))}%`
              }}
            />
          </div>
        )}
      </div>

      <div className="live-actions">
        <button
          type="button"
          className={`live-btn live-btn--toggle ${isLive ? "is-live" : ""}`}
          onClick={onToggleLive}
          title={isLive ? "Pause live auto-refresh" : "Enable live auto-refresh"}
        >
          {isLive ? <RiPauseCircleLine /> : <RiPlayCircleLine />}
          <span className="btn-label">{isLive ? "Pause" : "Live"}</span>
        </button>

        <button
          type="button"
          className={`live-btn live-btn--refresh ${isRefreshing ? "spinning" : ""}`}
          onClick={onRefresh}
          disabled={isRefreshing}
          title="Force refresh now"
        >
          <RiRefreshLine />
        </button>
      </div>
    </div>
  );
};

LiveIndicator.propTypes = {
  isLive: PropTypes.bool.isRequired,
  onToggleLive: PropTypes.func.isRequired,
  onRefresh: PropTypes.func.isRequired,
  lastUpdated: PropTypes.oneOfType([PropTypes.instanceOf(Date), PropTypes.number, PropTypes.string]),
  isRefreshing: PropTypes.bool,
  intervalSec: PropTypes.number,
  label: PropTypes.string,
};
