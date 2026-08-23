import { useState, useEffect } from "react";
import PropTypes from "prop-types";
import { RiRefreshLine, RiPauseLine, RiPlayLine } from "react-icons/ri";

const renderSyncMeta = (refreshing, updated, secs) => {
  if (refreshing) {
    return (
      <span className="syncing-text">
        <span className="syncing-spinner" /> Syncing...
      </span>
    );
  }
  if (updated) {
    const text = secs <= 1 ? "Just now" : `${secs}s ago`;
    return (
      <span className="updated-text">
        <span className="updated-label">Updated</span> {text}
      </span>
    );
  }
  return <span>Connecting...</span>;
};

export const LiveIndicator = ({
  isLive,
  onToggleLive,
  onRefresh,
  lastUpdated,
  isRefreshing,
  intervalSec = 10,
  label = "Live Sync"
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

  const nextSyncSec = intervalSec > 0 ? Math.max(0, intervalSec - (secondsAgo % intervalSec)) : 0;
  const progressPct = intervalSec > 0 ? Math.min(100, Math.max(0, ((secondsAgo % intervalSec) / intervalSec) * 100)) : 0;

  return (
    <div className="live-indicator-bar">
      <div className={`live-status-pill ${isLive ? "active" : "paused"}`}>
        <span className="live-dot-pulse">
          <span className="live-dot-core" />
          <span className="live-dot-ring" />
        </span>
        <span className="live-label">{isLive ? label : "Paused"}</span>
      </div>

      <div className="live-sync-meta">
        <span className="live-updated-time">
          {renderSyncMeta(isRefreshing, lastUpdated, secondsAgo)}
        </span>

        {isLive && intervalSec > 0 && !isRefreshing && (
          <div 
            className="live-progress-mini" 
            title={`Next auto-sync in ~${nextSyncSec}s`}
          >
            <div 
              className="live-progress-fill"
              style={{
                width: `${progressPct}%`
              }}
            />
          </div>
        )}
      </div>

      <div className="live-divider" />

      <div className="live-actions">
        <button
          type="button"
          className={`live-btn live-btn--toggle ${isLive ? "is-live" : ""}`}
          onClick={onToggleLive}
          title={isLive ? "Pause live auto-refresh" : "Enable live auto-refresh"}
        >
          {isLive ? <RiPauseLine /> : <RiPlayLine />}
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

