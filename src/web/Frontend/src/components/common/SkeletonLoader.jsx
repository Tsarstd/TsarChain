import PropTypes from "prop-types";
import { useId } from "react";

export const SkeletonBlockCard = ({ height = null }) => {
  return (
    <div className="lane-card lane-card--skeleton" style={{ cursor: "default", opacity: 0.85 }}>
      <div className="lane-card__grid">
        <div className="stat">
          <div className="skeleton-line" style={{ width: "65px", height: "12px", marginBottom: "4px" }} />
          <div className="lane-card__blockheight" style={{ opacity: 0.75 }}>
            {height !== null && height !== undefined ? (
              height
            ) : (
              <div className="skeleton-line" style={{ width: "70px", height: "24px" }} />
            )}
          </div>
        </div>
        <div className="skeleton-line" style={{ width: "42px", height: "14px", justifySelf: "right" }} />
      </div>

      <div className="lane-card__bid" style={{ opacity: 0.4 }}>
        <div className="skeleton-line" style={{ width: "100px", height: "10px" }} />
      </div>

      <div className="lane-card__grid">
        <div className="stat">
          <span className="label">Transactions</span>
          <div className="skeleton-line" style={{ width: "28px", height: "14px", marginTop: "2px" }} />
        </div>
      </div>
      <div className="lane-card__grid">
        <div className="stat">
          <span className="label">Comments</span>
          <div className="skeleton-line" style={{ width: "20px", height: "14px", marginTop: "2px" }} />
        </div>
        <div className="stat">
          <span className="label">Payouts</span>
          <div className="skeleton-line" style={{ width: "20px", height: "14px", marginTop: "2px" }} />
        </div>
      </div>
      <div className="skeleton-line" style={{ width: "100%", height: "11px", marginTop: "4px" }} />
    </div>
  );
};

SkeletonBlockCard.propTypes = {
  height: PropTypes.number,
};

export const SkeletonGraffitiCard = ({ height = null }) => {
  return (
    <div className="lane-card lane-card--graffiti lane-card--skeleton" style={{ cursor: "default", opacity: 0.85 }}>
      <div className="lane-card__grid">
        <div className="stat">
          <div className="value">Graffiti</div>
          <div className="lane-card__graffheader">
            {height !== null && height !== undefined ? (
              height
            ) : (
              <div className="skeleton-line" style={{ width: "50px", height: "24px" }} />
            )}
          </div>
        </div>
        <div className="skeleton-line" style={{ width: "55px", height: "18px", justifySelf: "right" }} />
      </div>

      <div className="lane-card__creator" style={{ opacity: 0.7 }}>
        <div className="skeleton-line" style={{ width: "130px", height: "12px" }} />
      </div>

      <div className="lane-card__grid">
        <div className="stat">
          <span className="label">Size</span>
          <div className="skeleton-line" style={{ width: "45px", height: "14px", marginTop: "2px" }} />
        </div>
        <div className="stat">
          <span className="label">Comments</span>
          <div className="skeleton-line" style={{ width: "25px", height: "14px", marginTop: "2px" }} />
        </div>
      </div>
      <div className="skeleton-line" style={{ width: "100%", height: "11px", marginTop: "4px" }} />
    </div>
  );
};

SkeletonGraffitiCard.propTypes = {
  height: PropTypes.number,
};

export const SkeletonCard = ({ count = 6 }) => {
  const baseId = useId();
  const items = Array.from({ length: count }, (_, i) => `${baseId}-card-${i}`);

  return (
    <div className="skeleton-lane-container">
      {items.map((id) => (
        <div className="skeleton-card glass-panel" key={id}>
          <div className="skeleton-line skeleton-header-line" />
          <div className="skeleton-line skeleton-height-line" />
          <div className="skeleton-grid">
            <div className="skeleton-line skeleton-stat-line" />
            <div className="skeleton-line skeleton-stat-line" />
          </div>
          <div className="skeleton-line skeleton-footer-line" />
        </div>
      ))}
    </div>
  );
};

SkeletonCard.propTypes = {
  count: PropTypes.number,
};

export const SkeletonNetwork = () => {
  const baseId = useId();
  const items = Array.from({ length: 8 }, (_, i) => `${baseId}-net-${i}`);

  return (
    <div className="skeleton-network-container">
      {/* Header Skeleton */}
      <div className="skeleton-header glass-panel">
        <div className="skeleton-line skeleton-title-line" />
        <div className="skeleton-bar-grid">
          <div className="skeleton-line skeleton-bar-stat" />
          <div className="skeleton-line skeleton-bar-stat" />
          <div className="skeleton-line skeleton-bar-stat" />
        </div>
      </div>

      {/* Grid Stat Cards Skeleton */}
      <div className="skeleton-grid-cols-4">
        {items.map((id) => (
          <div className="skeleton-stat-card glass-panel" key={id}>
            <div className="skeleton-line skeleton-label-line" />
            <div className="skeleton-line skeleton-val-line" />
            <div className="skeleton-line skeleton-sub-line" />
          </div>
        ))}
      </div>
    </div>
  );
};

export const SkeletonSearch = () => {
  return (
    <div className="skeleton-search-container glass-panel">
      <div className="skeleton-line skeleton-search-title" />
      <div className="skeleton-search-grid">
        <div className="skeleton-line skeleton-search-item" />
        <div className="skeleton-line skeleton-search-item" />
        <div className="skeleton-line skeleton-search-item" />
      </div>
    </div>
  );
};
