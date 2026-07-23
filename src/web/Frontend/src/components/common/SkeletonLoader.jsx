import PropTypes from "prop-types";

export const SkeletonCard = ({ count = 6 }) => {
  return (
    <div className="skeleton-lane-container">
      {Array.from({ length: count }).map((_, idx) => (
        <div className="skeleton-card glass-panel" key={`sk-card-${idx}`}>
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
        {Array.from({ length: 8 }).map((_, idx) => (
          <div className="skeleton-stat-card glass-panel" key={`sk-net-${idx}`}>
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
