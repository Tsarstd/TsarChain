import { useMemo } from "react";
import PropTypes from "prop-types";

// Hash string helper for deterministic seed
const hashString = (str) => {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.codePointAt(i) ?? 0;
    hash = (hash << 5) - hash + char;
    hash = Math.trunc(hash); // Convert to 32bit integer
  }
  return Math.abs(hash);
};

// Studio tailored harmonious palette
const PALETTE = [
  "#de5526", // Tsar Orange
  "#e05f32", // Accent Secondary
  "#ff7a45", // Accent Light
  "#fff8f0", // Tsar Cream
  "#b03c13", // Accent Dark
  "#ede6de", // Cream Slate
  "#eab308", // Amber
  "#f97316", // Bright Orange
];

export const Identicon = ({ value = "", size = 28, className = "" }) => {
  const { cells, bg, fg } = useMemo(() => {
    const seed = hashString(value || "anonymous");
    const bgIndex = seed % PALETTE.length;
    const fgIndex = (seed + 3) % PALETTE.length;
    
    // Generate 5x5 symmetric grid (3 unique cols mirrored)
    const grid = [];
    for (let r = 0; r < 5; r++) {
      const row = [];
      for (let c = 0; c < 3; c++) {
        const bit = ((seed >> (r * 3 + c)) & 1) === 1;
        row.push(bit);
      }
      // Mirror col 1 and col 0 to form 5 cols: [0, 1, 2, 1, 0]
      grid.push([row[0], row[1], row[2], row[1], row[0]]);
    }

    return {
      cells: grid,
      bg: "#141414",
      fg: PALETTE[fgIndex] === "#141414" ? PALETTE[bgIndex] : PALETTE[fgIndex],
    };
  }, [value]);

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 5 5"
      className={`identicon-avatar ${className}`}
      style={{
        display: "inline-block",
        verticalAlign: "middle",
        backgroundColor: bg,
        borderRadius: "4px",
        border: "1px solid rgba(255, 248, 240, 0.15)",
        boxShadow: "1px 1px 0px #121212",
        flexShrink: 0,
      }}
      aria-hidden="true"
    >
      {cells.map((row, r) =>
        row.map((active, c) =>
          active ? (
            <rect
              key={`${r}-${c}`}
              x={c}
              y={r}
              width={1}
              height={1}
              fill={fg}
            />
          ) : null
        )
      )}
    </svg>
  );
};

Identicon.propTypes = {
  value: PropTypes.string,
  size: PropTypes.number,
  className: PropTypes.string,
};

export default Identicon;
