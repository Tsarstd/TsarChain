export const fmtShort = (str, startLen = 6, endLen = 4) => {
  if (!str || typeof str !== 'string') return str || '-';
  if (str.length <= startLen + endLen) return str;
  return `${str.slice(0, startLen)}...${str.slice(-endLen)}`;
};

export const fmtHash = (hash) => fmtShort(hash, 8, 8);
export const fmtTxid = (txid) => fmtShort(txid, 8, 8);
export const fmtAddress = (addr) => fmtShort(addr, 8, 8);

export const fmtNumber = (n) => {
  if (n === null || n === undefined || n === "") return "-";
  const val = Number(n);
  if (Number.isNaN(val)) return String(n);
  return val.toLocaleString("id-ID");
};

export const fmtTsar = (sat) => {
  if (sat === null || sat === undefined || sat === "") return "-";
  const n = Number(sat);
  if (Number.isNaN(n)) return String(sat);
  const whole = Math.trunc(n / 1e8);
  const frac = Math.abs(n % 1e8)
    .toString()
    .padStart(8, "0")
    .replace(/0+$/, "");
  return `${whole.toLocaleString("id-ID")}${frac ? "," + frac : ""} TSAR`;
};

export const fmtBytes = (b) => {
  if (b === null || b === undefined || b === "") return "-";
  const parsed = Number(b);
  if (Number.isNaN(parsed)) return String(b);
  const units = ["B", "KB", "MB", "GB"];
  let val = parsed;
  let i = 0;
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024;
    i += 1;
  }
  return i === 0 ? `${val} ${units[i]}` : `${val.toFixed(2)} ${units[i]}`;
};

export const fmtTimestamp = (sec) => {
  if (!sec) return "-";
  const date = new Date(Number(sec) * 1000);
  
  const day = date.getUTCDate();
  const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", 
                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const month = monthNames[date.getUTCMonth()];
  const year = date.getUTCFullYear();
  
  const hours = String(date.getUTCHours()).padStart(2, '0');
  const minutes = String(date.getUTCMinutes()).padStart(2, '0');
  const seconds = String(date.getUTCSeconds()).padStart(2, '0');
  
  return `${day} ${month} ${year}, ${hours}:${minutes}:${seconds} UTC`;
};

export const fmtDateLong = (sec) => {
  if (!sec) return "-";
  const date = new Date(Number(sec) * 1000);
  const options = { year: 'numeric', month: 'long', day: 'numeric' };
  return date.toLocaleDateString('en-US', options);
};

export const timeAgo = (sec) => {
  if (!sec) return "-";
  
  const now = Math.floor(Date.now() / 1000);
  const diff = now - Number(sec);
  
  if (diff < 0) return "Just Now";
  
  const intervals = [
    { label: 'Year', seconds: 31536000 },
    { label: 'Month', seconds: 2592000 },
    { label: 'Week', seconds: 604800 },
    { label: 'Day', seconds: 86400 },
    { label: 'Hour', seconds: 3600 },
    { label: 'Minute', seconds: 60 },
    { label: 'Second', seconds: 1 }
  ];
  
  for (const interval of intervals) {
    const count = Math.floor(diff / interval.seconds);
    if (count >= 1) {
      return `${count} ${interval.label}${count !== 1 ? 's' : ''} Ago`;
    }
  }
  
  return 'just now';
};

export const fmtHashrate = (hps) => {
  const v = Number(hps || 0);
  if (v >= 1e12) return `${(v / 1e12).toFixed(3)} TH/s`;
  if (v >= 1e9) return `${(v / 1e9).toFixed(3)} GH/s`;
  if (v >= 1e6) return `${(v / 1e6).toFixed(3)} MH/s`;
  if (v >= 1e3) return `${(v / 1e3).toFixed(3)} kH/s`;
  return `${v.toFixed(0)} H/s`;
};

export const fmtChainwork = (val) => {
  if (val === null || val === undefined || val === "") {
    return "-";
  }

  try {
    let n;

    if (typeof val === "bigint") {
      n = val;
    } else if (typeof val === "number") {
      if (!Number.isFinite(val) || !Number.isInteger(val))
        throw new Error("Not an integer");
      n = BigInt(val);
    } else {
      const s = String(val).trim();
      if (!/^-?\d+$/.test(s)) throw new Error("Not a valid integer string");
      n = BigInt(s);
    }

    const hexstr = n < 0n ? (-n).toString(16) : n.toString(16);
    const prefixed = (n < 0n ? "-0x" : "0x") + hexstr;

    const short =
      hexstr.length <= 14
        ? prefixed
        : (n < 0n ? "-0x" : "0x") +
          hexstr.slice(0, 6) +
          "..." +
          hexstr.slice(-6);

    const human = n.toLocaleString("en-US");

    return `${short} (${human})`;
  } catch (e) {
    const s = String(val);
    return s.length <= 14 ? s : `${s.slice(0, 6)}...${s.slice(-6)}`;
  }
};
