export const getVoutLabel = (vout) => {
  switch (vout) {
    case 0:
      return "VOUT 0";
    case 1:
      return "VOUT 1";
    case 2:
      return "VOUT 2";
    case 3:
      return "VOUT 3";
    default:
      return `Output ${vout}`; // For vout > 3
  }
}

export const getStatusBadge = (status) => {
  const statusLower = String(status || "").toLowerCase();
  
  if (statusLower.includes("unconfirmed")) {
    return { 
      type: "unconfirmed", 
      label: "Pending",
      color: "#717170ff"
    };
  }
  
  if (statusLower.includes("confirmed")) {
    return { 
      type: "confirmed", 
      label: "Confirmed",
      color: "#4f772d"
    };
  }
  
  return {
    type: "unknown",
    label: "Unknown",
    color: "#8b8b8b"
  };
};

export const getDirectionBadge = (direction) => {
  const dir = String(direction || "").toLowerCase();
  
  if (dir === "in") {
    return { 
      type: "incoming", 
      label: "Received",
      color: "#3e8daaff"
    };
  }
  
  if (dir === "out") {
    return { 
      type: "outgoing", 
      label: "Sending", 
      color: "#d1495b"
    };
  }
  
  return {
    type: "unknown",
    label: "Unknown",
    color: "#8b8b8b"
  };
};

export const getAddressType = (address) => {
  const clean = String(address || "").trim();
  if (!clean) return null;
  if (clean.length === 44) return { type: "P2WPKH", label: "Citizen Address" };
  if (clean.length === 64) return { type: "P2WSH", label: "Pool Address" };
  return null;
}