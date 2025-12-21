const { guessKind } = require("../utils/searchKind");
const { rpcCall } = require("../tsarRpcAdapter");

class ExplorerService {
  constructor(options = {}) {
    this.nodeHost = options.nodeHost;
    this.nodePort = options.nodePort;
  }

  async getNetwork() {
    const res = await rpcCall("network", null, this.nodeHost, this.nodePort);
    return res;
  }

  async getBlock(id) {
    return rpcCall("block", id, this.nodeHost, this.nodePort);
  }

  async getTx(id) {
    return rpcCall("tx", id, this.nodeHost, this.nodePort);
  }

  async getAddress(addr) {
    return rpcCall("address", addr, this.nodeHost, this.nodePort);
  }

  async getGraffiti(artId) {
    const resp = await rpcCall("graffiti", artId, this.nodeHost, this.nodePort);
    if (!resp) return null;
    if (resp.post) {
      return { ...(resp.post || {}), comments: resp.comments || [] };
    }
    return resp;
  }

  async search(query) {
    const kind = guessKind(query);
    if (kind === "unknown") {
      return { kind, data: null };
    }
    switch (kind) {
      case "block_height":
      case "block_hash":
        return { kind: "block", data: await this.getBlock(query) };
      case "txid_hash":
        return { kind: "tx", data: await this.getTx(query) };
      case "address":
        return { kind: "address", data: await this.getAddress(query) };
      case "art_id":
        return { kind: "graffiti", data: await this.getGraffiti(query) };
      default:
        return { kind: "unknown", data: null };
    }
  }
}

module.exports = { ExplorerService };
