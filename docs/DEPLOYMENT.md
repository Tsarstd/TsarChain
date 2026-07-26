# TsarChain Network Deployment & Genesis Setup Guide

This guide explains how to set up the environment, initialize a new blockchain network via **Genesis Lock**, and deploy nodes or miners on the TsarChain network.

---

## 1. Environment Setup

Before running any node or miner, ensure all dependencies (Rust, CMake, Python 3.12, Node.js, and Native Extensions) are installed using the automated bootstrap scripts:

### On Linux / macOS (Bash)
```bash
# 1. Run setup script
./setup.sh

# 2. Activate virtual environment
source activate_env.sh
```

### On Windows (PowerShell)
```powershell
# 1. Run setup script
.\setup.ps1

# 2. Activate virtual environment (Note the leading dot for dot-sourcing)
. .\activate_env.ps1
```

---

## 2. Network Genesis Setup (`--init-genesis`)

In TsarChain, **Block 0 (Genesis Block)** is mined once by the first **Bootstrap Node**. Once mined, Block 0 is stored directly in the local **LMDB database** (`data/node`), which acts as the immutable **Genesis Lock**.

> [!IMPORTANT]
> - Automatic genesis creation is **100% disabled by default** on normal node startup.
> - Genesis creation must be explicitly triggered using the `--init-genesis` flag.

### Step-by-step: Creating a New Network

1. Run the `--init-genesis` command on the initial bootstrap server:
   ```bash
   python apps/cli_node_miner.py --init-genesis
   # then, input your address 'create address in wallet.py first'
   # tune your CPU core 'recomended 2 cpu , just for genesis'
   ```

2. The CLI will mine Block 0, store it into LMDB, print the summary, and exit cleanly:
   ```text
   ==> Mining Genesis Block (Block 0) for address 'tsar1...' with 2 core(s)...
   ================================================================
   Genesis Block created & locked in LMDB successfully!
   Hash      : 000fbaf94a24b16f5c0713b6b3513b758652e927e616bb52ecae31d214625759
   Height    : 0
   PrevHash  : 0000000000000000000000000000000000000000000000000000000000000000
   Nonce     : 109
   Timestamp : Sun Jul 26 20:40:57 2026
   ================================================================
   Environment ready! You can now start the node or miner in normal mode.
   ```

3. **Re-run Protection**: If `--init-genesis` is executed again on an existing database, the CLI detects the LMDB Genesis Lock, displays the Genesis Hash, and exits safely without re-mining.

4. **Run Archivist Node (Storage Node)** run this node is separated cli / terminal enviroment.
   ```bash
   python apps/cli_archivist.py
   ```
   you must run this node for Graffiti Feature in TsarChain. Otherwise, the network can only accept standard transactions (not OP_RETURN).

---

## 3. Running Nodes & Joining the Network

After the Genesis Block is initialized on the bootstrap node, other nodes and miners can join the network.

### A. Regular Miner Mode (Bootstrap Node or Peer Miner)
To start mining Block 1 and subsequent blocks:
```bash
python apps/cli_node_miner.py
```

### B. Full Node-Only Mode (Relay / RPC Server)
To run an always-on full node without mining:
```bash
python apps/cli_node_miner.py --node-only
```

### C. Joining as a Peer Node (New Machine)
New machines joining an existing network **DO NOT** run `--init-genesis`. Simply start the node:
```bash
python apps/cli_node_miner.py
# choose '0 mining mode'
```
The peer node will automatically connect to the bootstrap peer, download Block 0 over P2P sync, and store it into its local LMDB database, establishing the Genesis Lock automatically.

---

## 4. Production Checkpoints (Optional)

For official production/mainnet releases, the committed Genesis Hash can optionally be hardcoded in `src/tsarchain/utils/config.py`:

```python
# src/tsarchain/utils/config.py
GENESIS_HASH_HEX = "000fbaf94a24b16f5c0713b6b3513b758652e927e616bb52ecae31d214625759"
```

When `GENESIS_HASH_HEX` is set:
- Incoming P2P blocks and snapshot downloads (`bootstrap.py`) will validate against this hardcoded hash checkpoint.
- If `GENESIS_HASH_HEX = ""` (default), node integrity relies on the local LMDB Genesis state.

---

## 5. Maintenance & Resetting Testnets

If you need to wipe local chain data to restart a private testnet:

1. Stop all running nodes, miners & storage nodes.
2. Remove the local data directory:
   ```bash
   rm -rf data
   ```
3. Re-initialize Genesis on the bootstrap node using `--init-genesis`.
