<p align="center">
  <img src="assets/branding/TsarChain Logo.png" width="720" alt="TsarChain — The Voice Sovereignty Monetary System">
</p>

<p align="center">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-brightgreen">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.11%2B-blue">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-Pyo3-black">
  <img alt="Consensus" src="https://img.shields.io/badge/Consensus-PoW-lightgrey">
  <img alt="Ledger" src="https://img.shields.io/badge/Ledger-UTXO-blueviolet">
  <img alt="Address" src="https://img.shields.io/badge/Address-tsar1%20(Bech32)-orange">
  <img alt="Network" src="https://img.shields.io/badge/Network-Devnet-yellow">
</p>

# Long Live The Voice Sovereignty Monetary System

*A proof‑of‑work, UTXO‑based chain for digital preservation — durable, verifiable, and community‑owned.*

TsarChain focuses on **Voice Sovereignty**: preserving *cultural archives*, *art*, and *testimonies* so that *digital traces* don't disappear. Its decentralized architecture keeps evidence **verifiable** and **publicly auditable**, providing creative communities and cultural researchers with a durable **preservation platform**.


---

## Table of Contents
- [Demo](#️-demo)
- [Project Status](#️-project-status)
- [Features at a Glance](#-features-at-a-glance)
- [Why Voice Sovereignty](#-why-voice-sovereignty)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Setup](#setup)
  - [(Optional) Build Native Extension](#optional-build-native-extension)
  - [Quickstart](#️-quickstart)
- [Devnet Quick Config](#️-devnet-quick-config)
- [Mining Modes](#-mining-modes)
- [Architecture](#️-architecture)
- [Security Notes](#-security-notes)
- [Contributing](#-contributing)
- [Roadmap](#️-roadmap)
- [Documentation](#-documentation)
- [License](#-license)

---

## 🎞️ Demo

- ***Miner walkthrough (Mining GUI):***
  <details>
    <summary>See Mining demo</summary>
    <img src="assets/demo/Miner_gui_demo.gif" alt="Miner GUI demo" width="500" height="500">
  </details>

---

## ⚠️ Project Status

#### ✅ Implemented
- Wallet generation (with SegWit Bech32)
- Address prefix `tsar1`
- Genesis block
- Proof-of-Work
- Chat Feature (X3DH & Double Ratchet)
- Coinbase reward
- UTXO system
- SegWit transactions
- Fee mechanism
- Mempool
- Multi-node networking
- Transaction & block validation
- Chain validation

#### 🚧 In Development
- Storage Node
- Graffiti
- Some Security
- Some UI/UX Wallet
- etc.

> This status mirrors the latest UI status board.

---

## ✨ Features at a Glance

- **Consensus** – RandomX PoW with LWMA difficulty targeting predictable block times.
- **Ledger model** — UTXO with SegWit serialization and signature validation (secp256k1).
- **Addresses** — Bech32, prefix **`tsar1`** (P2WPKH today; room for scripts/contracts later).
- **Wallet** — “Kremlin” light wallet (GUI) for send/receive, explorer, and secure P2P chat.
- **Secure chat** — X3DH key agreement + Double Ratchet, safety numbers, and key-change alerts.
- **Networking** — Peer discovery with bootstrap support, multi-port range, full block/tx relay.
- **Observability** — Structured logs for node, miner, and wallet.

---

## 🧭 Why Voice Sovereignty?

Platforms curate history; networks preserve it. TsarChain treats each message, artwork, or testimony as **expressive value** anchored in blocks and protected by open consensus — not for confrontation, but for the care of collective memory.

---

## 🚀 Getting Started

#### Prerequisites
- Python ≥ 3.11, Git
- Rust toolchain for native acceleration

#### Setup
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -U pip wheel
pip install -r requirements.txt
```

#### Build Native Extension
```bash
pip install maturin
cd tsarcore_native
maturin develop --release

# -- Optional --
maturin develop --release --features parallel

# -- Run Test --
python tests/native_test.py
```
> TsarChain always loads the Rust extension; ensure `tsarcore_native` is installed in the active environment.

> RandomX support ships inside `tsarcore_native`. Building it requires a C toolchain plus `cmake` (RandomX vendored sources are compiled during `maturin develop`). For best CPU performance enable AES-NI in BIOS and configure huge pages before starting the miner (`TSAR_RANDOMX_LARGE_PAGES=1`).

---

## 🏃🏻‍♂️ Quickstart

**Run a Miner/Node**
```bash
# GUI (lite-friendly, limited to 1 core)
python apps/miner_gui.py

# Stateless CLI miner (no on-disk blockchain, just hashing)
python apps/cli_miner.py --address tsar1qyoursomething --cores 4

# Full node + miner (keeps blockchain DB + snapshot gateway)
python apps/cli_node_miner.py --address tsar1qyoursomething --cores 4

# GUI Wallet
python apps/kremlin.py
```

> **Tip:** For public devnet tests, lock `GENESIS_HASH`, keep `ALLOW_AUTO_GENESIS = 0`, enable the chain-work rule and reorg limits, and tune difficulty/LWMA for your network size.

---

## ⚙️ Config Codebase Preview

```python
# =============================================================================
# IDENTITY & NETWORK
# =============================================================================
ADDRESS_PREFIX      = "tsar"
NET_ID_DEV          = "gulag-net"

# =============================================================================
# CONSENSUS / DIFFICULTY
# =============================================================================
INITIAL_BITS       = 0x1F0FFFFF     # easier RandomX default for dev
MAX_BITS           = 0x1F0FFFFF
TARGET_BLOCK_TIME  = 60             # 60 Sec
LWMA_WINDOW        = 60             # Block's
FUTURE_DRIFT       = 600            # 10 Minute
MTP_WINDOWS        = 11             # Block's

# === Consensus Hardening ===
# CONSENSUS LIMITS (Blocks & TX)
MAX_BLOCK_BYTES         = 1_200_000        # 1,2 MB
MAX_TXS_PER_BLOCK       = 5_000
MAX_SIGOPS_PER_BLOCK    = 40_000
MAX_SIGOPS_PER_TX       = 6_000

# FORK-CHOICE & REORG
ENABLE_CHAINWORK_RULE   = True
ENABLE_REORG_LIMIT      = True
REORG_LIMIT             = 1000

# DIFF CLAMP
ENABLE_DIFF_CLAMP       = True
DIFF_CLAMP_MAX_UP       = 1.5
DIFF_CLAMP_MAX_DOWN     = 0.4

# Emergency Difficulty Adjustment (EDA)
ENABLE_EDA              = True
EDA_WINDOW              = 48
EDA_TRIGGER_RATIO       = 3.0
EDA_EASE_MULTIPLIER     = 2.0

# =============================================================================
# P2P / PORTS
# =============================================================================
PORT_RANGE_DEV     = (38169, 38178)

BOOTSTRAP_DEV      = (
    ("127.0.0.1", 38169),
)
```

> To see the entire project configuration, you can check in [`src/tsarchain/utils/config.py`](src/tsarchain/utils/config.py)
>
> 🔧 **RandomX knobs** live in the same file (`POW_ALGO`, `RANDOMX_*`). Tune `RANDOMX_FULL_MEM`, `RANDOMX_LARGE_PAGES`, and `RANDOMX_KEY_EPOCH_BLOCKS` if you need lighter verification nodes or want to rotate the RandomX seed more/less frequently.
> - **Dev/Test**: `RANDOMX_FULL_MEM=False`, `RANDOMX_LARGE_PAGES=False`, `RANDOMX_CACHE_MAX=1`, `RANDOMX_KEY_EPOCH_BLOCKS=64`.
> - **Mainnet/Full Node**: `RANDOMX_FULL_MEM=True`, enable huge pages, bump `RANDOMX_CACHE_MAX` (4+) and lengthen `RANDOMX_KEY_EPOCH_BLOCKS` (e.g. 2048).


---

## Mining Modes

- **GUI Miner (`apps/miner_gui.py`)** ? ships with Lite GUI mode enabled and limits RandomX to one core by default so the Tkinter UI stays responsive.
- **Stateless CLI Miner (`apps/cli_miner.py`)** ? keeps chain data in-memory, fetches the latest tip from peers, mines, then broadcasts (no snapshots or DB).
- **Full Node CLI Miner (`apps/cli_node_miner.py`)** ? persists the entire blockchain, handles snapshot bootstrap, wallet gateway traffic, and can run `--node-only` for infra roles.

Use the GUI for demos/monitoring, `cli_miner.py` for raw hash power, and `cli_node_miner.py` when you need full-node responsibilities.


## 🏗️ Architecture

```
+-----------------+                     +------------------+
|  Miner / Node   | <--- blocks/tx ---> |   Miner / Node   |
+-----------------+                     +------------------+
         ^                                     ^
         | RPC                                 | RPC
         v                                     v
+-----------------+                     +-----------------+
|  Kremlin Wallet |  <-- P2P chat -->   |  Kremlin Wallet |
+-----------------+                     +-----------------+

- UTXO ledger with SegWit
- LWMA difficulty adjustment
- Bootstrap discovery + multi‑port range
- Chat: X3DH + Double Ratchet + safety number
```
- **Block Data Structure**
```python
  {
    "height": 9,
    "version": 1,
    "prev_block_hash": "00055cf16aa3b256594be97cea914e725cfa445d2a72d3bb41664f08f36905b5",
    "merkle_root": "f84393b07bf754e34f88d07f573e389abe2609cc764bfec92aa2b0ef65bc8bf5",
    "timestamp": 1763044929,
    "bits": 521871414,
    "nonce": 729,
    "hash": "00174b6f1cb8b8069562824e9fe07b21e9ada22c81acfbf42067e60aef35f34e",
    "transactions": [
      {
        "version": 1,
        "inputs": [
          {
            "txid": "0000000000000000000000000000000000000000000000000000000000000000",
            "vout": 4294967295,
            "amount": 0,
            "script_sig": "010925446170686e655f43617275616e615f47616c697a69615f323031375f5a7133666a3755526f",
            "witness": []
          }
        ],
        "outputs": [
          {
            "amount": 25000009568,
            "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
          }
        ],
        "locktime": 0,
        "txid": "3e8ec61b5016df41fb60d460dbe3baaff926e8ee08587c7f864e5e355ba2ebb3",
        "fee": 0,
        "is_coinbase": true,
        "type": "Coinbase",
        "to_address": "tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr",
        "reward": 25000009568,
        "block_id": "Daphne_Caruana_Galizia_2017_Zq3fj7URo",
        "height": 9
      },
      {
        "version": 1,
        "inputs": [
          {
            "txid": "24b06b68fc405364159d686b526c9ccda1d389f3cc2111187099d39f656b38f6",
            "vout": 0,
            "amount": 25000000000,
            "script_sig": "",
            "witness": [
              "3045022100d80a60b0b3230dc995d2991ce7db1780f6c463f6df38bff43ffbd747bd475aa1022030a257bc61e0f30a5cdf6f598df94d329f8ba0ea298997f1af6be54c67a0fec601",
              "0359c3eab29ad7feb9fad33caae30e9e7a9bbbc1291748a851bb1e6d3bc81c0143"
            ]
          },
          {
            "txid": "42c7d44c08976be5161a365817fee5a1cbdf15d58a67d1f5296311c6e2ee6d01",
            "vout": 1,
            "amount": 248824999992720,
            "script_sig": "",
            "witness": [
              "3045022100c0d242bf9081abdb0f4387048b5367f8995955467acf24e99f18555b72cd50eb02207949b401638a8d2b0b379ac842eb2154bc4bda99d4c7df3f974d27540a5e92b501",
              "0359c3eab29ad7feb9fad33caae30e9e7a9bbbc1291748a851bb1e6d3bc81c0143"
            ]
          }
        ],
        "outputs": [
          {
            "amount": 1000000000000,
            "script_pubkey": "00149fb49a362a364b57d2f05e7929109cedc7824ef4"
          },
          {
            "amount": 247849999983152,
            "script_pubkey": "0014118424d3a2a2396ac76978aad2d79c4757596332"
          }
        ],
        "locktime": 0,
        "txid": "6533068e0db4c759a444801894554c4ad701c338585de4fa21d02f956c6b9c86",
        "fee": 9568,
        "is_coinbase": false
      }
    ]
  }
```
- **UTXO's Data Structure**
```python
  },
  "3e8ec61b5016df41fb60d460dbe3baaff926e8ee08587c7f864e5e355ba2ebb3:0": {
    "tx_out": {
      "amount": 25000009568,
      "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
    },
    "is_coinbase": true,
    "block_height": 9
  },
  "6533068e0db4c759a444801894554c4ad701c338585de4fa21d02f956c6b9c86:0": {
    "tx_out": {
      "amount": 1000000000000,
      "script_pubkey": "00149fb49a362a364b57d2f05e7929109cedc7824ef4"
    },
    "is_coinbase": false,
    "block_height": 9
  },
  "6533068e0db4c759a444801894554c4ad701c338585de4fa21d02f956c6b9c86:1": {
    "tx_out": {
      "amount": 247849999983152,
      "script_pubkey": "0014118424d3a2a2396ac76978aad2d79c4757596332"
    },
    "is_coinbase": false,
    "block_height": 9
  },
  "44ceacde4425a12a6032e0f93bd952d87b844d28e6d5cacda02d0e315a3b8104:0": {
    "tx_out": {
      "amount": 25000000000,
      "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
    },
    "is_coinbase": true,
    "block_height": 10
  }
```

---

## 🔐 Security Notes

- Chat privacy uses X3DH + Double Ratchet (simple implementation).
- This is experimental software; there haven't been many network security audits, it was built by a **graphics design studio** with little experience in low-level engineering.
- If you run validators/miners publicly, just **mining it!** **fork it!** **learn it!** **Look for vulnerabilities!** and see how blockchain work.

---

## 🫂 Contributing

Pull requests are welcome. Please start with small, well‑scoped changes (docs, tests, logging), then propose larger work via issues. Be respectful: the mission is **Voice Sovereignty**.
> I've provided a logging tool. For easier debugging, you can check [`src/tsarchain/utils/tsar_logging.py`](src/tsarchain/utils/tsar_logging.py)

---

## 🗺️ Roadmap

- Graffiti & Storage Node incentives
- Wallet UX hardening and recovery tooling
- The Voice Sovereignty

---

## 📄 Documentation

**Whitepaper**
- [`Grungepaper - The Voice Sovereignty (EN)`](docs/Grungepaper%20-%20The%20Voice%20Sovereignty%20(EN).pdf)
- [`Grungepaper - The Voice Sovereignty (ID)`](docs/Grungepaper%20-%20The%20Voice%20Sovereignty%20(ID).pdf)

**Graffiti Protocol**
- [`Graffiti Protocol - Draft v0.1 (EN)`](docs/Graffiti%20Protocol%20-%20Draft%20v0.1%20(EN).pdf)

---

## 📜 License

MIT
