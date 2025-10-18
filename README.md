<p align="center">
  <img src="assets/branding/TsarChain Logo.png" width="720" alt="TsarChain — The Voice Sovereignty Monetary System">
</p>

<p align="center">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-brightgreen">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.11%2B-blue">
  <img alt="Consensus" src="https://img.shields.io/badge/Consensus-PoW-lightgrey">
  <img alt="Ledger" src="https://img.shields.io/badge/Ledger-UTXO-blueviolet">
  <img alt="Address" src="https://img.shields.io/badge/Address-tsar1%20(Bech32)-informational">
  <img alt="Network" src="https://img.shields.io/badge/Network-Devnet-orange">
</p>

# Long Live The Voice Sovereignty Monetary System

*A proof-of-work, UTXO-based chain built to preserve human voice — uncensorable, durable, and verifiable.*

TsarChain is a minimal, pragmatic Layer-1 focused on **Voice Sovereignty**: protecting speech, art, and testimony so they can’t be silently erased. The project pairs a Python-first core with Rust accelerators where performance matters, and ships a local-first wallet so everyone can participate without gatekeepers.


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
- [Architecture](#️-architecture)
- [Security Notes](#-security-notes)
- [Contributing](#-contributing)
- [Roadmap](#️-roadmap)
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

- **Consensus** — PoW with LWMA difficulty targeting predictable block times.
- **Ledger model** — UTXO with SegWit serialization and signature validation (secp256k1).
- **Addresses** — Bech32, prefix **`tsar1`** (P2WPKH today; room for scripts/contracts later).
- **Wallet** — “Kremlin” light wallet (GUI) for send/receive, explorer, and secure P2P chat.
- **Secure chat** — X3DH key agreement + Double Ratchet, safety numbers, and key-change alerts.
- **Networking** — Peer discovery with bootstrap support, multi-port range, full block/tx relay.
- **Observability** — Structured logs for node, miner, and wallet.

---

## 🧭 Why Voice Sovereignty?

Platforms curate history; networks preserve it. TsarChain treats each message, artwork, or testimony as **expressive value** anchored in blocks and protected by open consensus — so proof of speech remains auditable long after timelines move on.

---

## 🚀 Getting Started

#### Prerequisites
- Python ≥ 3.11, Git
- (Optional) Rust toolchain for native acceleration

#### Setup
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -U pip wheel
pip install -r requirements.txt
```

#### (Optional) Build Native Extension
```bash
pip install maturin
cd tsarcore_native
maturin develop --release

# -- Optional --
maturin develop --release --features parallel

# -- Run Test --
python tests/native_test.py
```
> You can Switch python or native acceleration in [`src/tsarchain/utils/config.py`](src/tsarchain/utils/config.py) : set `NATIVE = 0` or `1`.

---

## 🏃🏻‍♂️ Quickstart

**Run a Miner/Node**
```bash
# GUI
python apps/miner_gui.py
# CLI
python apps/cli_miner.py
```

**Run the GUI Wallet**
```bash
python apps/kremlin.py
```

> **Tip:** For public devnet tests, lock `GENESIS_HASH`, keep `ALLOW_AUTO_GENESIS = 0`, enable the chain-work rule and reorg limits, and tune difficulty/LWMA for your network size.

---

## ⚙️ Devnet Quick Config

```python
# =============================================================================
# IDENTITY & NETWORK
# =============================================================================
ADDRESS_PREFIX      = "tsar"
NET_ID_DEV          = "gulag-net"

# =============================================================================
# CONSENSUS / DIFFICULTY
# =============================================================================
INITIAL_BITS       = 0x1E00FFFF
MAX_BITS           = 0x1F0FFFFF
TARGET_BLOCK_TIME  = 37             # 37 Sec
LWMA_WINDOW        = 75             # Block's
FUTURE_DRIFT       = 7200           # 2 Hours
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
REORG_LIMIT             = 100

# DIFF CLAMP
ENABLE_DIFF_CLAMP       = True
DIFF_CLAMP_MAX_UP       = 1.8
DIFF_CLAMP_MAX_DOWN     = 0.5

# Emergency Difficulty Adjustment (EDA)
ENABLE_EDA              = True
EDA_WINDOW              = 48
EDA_TRIGGER_RATIO       = 5.0
EDA_EASE_MULTIPLIER     = 2.5

# =============================================================================
# P2P / PORTS
# =============================================================================
PORT_RANGE_DEV     = (38169, 38178)

BOOTSTRAP_DEV      = (
    ("31.97.51.207", 38169),
)
```

> To see the entire project configuration, you can check in [`src/tsarchain/utils/config.py`](src/tsarchain/utils/config.py)


---

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

- Smarter mempool relay + anti-DoS
- Graffiti & Storage Node incentives
- Wallet UX hardening and recovery tooling

---

## 📜 License

MIT
