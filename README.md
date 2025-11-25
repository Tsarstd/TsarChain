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

# Layer 1 Blockchain - for digital preservation and voice sovereignty

*A proof‑of‑work, UTXO‑based chain for digital preservation — durable, verifiable, and community‑owned.*

TsarChain focuses on **Voice Sovereignty**: preserving *cultural archives*, *art*, and *testimonies* so that *digital traces* don't disappear. Its decentralized architecture keeps evidence **verifiable** and **publicly auditable**, providing creative communities and cultural researchers with a durable **preservation platform**.


---

## Table of Contents
- [Demo](#️-demo)
- [ScreenShoots](#️-screenshoots)
- [Project Status](#️-project-status)
- [Features at a Glance](#-features-at-a-glance)
- [Why Voice Sovereignty](#-why-voice-sovereignty)
- [Getting Started](#-getting-started)
- [Quickstart](#️-quickstart)
- [Config Codebase (Preview)](#️-config-codebase-preview)
- [Mining Modes](#️-mining-modes)
- [Project & Data Structure's](#️-project--data-structures)
- [Security Notes](#-security-notes)
- [Contributing](#-contributing)
- [Roadmap](#️-roadmap)
- [Documentation](#-documentation)
- [License](#-license)

---

## 🎞️ Demo

- ***Wallet (Send Tx)***
  <details>
    <summary>See Transaction demo</summary>
    <img src="assets/demo/payment_demo.gif">
  </details>

- ***CLI Mining***
  <details>
    <summary>See Mining demo</summary>
    <img src="assets/demo/mining_demo.gif">
  </details>

---

## 🖼️ ScreenShoots

- ***Wallet Tab***
  <details>
    <summary>Preview 1</summary>
    <img src="assets/screenshoot/main.png">
  </details>
  <details>
    <summary>Preview 2</summary>
    <img src="assets/screenshoot/wallet_tab1.png">
  </details>

- ***Send Tab***
  <details>
    <summary>Preview 1</summary>
    <img src="assets/screenshoot/send_tab1.png">
  </details>
  <details>
    <summary>Preview 2</summary>
    <img src="assets/screenshoot/send_tab2.png">
  </details>

- ***Explore Tab***
  <details>
    <summary>Preview 1</summary>
    <img src="assets/screenshoot/explore_tab1.png">
  </details>
  <details>
    <summary>Preview 2</summary>
    <img src="assets/screenshoot/explore_tab2.png">
  </details>
  <details>
    <summary>Preview 3</summary>
    <img src="assets/screenshoot/explore_tab3.png">
  </details>

- ***History Tab***
  <details>
    <summary>Preview 1</summary>
    <img src="assets/screenshoot/history_tab1.png">
  </details>

- ***P2P Chat Tab***
  <details>
    <summary>Preview 1</summary>
    <img src="assets/screenshoot/chat_tab1.png">
  </details>

- ***Network Info Tab***
  <details>
    <summary>Preview 1</summary>
    <img src="assets/screenshoot/network_tab1.png">
  </details>

---

## ⚠️ Project Status

#### ✅ Implemented
- Kremlin Wallet (Light Wallet)
- Wallet generation (Bech32)
- Address prefix `tsar1`
- Genesis Block
- Proof-of-Work (RandomX)
- Chat Feature (X3DH & Double Ratchet)
- Coinbase Reward
- UTXO System
- SegWit Transactions (P2WPKH)
- Fee Mechanism
- Mempools
- Multi-node Networking
- Transaction & Block Validation
- Chain Validation

#### 🚧 In Development
- Storage Node
- Graffiti
- Some Security
- Some UI/UX Wallet
- etc.

---

## ✨ Features at a Glance

- **Consensus** – RandomX PoW with LWMA difficulty targeting predictable block times.
- **Ledger model** — UTXO with SegWit serialization and signature validation (secp256k1).
- **Addresses** — Bech32, prefix **`tsar1`** (P2WPKH).
- **Wallet** — “Kremlin” light wallet (GUI) for send/receive, explorer, and secure P2P chat.
- **Secure chat** — X3DH key agreement + Double Ratchet, safety numbers, and key-change alerts.
- **Networking** — Peer discovery with bootstrap support, multi-port range, full block/tx relay.
- **Observability** — Structured logs for node, miner, and wallet.

---

## 🧭 Why Voice Sovereignty?

Platforms curate history; networks preserve it. TsarChain treats each message, artwork, or testimony as **expressive value** anchored in blocks and protected by open consensus — not for confrontation, but for the care of collective memory.

---

## 🚀 Getting Started

#### Requirements:
- Python ≥ 3.11, Git
- Rust toolchain for native acceleration
- CMake 3.x+

#### 1. Setup
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements.txt
```

#### 2. Build Native Extension
- TsarChain `tsarcore_native` (RandomX, hashing, and some heavy routines) is built with Rust + CMake.  
- You need **CMake 3.x+** installed on your system before running `maturin develop`.
  ```bash
  # After Instaling CMake
  pip install maturin
  cd tsarcore_native
  maturin develop --release --features parallel

  # -- Run Test --
  python tests/native_test.py
  ```
  > ⚠️ If there are any installation problems or issues, read the complete instructions and troubleshooting steps at: [`INSTALL_NATIVE.md`](INSTALL_NATIVE.md)

- TsarChain always loads the Rust extension; ensure `tsarcore_native` is installed in the active environment. **see more detailed information about tsarcore_native* [`here`](tsarcore_native/README.md)

---

## 🏃🏻‍♂️ Quickstart

**Run a Miner/Node**
```bash
# GUI (lite-friendly, limited to 1 core)
python apps/miner_gui.py

# Stateless CLI miner (no on-disk blockchain, just hashing)
python apps/cli_miner.py

# Full node + miner (keeps blockchain DB + snapshot gateway)
python apps/cli_node_miner.py

# GUI Wallet
python apps/kremlin.py
```

> **Tip:** For public devnet tests, lock `GENESIS_HASH`, keep `ALLOW_AUTO_GENESIS = 0`, enable the chain-work rule and reorg limits, and tune difficulty/LWMA for your network size.

---

## ⚙️ Config Codebase (Preview)

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
```

> To see the entire project configuration, you can check in [`src/tsarchain/utils/config.py`](src/tsarchain/utils/config.py)

🔧 **RandomX knobs** live in the same file.Tune `RANDOMX_FULL_MEM`, `RANDOMX_LARGE_PAGES`, and `RANDOMX_KEY_EPOCH_BLOCKS` if you need lighter verification nodes or want to rotate the RandomX seed more/less frequently.
- **Dev/Test**: `RANDOMX_FULL_MEM=False`, `RANDOMX_LARGE_PAGES=False`, `RANDOMX_CACHE_MAX=1`, `RANDOMX_KEY_EPOCH_BLOCKS=64`.

---

## ⛏️ Mining Modes

- **GUI Miner (`apps/miner_gui.py`)** ships with Lite GUI mode enabled and limits RandomX to one core by default so the Tkinter UI stays responsive.
- **Stateless CLI Miner (`apps/cli_miner.py`)** keeps chain data in-memory, fetches the latest tip from peers, mines, then broadcasts (no snapshots or DB).
- **Full Node CLI Miner (`apps/cli_node_miner.py`)** persists the entire blockchain, handles snapshot bootstrap, wallet gateway traffic, and can run `--node-only` for infra roles.

Use the GUI for monitoring log, `cli_miner.py` for raw hash power, and `cli_node_miner.py` when you need full-node responsibilities.

---

## 🏗️ Project & Data Structure's

```
TsarChain/
├── apps/                    # Entry points (Executable)
│   ├── archivist.py         # Storage Node (Archivist)
│   ├── cli_miner.py         # Miner CLI (Stateless)
│   ├── cli_node_miner.py    # Miner CLI (Full Node)
│   ├── kremlin.py           # Wallet GUI (Kremlin Wallet)
│   └── miner_gui.py         # Miner GUI (Tkinter)
│
├── assets/                  # Logo, img, etc.
├── docs/                    # Documentation, Whitepaper & Draft Protocol
├── scripts/                 # Development utility scripts
├── src/
│   └── tsarchain/           # Python main packages
│       ├── consensus/       # Blockchain Logic (PoW, Difficulty, Validation, etc.)
│       ├── contracts/       # Smart Contracts (Graffiti) & Archivist Module
│       ├── core/            # Core data structure (Block, Transaction, Coinbase)
│       ├── mempool/         # MemPool Management & Policy
│       ├── network/         # P2P Networking, RPC, & Gossip Protocol
│       ├── storage/         # Database Layer (LMDB/JSON mode & UTXO)
│       ├── utils/           # Global Configurations (config.py) & Helper
│       └── wallet/          # Wallet Logic, Security, & UI Components
│
├── tests/                   # Unit testing (native & double rachet)
├── tools/                   # LMDB database tools & Snapshot maintenance
└── tsarcore_native/         # Native Module (Rust + PyO3)
    └── src/                 # Source code Rust (lib.rs, networking.rs, validation.rs)
```

The example data of `block, utxo's & mempool` below, shows a transaction between 1 sender and 1 miner recipient.
- ***Block Data Structure (.json):***
  <details>
    <summary>See Preview</summary>

  ```json
  {
    "height": 9,
    "version": 1,
    "prev_block_hash": "000a0638cc7d73011bc4db7616eba7badacfa3f1c3cadaa61385b38e0cf629be",
    "merkle_root": "3cbf3c045716ad5890d064a34cf187f12444b36a9de24a656a87375bacf7eca5",
    "timestamp": 1763488189,
    "bits": 522190847,
    "nonce": 229,
    "hash": "000a17e45cddd85cf6a41744050ba9026c99df6424b9a2e8aa93592dda2ff8c8",
    "transactions": [
      {
        "version": 1,
        "inputs": [
          {
            "txid": "0000000000000000000000000000000000000000000000000000000000000000",
            "vout": 4294967295,
            "amount": 0,
            "script_sig": "01091d506176656c5f53686572656d65745f323031365f346b46525350626276",
            "witness": []
          }
        ],
        "outputs": [
          {
            "amount": 25000007280,
            "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
          }
        ],
        "locktime": 0,
        "txid": "00d219b3fa137584aa808e546bbc7f939f74125e5c6aaf287e1e0eeec996ac33",
        "fee": 0,
        "is_coinbase": true,
        "type": "Coinbase",
        "to_address": "tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr",
        "reward": 25000007280,
        "block_id": "Pavel_Sheremet_2016_4kFRSPbbv",
        "height": 9
      },
      {
        "version": 1,
        "inputs": [
          {
            "txid": "c3f8cfe9961bc02f619f2074240777936cef3cba0495aebd13cd1f0e8b775c77",
            "vout": 0,
            "amount": 25000000000,
            "script_sig": "",
            "witness": [
              "3045022100d59497380ca6e007fe5490e786d4be10ed958a246f0680ba559d57817e87b8b8022009a04fac29973744ee9bc9528c76206755466b435427bd2aa50eb4bf7d5f7ca601",
              "0317e6da93b8800805abbdf88533d8c3729acdcee1f4d3fcf8c4587f16c3437654"
            ]
          },
          {
            "txid": "1e06c0b7d7b41f8f940a4ea7b8289829d80660df79bc9fa2b1448621c9cfb119",
            "vout": 0,
            "amount": 250000000000000,
            "script_sig": "",
            "witness": [
              "3045022100e82db6d6b09cd72d2b23e8b96b6e07e8996be5b4f941b90537bfdbea702b9b9202207c14783f79ce4df23e50d117cf1760e13ba676ff30f179420cf497c972934cb701",
              "0317e6da93b8800805abbdf88533d8c3729acdcee1f4d3fcf8c4587f16c3437654"
            ]
          }
        ],
        "outputs": [
          {
            "amount": 1200000000000,
            "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
          },
          {
            "amount": 248824999992720,
            "script_pubkey": "0014266dd5c8b1fb3a0d18710146713af668b762dc6f"
          }
        ],
        "locktime": 0,
        "txid": "80817285aaf676697420b857d58afa8da19f3b1e785d12cc05bd30ab6b0d1b2f",
        "fee": 7280,
        "is_coinbase": false
      }
    ]
  }
  ```
  </details>

- ***UTXO's Data Structure (.json):***
  <details>
    <summary>See Preview</summary>

  ```json
    },
    "00d219b3fa137584aa808e546bbc7f939f74125e5c6aaf287e1e0eeec996ac33:0": {
      "tx_out": {
        "amount": 25000007280,
        "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
      },
      "is_coinbase": true,
      "block_height": 9
    },
    "80817285aaf676697420b857d58afa8da19f3b1e785d12cc05bd30ab6b0d1b2f:0": {
      "tx_out": {
        "amount": 1200000000000,
        "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
      },
      "is_coinbase": false,
      "block_height": 9
    },
    "80817285aaf676697420b857d58afa8da19f3b1e785d12cc05bd30ab6b0d1b2f:1": {
      "tx_out": {
        "amount": 248824999992720,
        "script_pubkey": "0014266dd5c8b1fb3a0d18710146713af668b762dc6f"
      },
      "is_coinbase": false,
      "block_height": 9
    },
  ```
  </details>

- ***MemPool Data Structure (.json):***
  <details>
    <summary>See Preview</summary>
  
  ```json
  {
    "version": 1,
    "inputs": [
      {
        "txid": "c3f8cfe9961bc02f619f2074240777936cef3cba0495aebd13cd1f0e8b775c77",
        "vout": 0,
        "amount": 25000000000,
        "script_sig": "",
        "witness": [
          "3045022100d59497380ca6e007fe5490e786d4be10ed958a246f0680ba559d57817e87b8b8022009a04fac29973744ee9bc9528c76206755466b435427bd2aa50eb4bf7d5f7ca601",
          "0317e6da93b8800805abbdf88533d8c3729acdcee1f4d3fcf8c4587f16c3437654"
        ]
      },
      {
        "txid": "1e06c0b7d7b41f8f940a4ea7b8289829d80660df79bc9fa2b1448621c9cfb119",
        "vout": 0,
        "amount": 250000000000000,
        "script_sig": "",
        "witness": [
          "3045022100e82db6d6b09cd72d2b23e8b96b6e07e8996be5b4f941b90537bfdbea702b9b9202207c14783f79ce4df23e50d117cf1760e13ba676ff30f179420cf497c972934cb701",
          "0317e6da93b8800805abbdf88533d8c3729acdcee1f4d3fcf8c4587f16c3437654"
        ]
      }
    ],
    "outputs": [
      {
        "amount": 1200000000000,
        "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
      },
      {
        "amount": 248824999992720,
        "script_pubkey": "0014266dd5c8b1fb3a0d18710146713af668b762dc6f"
      }
    ],
    "locktime": 0,
    "txid": "80817285aaf676697420b857d58afa8da19f3b1e785d12cc05bd30ab6b0d1b2f",
    "fee": 7280,
    "is_coinbase": false
  }
  ```
  </details>

State - is a database for overall network information. for user requests in the wallet section `Network Info Tab`
- ***State Data Structure (.json):***
  <details>
    <summary>See Preview</summary>

  ```json
    {
    "schema_version": 1,
    "last_updated": "2025-11-19T00:50:21.990876+07:00",
    "identity": {
      "network_id": "gulag-net",
      "address_prefix": "tsar",
      "network_magic_hex": "54534152434841494e"
    },
    "chain": {
      "total_blocks": 11,
      "tip_height": 10,
      "genesis_hash": "0012de8832a4f54b9f316b6cac270c772e5bfcae2d3a3a2d942e968465aa34db",
      "genesis_message": "Every person who is born free has the same rights and dignity. (Munir Said Thalib - 2004-09-07)",
      "tip_hash": "001a5ff14ab67010d7b92f2c7a2c032563dd04111c5f3d223e90bc552167e70a",
      "tip_timestamp": 1763488199,
      "tip_bits": 522190847,
      "tip_target_hex": "0x1fffff00000000000000000000000000000000000000000000000000000000",
      "tip_difficulty": 2048,
      "avg_block_time_sec_window": 179.4,
      "est_network_hashrate_hps_window": 11
    },
    "supply": {
      "max_supply": 25250000000000000,
      "emitted_subsidy": 250250000000000,
      "circulating_estimate": 250199999992720,
      "immature_coinbase": 50000007280,
      "coinbase_maturity": 3,
      "current_block_subsidy": 25000000000,
      "current_epoch": 0,
      "next_halving_height": 235000,
      "blocks_to_halving": 234989
    },
    "transactions": {
      "total_txs": 12,
      "total_non_coinbase_txs": 1,
      "total_fees_paid": 7280,
      "mempool_txs": 0,
      "mempool_vbytes_estimate": 0
    },
    "utxo": {
      "utxo_set_size": 11
    },
    "miners_snapshot": {
      "top_miners": [
        [
          "tsar1qzxzzf5az5guk43mf0z4d94uugat4jcejwglp07",
          6
        ],
        [
          "tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr",
          3
        ],
        [
          "tsar1qyekatj93lvaq6xr3q9r8zwhkdzmk9hr0fmfrss",
          2
        ]
      ]
    },
    "files": {
      "blockchain_json_sha256": "46f1c89ba64a15a40ea58c9a629f899f486a9d42a7b8462038a6611836299711"
    },
    "total_supply": 250250000000000,
    "total_blocks": 11
  }
  ```

  </details>

---

## 🔐 Security Notes

- Chat privacy uses X3DH + Double Ratchet (simple implementation).
- This is experimental software; there haven't been many network security audits, a independet project with little experience in low-level engineering.
- If you run validators/miners publicly, just **mining it!** **fork it!** **learn it!** **Look for vulnerabilities!** and see how blockchain work.
- There's no **testnet** yet, no **mainnet** yet,
- There are no promises of **riches** here.
- There are still many **bugs to fix**. If you want to test publicly, use your own private VPS.

---

## 🫂 Contributing

Pull requests are welcome. Please start with small, well‑scoped changes (docs, tests, logging), then propose larger work via issues. Be respectful: the mission is **Voice Sovereignty**.
> I've provided a logging tool. For easier debugging, you can check [`src/tsarchain/utils/tsar_logging.py`](src/tsarchain/utils/tsar_logging.py)

---

## 🗺️ Roadmap

- Graffiti & Storage Node incentives
- Exploring Graffiti art & Put Graffiti Comment in Kremlin Wallet
- Mobile app 'Graffiti'
- The Voice Sovereignty

---

## 📄 Documentation

**Whitepaper**
- [`Grungepaper - The Voice Sovereignty (EN)`](docs/Grungepaper%20-%20The%20Voice%20Sovereignty%20(EN).pdf) | [*Download*](docs/Grungepaper%20-%20The%20Voice%20Sovereignty%20(EN).pdf?raw=true)
- [`Grungepaper - The Voice Sovereignty (ID)`](docs/Grungepaper%20-%20The%20Voice%20Sovereignty%20(ID).pdf) | [*Download*](docs/Grungepaper%20-%20The%20Voice%20Sovereignty%20(ID).pdf?raw=true)

**Graffiti Protocol**
- [`Graffiti Protocol - Draft v0.1 (EN)`](docs/Graffiti%20Protocol%20-%20Draft%20v0.1%20(EN).pdf) | [*Download*](docs/Graffiti%20Protocol%20-%20Draft%20v0.1%20(EN).pdf?raw=true)
- [`Graffiti Protocol - Draft v0.1 (ID)`](docs/Graffiti%20Protocol%20-%20Draft%20v0.1%20(ID).pdf) | [*Download*](docs/Graffiti%20Protocol%20-%20Draft%20v0.1%20(ID).pdf?raw=true)

**Trademarks & References**
- [`TRADEMARKS.md`](TRADEMARKS.md) [`REFERENCES.md`](REFERENCES.md)

---

## 📜 License

[`MIT`](LICENSE)
