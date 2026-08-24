---
name: graffiti-protocol
description: Development, compilation, testing, benchmarking, and devnet orchestration guide for the Graffiti Protocol codebase (Rust native bindings, Python core, Kremlin wallet, Archivist node, CLI tools, and website explorer).
---

# Graffiti Protocol Developer Guide & Workflows

Use this skill when developing, testing, building, benchmarking, or orchestrating components in the **Graffiti Protocol / TsarChain** repository.

---

## 1. Key Project Components & Architecture

1. **Rust Core (`tsarcore_native/`)**: Native PyO3 Rust extension accelerating RandomX PoW, cryptography, block header hashing, and batch signature verification.
2. **TsarChain Core (`src/tsarchain/`)**: Python implementation of consensus (RandomX + LWMA difficulty), UTXO ledger, SegWit transactions (`tsar1` Bech32), mempool, P2P networking, and state management.
3. **Kremlin Wallet (`src/kremlin/` / `apps/wallet.py`)**: Light wallet GUI (PyQt/PySide) supporting transactions, cultural archiving (Graffiti posts/comments/tips), and Signal X3DH + Double Ratchet encrypted P2P chat.
4. **Archivist Storage Node (`src/archivist/` / `apps/cli_archivist.py`)**: Distributed storage layer providing Proof of Retention challenges, file chunk upload/download RPCs, and epoch payout processing.
5. **Node & Miner CLI (`apps/cli_node_miner.py`)**: CLI runner for full nodes, block mining, and devnet genesis initialization.
6. **Website Explorer (`src/web/`)**: Web frontend & backend for visualizing blocks, transaction details, and Graffiti art.

---

## 2. Environment Setup & Activation

### Automatic Setup Script (Recommended)

Run the bootstrap script to install dependencies (Rust, CMake, Python 3.12, Node.js) and build native extensions:

**Windows (PowerShell):**
```powershell
.\setup.ps1
. .\activate_env.ps1
```

**Linux / macOS (Bash):**
```bash
chmod +x setup.sh
./setup.sh
source activate_env.sh
```

### Manual Environment Activation

If environment is already set up:
```powershell
# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\src"
```

```bash
# Linux / macOS (Bash)
source .venv/bin/activate
export PYTHONPATH=src
```

---

## 3. Building Native Extension (`tsarcore_native`)

Whenever Rust code in `tsarcore_native/` is modified or when setting up the environment:

### Development Build (Maturin)
```powershell
cd tsarcore_native
..\.venv\Scripts\maturin.exe develop --release --features parallel
cd ..
```

### Alternative Pip Install
```bash
pip install ./tsarcore_native
```

---

## 4. Running Applications & Devnet Orchestration

### A. Network Genesis Initialization (`--init-genesis`)
To start a new network or testnet, the first (bootstrap) node must mine Block 0 and set the **LMDB Genesis Lock**:
```bash
python apps/cli_node_miner.py --init-genesis
```

### B. Running a Node / Miner
```bash
# Run full node + miner (normal mining mode)
python apps/cli_node_miner.py

# Run full node only (relay node / no mining)
python apps/cli_node_miner.py --node-only
```

### C. Running Archivist Storage Node
Required for handling Graffiti payloads (art/posts/retention challenges):
```bash
python apps/cli_archivist.py
```

### D. Running Kremlin Wallet (GUI)
```bash
python apps/wallet.py
```

### E. Resetting Local Testnet Data
To wipe local chain state and restart a private testnet:
```bash
# Windows PowerShell
Remove-Item -Recurse -Force data

# Linux / Bash
rm -rf data
```

---

## 5. Testing & Benchmarking Workflows

### 1. Run Rust Core Unit Tests
```bash
cd tsarcore_native
cargo test
cd ..
```

### 2. Run Python Unit Tests & Coverage
```powershell
# Standard pytest execution:
$env:PYTHONPATH="src"; pytest

# Single test file / module:
$env:PYTHONPATH="src"; pytest tests/unit/tsarchain/consensus/blockchain_test.py -v

# Pytest with coverage report:
$env:PYTHONPATH="src"; pytest --cov=src --cov-report=term-missing

# NOTE: always use .venv to run python tests.
```

```bash
# Linux / WSL (headless GUI tests via xvfb):
xvfb-run -a env PYTHONPATH=src pytest
```

### 3. Run Native RandomX Benchmarks
```bash
python benchmarks/native_bench.py
```

---

## 6. Code Style & Conventions: Strict Prohibition of `hasattr`

> [!IMPORTANT]
> **DO NOT USE `hasattr()` ANYWHERE IN THIS CODEBASE.**
> The Graffiti Protocol monorepo is strictly clean of `hasattr()`. 
> - Always prefer direct attribute access, explicit method invocation, or `getattr(obj, "attr_name", default)` when attributes are truly optional.
> - For callables, use `ser = getattr(obj, "method", None); if callable(ser): ...`.
> - Do not write defensive shims with `hasattr()`. Trust established data contracts and concrete class implementations across core models (`Block`, `Tx`, `TxIn`, `TxOut`, `GraffitiRegistry`, etc.).

---

## 7. Verification & PR Guidelines

Before declaring success or submitting pull requests:
1. Ensure all Rust unit tests pass (`cargo test` inside `tsarcore_native`).
2. Ensure all Python unit tests pass (`pytest`).
3. Verify native extension builds without errors (`maturin develop --release`).
4. Ensure guarded core consensus files (`src/tsarchain/consensus/`, `src/kremlin/security/`, `tests/`) maintain integrity.
5. Verify that no `hasattr` usage has been introduced into the codebase.
