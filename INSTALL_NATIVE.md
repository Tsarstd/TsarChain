# Install `tsarcore_native` (Rust Native Acceleration)

`tsarcore_native` is the Rust + PyO3 native acceleration module for **TsarChain**.
When available, TsarChain will automatically use native paths for critical code
(e.g. sigops counting, ECDSA verify (low-S), Merkle root, etc.). If the module
is missing or fails to import, TsarChain gracefully falls back to pure‑Python.

> **Default toggle:** See `src/tsarchain/utils/config.py` → `NATIVE = 1` to enable,
> or set `NATIVE = 0` to force pure‑Python.

---

## ⚠️ Consensus: Merkle Root is locked to Python ⚠️

To maintain consensus determinism across platforms/architectures, the `merkle_root` function used by consensus is locked to the Python implementation** (native is not used for the final merkle result in consensus).
This means that even though Rust bindings are available, merkle calculations affecting blocks/tx still use the Python version. See the implementation and comments in `helpers.py`.

---

## TL;DR

```bash
# From repo root
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

pip install --upgrade pip
pip install maturin            # build backend

cd tsarcore_native
maturin develop --release      # build & install into the active venv
```

To build a wheel instead:
```bash
cd tsarcore_native
maturin build --release
pip install target/wheels/tsarcore_native-*.whl
```

---

## 1) Prerequisites

- **Python** 3.8–3.12 (virtualenv recommended)
- **Rust toolchain (stable)** via [`rustup`](https://rustup.rs/)
- **maturin** (build backend). Installed via `pip install maturin`
- Platform toolchain:
  - **Windows**
    - Install *Visual Studio Build Tools* (C++ workload).
    - Rust target: MSVC (default if using standard rustup on Windows).
  - **macOS**
    - `xcode-select --install` (Command Line Tools) + rustup.
    - Apple Silicon is supported; the wheel will match your Python arch (arm64/x86_64).
  - **Linux (Debian/Ubuntu)**
    - `sudo apt-get update && sudo apt-get install -y build-essential python3-dev`
    - Install rustup per official docs.

> Ensure your Python architecture (x64/arm64) matches the Rust target; mismatch can cause import errors.

---

## 2) Install Options

### Option A — Fast Dev (editable)
Build and install directly into the current virtualenv (best for contributors).

```bash
# repo root
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

pip install --upgrade pip
pip install maturin

cd tsarcore_native
maturin develop --release
```

### Option B — Release Wheel (distributable)
Build a wheel and install it explicitly.

```bash
# activate venv first
pip install --upgrade pip maturin

cd tsarcore_native
maturin build --release
pip install target/wheels/tsarcore_native-*.whl
```

### Option C — Via `pip` (PEP 517)
Pip will invoke maturin (maturin must be installed in the environment).

```bash
# repo root (venv active)
pip install --upgrade pip maturin
pip install ./tsarcore_native
```

---

## 3) Enable Native in TsarChain

Set the native toggle in config:

```python
# src/tsarchain/utils/config.py
NATIVE = 1  # 1 = prefer Rust acceleration, 0 = force pure-Python
```

TsarChain will attempt to import `tsarcore_native`. On failure, it falls back automatically.

---

## 4) Quick Self‑Test

```bash
python - <<'PY'
import tsarcore_native as n
print("[native] count_sigops(OP_CHECKSIG) ->", n.count_sigops(b"\xac"))  # expect 1
mr = n.merkle_root([])
print("[native] merkle_root([]) ->", type(mr), len(mr) if isinstance(mr,(bytes,bytearray)) else None)
print("OK")
PY
```

Or run the bundled benchmark/test (if available):

```bash
python -m tests.native_test --sigops-iters 500000 --merkle-n 2000 --merkle-reps 200 --ecdsa-keys 5 --ecdsa-iters 5000
```

> If some functions (e.g., `sighash_bip143`) are not yet implemented in the native module,
> TsarChain will transparently use Python implementations.

---

## 5) Troubleshooting

- **`ModuleNotFoundError: tsarcore_native`**
  - Ensure you built and installed into the **same** environment where you run TsarChain.
  - Re-activate the venv and `pip show tsarcore_native` to verify installation.
- **Linker / toolchain errors**
  - Update toolchain: `rustup update`
  - Windows: ensure **MSVC Build Tools** installed; use “x64 Native Tools” prompt if needed.
  - Linux: check `build-essential` and `python3-dev` installed.
- **Arch mismatch**
  - Ensure Python x64 ↔ Rust x64 (or arm64 ↔ arm64). On macOS Apple Silicon,
    prefer a native arm64 Python to avoid Rosetta mismatches.
- **Rebuild clean**
  - `cd tsarcore_native && maturin develop --release --strip` to strip symbols and rebuild.

---

## 6) CI / Release (Optional)

For publishing wheels, consider GitHub Actions with `maturin-action` to build for
multiple targets (macOS, Linux manylinux, Windows) and upload artifacts. Example
snippets can be added later to `.github/workflows/release.yml`.

---

## 7) Notes

- This module uses **PyO3**; the Python ABI compatibility follows what maturin builds.
- Performance-sensitive features (sigops, merkle, ECDSA verify) benefit most from native.
- Pure‑Python remains the reference implementation and safe fallback.

---

Happy Coding — *Long Live The Voice Sovereignty*.
