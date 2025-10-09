# Install `tsarcore_native` (Rust Native Acceleration)

`tsarcore_native` is the Rust + PyO3 native acceleration module for **TsarChain**.
When available, TsarChain will automatically use native paths for performance‑critical routines
(sigops counting, ECDSA verify (low‑S) incl. batch, BIP143 sighash, hashing, etc.).
If the module is missing or fails to import, TsarChain **gracefully falls back to pure‑Python**.

> **Native toggle:** configure in `src/tsarchain/utils/config.py` → `NATIVE = 1` (prefer native),
> set `NATIVE = 0` to force pure‑Python.

---

## ⚠️ Consensus Note: Merkle Root is Locked to Python

For deterministic consensus across platforms/architectures, the **`merkle_root` used by consensus
is locked to the Python implementation**. The native Merkle function may exist for diagnostics, but
block/tx consensus calculation *always* calls the Python version. See the binding comment in
`helpers.py` (look for the wrapper that returns the Python `_py_merkle_root`).

---

## TL;DR

```bash
# From your repo root
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate

pip install --upgrade pip maturin

cd tsarcore_native
maturin develop --release      # build & install into the active venv
```

Want a distributable wheel?

```bash
cd tsarcore_native
maturin build --release
pip install target/wheels/tsarcore_native-*.whl
```

---

## 1) Prerequisites

- **Python** 3.8–3.12 (recommended to use a virtual environment)
- **Rust toolchain (stable)** via [`rustup`](https://rustup.rs/)
- **maturin** (`pip install maturin`)

Platform notes:
- **Windows**: install *Visual Studio Build Tools* (C++ workload). Rust target should be **MSVC** (default).
- **macOS**: `xcode-select --install` for Command Line Tools. Apple Silicon is supported; your wheel arch follows your Python arch (arm64/x86_64).
- **Linux (Debian/Ubuntu)**: `sudo apt-get update && sudo apt-get install -y build-essential python3-dev` in addition to rustup.

> Ensure the Python architecture matches Rust’s target (x64 ↔ x64, arm64 ↔ arm64).

---

## 2) Installation Options

### A) Dev‑friendly (editable)

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate

pip install --upgrade pip maturin
cd tsarcore_native
maturin develop --release
```

### B) Build a wheel (for distribution)

```bash
# with your venv active
pip install --upgrade pip maturin
cd tsarcore_native
maturin build --release
pip install target/wheels/tsarcore_native-*.whl
```

### C) PEP 517 install via `pip`

```bash
# from repo root (venv active)
pip install --upgrade pip maturin
pip install ./tsarcore_native
```

### (Optional) Enable parallel code paths

If you added conditional parallel implementations in Rust, you can expose them with a feature flag:

```bash
cd tsarcore_native
maturin develop --release --features parallel
# or
maturin build --release --features parallel
```

---

## 3) Enable Native in TsarChain

Set the toggle in config:

```python
# src/tsarchain/utils/config.py
NATIVE = 1  # 1 = prefer Rust acceleration, 0 = force pure‑Python
```

On import, TsarChain tries `import tsarcore_native`; if it fails, it auto‑fallbacks to Python.

---

## 4) Quick Self‑Test (sanity)

Run a very small import & call check in your active environment:

```bash
python - <<'PY'
import tsarcore_native as n
print("[native] available symbols:", [k for k in dir(n) if not k.startswith("_")][:8], "...")
print("[native] count_sigops(OP_CHECKSIG):", n.count_sigops(b"\xac"))
print("[native] hash256('abc'):", n.hash256(b"abc"))
print("[native] hash160('abc'):", n.hash160(b"abc"))
print("OK")
PY
```

> Remember: for **consensus**, Merkle root remains Python‑only (see section above).

---

## 5) How to Test with `native_test.py`

`native_test.py` performs **correctness parity** checks (Python vs Native where applicable) and **micro‑benchmarks**.

What it covers:
- Parity: `hash256/hash160`, ECDSA verify (strict DER + low‑S), **BIP143 SIGHASH_ALL**,
  and diagnostic **Merkle** comparisons (for debugging only — consensus still uses Python).
- Micro‑benchmarks: sigops counting, Merkle tree building, ECDSA single verify, ECDSA batch verify, and hashing.

### Run with defaults

```bash
# from repo root, in the project venv
python native_test.py
```

### Useful CLI options

```bash
python native_test.py   --sigops-iters 250000   --merkle-n 1000 --merkle-reps 200   --ecdsa-keys 200 --ecdsa-iters 5000   --batch-keys 256 --batch-iters 2048   --hash-total 1500000   --strict-merkle \            # fail the run if any merkle mismatch
  --show-merkle-debug \        # print diagnostic details for merkle differences
  --no-bench-batch \           # skip batch verify benchmark
  --no-bench-hash              # skip hashing benchmarks
```

**Expected output (high‑level):**
- A header line stating whether native loaded (`True/False`) and why.
- `== correctness ==` section showing OK/mismatch per component (with details when mismatched).
- `== microbench ==` section with throughputs (ops/s, trees/s, verif/s).

If `--strict-merkle` is set and a mismatch is detected, the script **raises** after printing a minimal repro.

---

## 6) Troubleshooting

- **`ModuleNotFoundError: tsarcore_native`**
  - Verify you built inside the **same venv** you’re running.
  - Re‑activate venv and check with `pip show tsarcore_native`.

- **Toolchain/linker errors**
  - `rustup update` to ensure a fresh stable toolchain.
  - **Windows**: make sure *MSVC Build Tools* are installed; open the “x64 Native Tools” prompt if needed.
  - **Linux**: ensure `build-essential` and `python3-dev` are installed.

- **Architecture mismatch**
  - Python x64 requires Rust x64; Python arm64 requires Rust arm64. On macOS Apple Silicon,
    prefer a native arm64 Python instead of Rosetta emulation for clean wheels.

- **Clean rebuild**
  - `cd tsarcore_native && maturin develop --release --strip`

- **`maturin` complains about `LICENSE`**
  - Example: `Failed to read .../tsarcore_native/LICENSE`
  - Add a `LICENSE` file in `tsarcore_native/`, or set the appropriate `license` / `license-file`
    metadata fields in `Cargo.toml`.

---

## 7) CI / Release (optional)

You can use GitHub Actions with `maturin-action` to build wheels for macOS, manylinux, and Windows,
then upload artifacts to a release. Keep your workflow minimal at first; expand once basics are green.

---

## 8) Notes

- Built with **PyO3**; ABI compatibility follows the wheel built by `maturin`.
- The biggest wins from native are: sigops, ECDSA verify (low‑S), BIP143 sighash, batch verify, and hashing.
- **Consensus Merkle Root is Python‑locked** by design; native Merkle should be treated as a diagnostic helper only.

---

Happy coding — *Long Live The Voice Sovereignty*.
