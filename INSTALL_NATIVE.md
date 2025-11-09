# Install `tsarcore_native` (Rust Native Acceleration)

`tsarcore_native` is the Rust + PyO3 native acceleration module for **TsarChain**.
TsarChain now **requires** this module: all consensus-critical routines (sigops counting,
ECDSA verify (low-S) incl. batch, BIP143 sighash, hashing, block validation, etc.) call the
Rust bindings directly. If the module is missing or fails to import, TsarChain will raise
at startup—there is no longer a Python fallback or runtime toggle.

---

## ⚠️ Consensus Note: Single Native Path

For deterministic consensus across platforms/architectures, every node now runs the exact same
Rust implementation shipped in `tsarcore_native` for operations such as `merkle_root`,
`sighash_bip143`, sigops counting, and block validation. The historical Python implementations have
been removed to avoid divergence, so keeping the native library installed is mandatory.

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

## 3) Integrate with TsarChain

Install `tsarcore_native` inside the same environment that runs TsarChain. On startup the code
imports the module and will abort with a descriptive error if the binding is unavailable. Nothing
else needs to be toggled in `config.py`.

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

## 5) How to Test with `native_test.py`

`tests/native_test.py` is the all-in-one harness for the Rust bindings. It now runs **only native paths** and checks:

- Deterministic vectors for `hash256`, `hash160`, `merkle_root`, `bip143_sig_hash`, strict DER low-S verification (single + batch).
- Native block validation via `validate_block_txs_native` (happy-path block + common failure reasons: witness tamper, immature coinbase, missing witness, unsupported script).
- Micro-benchmarks for sigops counting, merkle building, single/batch ECDSA verify, and hashing.

### Run with defaults

```bash
# from repo root, inside your project venv
python tests/native_test.py
```

Useful knobs (keep or drop as needed):

```bash
python tests/native_test.py \
  --sigops-iters 250000 \
  --merkle-n 1000 --merkle-reps 200 \
  --ecdsa-keys 200 --ecdsa-iters 5000 \
  --batch-keys 256 --batch-iters 2048 \
  --hash-total 1500000 \
  --no-bench-batch --no-bench-hash   # skip heavy benches if you only need correctness
```

### Sample output

When everything is installed correctly you should see something like:

```
Native backend is mandatory; helpers module imported tsarcore_native successfully.
Functions available: ['count_sigops_in_script', 'bip143_sig_hash', 'verify_der_strict_low_s', 'merkle_root', 'hash256', 'hash160', 'batch_verify_der_low_s']

== correctness checks ==
[ok] hash256/hash160 vectors
[ok] merkle root deterministic vector
[ok] verify_der_strict_low_s (low-S true, high-S false)
[ok] batch_verify_der_low_s == single verify
[ok] bip143_sig_hash known vector (SIGHASH_ALL)

== native block validation ==
[block] valid block: ok
[block] invalid witness: ok
[block] immature coinbase: ok
[block] missing witness: ok
[block] unsupported script: ok

== microbench ==
[sigops] 250.000 loops in 0.101s -> 2.468.004 ops/s
[merkle] 200 trees (n=1000) in 0.070s -> 2843.6 trees/s
[ecdsa-single] 5.000 verifications in 0.245s -> 20.433 verif/s
[ecdsa-batch] ~2.048 verifications in 0.016s -> ~129.146 verif/s
[hash256] 1.500.000B in 0.001s
[hash160] 1.500.000B in 0.001s
```

Any deviation (e.g., `[block] …` showing a failure reason) means the native validator caught a real issue—fix the underlying data before moving on.

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
