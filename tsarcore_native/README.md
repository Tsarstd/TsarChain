# tsarcore_native (Rust + pyo3)

Native acceleration module for **TsarChain**.

## What’s inside (current API)

- `count_sigops(script: bytes) -> int`  
  Counts `CHECKSIG` (+1) and `CHECKMULTISIG` (+min(n or 20, 20)) including their `VERIFY` variants, mirroring typical Bitcoin-style limits.

- `hash256(data: bytes) -> bytes32`  
  SHA256d (double-SHA256).

- `hash160(data: bytes) -> bytes20`  
  RIPEMD160(SHA256(data)).

- `secp_verify_der_low_s(pubkey: bytes, digest32: bytes, der_sig: bytes) -> bool`  
  Strict DER parse; rejects **high-S** signatures (normalized-s must match original). Accepts 33B/65B pubkeys and 64B raw `x||y` (treated as uncompressed).

- `secp_verify_der_low_s_many(triples: Sequence[tuple[pubkey, digest32, der_sig]], enforce_low_s: bool = True, parallel: bool = False) -> list[bool]`  
  Batch verify. If built with feature `parallel`, set `parallel=True` to use Rayon.

- `sighash_bip143(tx_bytes: bytes, input_index: int, script_code: bytes, value_sat: int, sighash_type: int) -> bytes32`  
  Native **BIP143** preimage + SHA256d for **`SIGHASH_ALL` only**. Other sighash types raise `ValueError` so your Python shim can fallback.

- `merkle_root(txids: Iterable[bytes32]) -> bytes32`  
  Double-SHA256 Merkle root over 32‑byte leaves. For odd nodes, the last hash is duplicated (Bitcoin-style).

> Endianness note: pass **little‑endian txids** if you want a Bitcoin‑compatible block header merkle root.

## Build & install

```bash
# Dev install (local editable wheel)
pip install maturin
maturin develop --release
# optional: enable parallel batch verify
maturin develop --release --features parallel

# Build wheel only
maturin build --release
# wheel will appear under target/wheels/
```

## Usage (Python)

```python
import tsarcore_native as tc

assert tc.count_sigops(b"\xac") == 1  # OP_CHECKSIG
d32 = bytes.fromhex("00"*32)
pk  = bytes.fromhex("02" + "11"*32)    # compressed (example only)
sig = b"\x30..."                      # strict DER (example only)

ok = tc.secp_verify_der_low_s(pk, d32, sig)

# Batch verify (optional parallel)
pairs = [(pk, d32, sig)]
results = tc.secp_verify_der_low_s_many(pairs, enforce_low_s=True, parallel=False)
```

## Safety notes

- No `unsafe`, no panics, strict bounds checks when parsing transaction bytes & varints.
- `secp_verify_der_low_s` and the batch verifier reject **high‑S** by default (set `enforce_low_s=False` in batch mode for legacy).
- `sighash_bip143` currently supports **`SIGHASH_ALL`** natively; use your Python fallback for others (e.g., `ANYONECANPAY`, `SINGLE`, `NONE`).

## Changelog

- **0.1.1** — Docs synced with code: expose `hash256`, `hash160`, `secp_verify_der_low_s_many`, native `sighash_bip143` (ALL); clarify merkle root behavior & parallel feature.
- **0.1.0** — Initial release.
