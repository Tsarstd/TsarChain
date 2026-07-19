# tsarcore_native (Rust + pyo3)

Native acceleration module for **TsarChain** with crypto, PoW, validation, and fused LMDB/JSON storage bindings.

**Build prerequisites**

- Python 3.8+
- Rust toolchain (stable) via `rustup`
- `maturin`
- `cmake` 4.2.0-rc2 (required to build the bundled RandomX backend)

> Full Instalation Guide [`INSTALL_NATIVE.md`](/docs/INSTALL_NATIVE.md)

## What's inside

The core functionality of `tsarcore_native` is organized into the following Rust modules in `src/`:

- **[lib.rs](src/lib.rs)**: Exposes PyO3 native module bindings (`tsarcore_native`), implements core cryptographic hash functions (`hash256`, `hash160`), and orchestrates the RandomX VM cache.
- **[generate_receipt.rs](src/generate_receipt.rs)**: Generates QR codes as PNG, formats decimals and TSAR currency strings, and exposes receipt layout drawing helpers (table rows, transaction ID grids) for website backend.
- **[graff_merkle.rs](src/graff_merkle.rs)**: Implements the single SHA-256 Merkle tree used for chunked "Graffiti" archives, supporting path generation and client-side inclusion proof validation.
- **[mining.rs](src/mining.rs)**: A multi-threaded RandomX PoW mining orchestrator that checks block difficulty, tracks hashrate progress, and supports cooperative mining thread cancellation.
- **[networking.rs](src/networking.rs)**: Implements the P2P encryption handshake (`SecureChannelNative`) using X25519 static/ephemeral secrets, Ed25519 peer validation, HKDF key derivation, and sliding-window AES-256-GCM epoch key rotation.
- **[storage.rs](src/storage.rs)**: Features a dual-backend storage wrapper (`NativeStorage`) exposing high-performance memory-mapped LMDB (with thread-safe growable boundaries) and atomic fallback JSON files.
- **[txcodec.rs](src/txcodec.rs)**: Encodes and decodes consensus transaction byte payloads (varints, inputs, outputs, witness data) and generates BIP-143 transaction signatures and preimages.
- **[utxo.rs](src/utxo.rs)**: Processes block transaction records to construct bulk UTXO set modifications (inserts and deletions of spent outputs), filtering out OP_RETURN data.
- **[validation.rs](src/validation.rs)**: Enforces consensus rules over blocks and transactions, checking coinbase maturity constraints, transaction vsize/weight limits, signature verification, and input/output fees.

## Unit Tests

Integration and unit tests are located in the `tests/` directory and match the structure of the source modules. They verify correctness of the Rust implementation independently of the Python runtime:

- **[lib_test.rs](tests/lib_test.rs)**: Validates Python bindings interfaces, including hashing, secp256k1 sign/verify mechanisms, and basic RandomX VM hashing.
- **[generate_receipt_test.rs](tests/generate_receipt_test.rs)**: Asserts formatting logic for receipts, QR code rendering limits, and table row drawing calculations.
- **[graff_merkle_test.rs](tests/graff_merkle_test.rs)**: Exercises tree construction correctness, leaf verification paths, and error scenarios.
- **[mining_test.rs](tests/mining_test.rs)**: Verifies the miner difficulty comparator, stop event cooperative cancellations, and multi-thread startup conditions.
- **[networking_test.rs](tests/networking_test.rs)**: Tests peer key exchange handshake flows, decryption/encryption integrity, and sliding rekey thresholds.
- **[storage_test.rs](tests/storage_test.rs)**: Validates key-value storage consistency, transaction atomicity, prefix matching, and LMDB auto-grow behavior.
- **[txcodec_test.rs](tests/txcodec_test.rs)**: Tests transaction serialization codecs, txid/wtxid hashes, and P2WPKH transaction validation.
- **[utxo_test.rs](tests/utxo_test.rs)**: Asserts correct computation of UTXO updates from block records and OP_RETURN exclusions.
- **[validation_test.rs](tests/validation_test.rs)**: Asserts consensus block execution rules, coinbase uniqueness, coin age maturity limits, and block limits.

To run the Rust tests:

```bash
cargo test
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

# Block validation (simplified)
block_dict = {...}      # block.to_dict()
utxo_snapshot = {...}   # { "txid:vout": {"amount":..., "script_pubkey":..., ...}, ... }
opts = {
    "coinbase_maturity": 10,
    "max_sigops_per_tx": 6000,
    "max_sigops_per_block": 40000,
    "enforce_low_s": True,
}
ok, reason, fees = tc.validate_block_txs_native(block_dict, utxo_snapshot, block_dict["height"], opts)
assert ok, reason

# RandomX hashing (80-byte block header + seed)
header80 = block_header_bytes
seed = b"seed-deriv"  # derived from height/epoch in TsarChain
digest = tc.randomx_pow_hash(
    header80,
    seed,
    full_mem=False,
    large_pages=False,
    jit=True,
    hard_aes=True,
    secure_jit=False,
    cache_entries=1,
)

# Storage (LMDB backend; set backend="json" for atomic JSON files)
store = tc.open_storage(
    "lmdb",
    "/tmp/tsar.db",
    map_size_init=4 * 1024 * 1024,
    map_size_max=64 * 1024 * 1024,
    pretty_json=True,
)
store.put_json("utxo", b"\x01", '{"height": 1, "amount": 5000}')
assert store.get_json("utxo", b"\x01")["height"] == 1
rows = store.iter_prefix("utxo", b"")
store.copy("/tmp/tsar.db.backup", compact=True)  # LMDB only
```

## Safety notes

- No `unsafe`, no panics, strict bounds checks when parsing transaction bytes and varints.
- `secp_verify_der_low_s` and the batch verifier reject high-`S` by default (set `enforce_low_s=False` in batch mode for legacy).
- `sighash_bip143` currently supports **`SIGHASH_ALL`** natively.

## Changelog

- **0.2.2** - Removed `graff_merkle_path_for_bytes` and Python fallback `get_final_bytes` bindings to fully rely on memory-mapped LMDB pointers (`get_final_bytes_range` & `get_final_merkle_path`). This guarantees zero-copy scale for massive chunks and resolves out-of-memory crashes on the Graffiti Archival nodes.
- **0.2.1** - Native graffiti Merkle (single SHA-256) bindings added for root/path/verify/leaves; Python Merkle path removed in favor of native; per-call debug/warning logs added to help trace Merkle operations.
- **0.2.0** - Added consensus TX guardrails: vsize/weight and max inputs/outputs enforced in native validators (block + mempool P2WPKH), options expanded to carry new limits from Python, and debug logs trimmed. Aligns with TsarChain config MIN/MAX TX limits.
- **0.1.9** - SecureChannel gains automatic AEAD rekey per-message epoch (configurable via `P2P_REKEY_EVERY_MSG`); epoch keys are derived from the HKDF root with sliding TTL/msg windows so long-lived links rekey smoothly without dropping the connection.
- **0.1.8** - Native RandomX miner now reports hashrate via `progress_queue` and respects `stop_event`/Ctrl+C using a stop watcher inside Rust threads; mining cancellation no longer waits for a full block and remains verified with light hash check in Python.
- **0.1.7** - Added native mempool validator for P2WPKH (no Python fallback) and native UTXO snapshot streaming for full-sync (chunked LMDB read). full-sync uses native streaming when `KV_BACKEND=lmdb`.
- **0.1.6** - Native UTXO apply (LMDB batch) now default (no Python fallback); compact tx codec exposed (serialize/txid/wtxid/sighash) and wired into txid/wtxid compute, mempool BIP143, and payload compact consensus; P2PKH legacy path deleted (only P2WPKH).
- **0.1.5** - LMDB storage enhancements: batch put/delete API, chunked prefix iteration, smoother map growth (doubling up to max) to avoid MapFull; thread-safe KV init and streaming iterators exposed to Python for lower memory use.
- **0.1.4** - Added `NativeStorage`/`open_storage` with LMDB or atomic JSON backends (prefix scans, temp-file persistence, optional pretty JSON, LMDB auto-grow + copy), plus `json_read_file`/`json_write_file` helpers.
- **0.1.3** - Added `SecureChannelNative` (X25519 handshake + HKDF + AES-256-GCM) so TsarChain P2P crypto now runs entirely in Rust, lowering latency and hardening TTL/msg quotas.
- **0.1.2** - Stateless RandomX hashing used by TsarChain PoW.
- **0.1.1** - Docs synced with code: expose `hash256`, `hash160`, `secp_verify_der_low_s_many`, native `sighash_bip143` (ALL); clarify merkle root behavior and parallel feature.
- **0.1.0** - Initial release.
