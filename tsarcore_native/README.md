# tsarcore_native (Rust + pyo3)

Native acceleration module for **TsarChain** with crypto, PoW, validation, and fused LMDB/JSON storage bindings.

**Build prerequisites**

- Python 3.8+
- Rust toolchain (stable) via `rustup`
- `maturin`
- `cmake` 3.20+ (required to build the bundled RandomX backend)

## What's inside (current API)

- `count_sigops(script: bytes) -> int`  
  Counts `CHECKSIG` (+1) and `CHECKMULTISIG` (+min(n or 20, 20)) including their `VERIFY` variants, mirroring TsarChain's consensus rules.

- `hash256(data: bytes) -> bytes32`  
  SHA256d (double-SHA256).

- `hash160(data: bytes) -> bytes20`  
  RIPEMD160(SHA256(data)).

- `merkle_root(txids: Iterable[bytes32]) -> bytes32`  
  Double-SHA256 Merkle root over 32-byte leaves. For odd nodes, the last hash is duplicated (Bitcoin-style).

- `sighash_bip143(tx_bytes: bytes, input_index: int, script_code: bytes, value_sat: int, sighash_type: int) -> bytes32`  
  Native **BIP143** preimage + SHA256d for **`SIGHASH_ALL`**. Other sighash types return `ValueError` so the caller can handle fallbacks if ever needed.

- `secp_verify_der_low_s(pubkey: bytes, digest32: bytes, der_sig: bytes) -> bool`  
  Strict DER parse + low-S enforcement (mirrors mempool policy). Accepts 33/65-byte SEC pubkeys or 64-byte raw `x||y`.

- `secp_verify_der_low_s_many(triples: Sequence[tuple[pubkey, digest32, der_sig]], enforce_low_s: bool = True, parallel: bool = False) -> list[bool]`  
  Batch verify. If built with feature `parallel`, set `parallel=True` to use Rayon.

- `validate_block_txs_native(block: Mapping, utxo_snapshot: Mapping, spend_height: int, opts: Mapping) -> tuple[bool, str|None, list[int]|None]`  
  Full block-level transaction validation (sigops, coinbase rules, witness verification, fee projection, etc.). Returns `(ok, reason, fees)` where `fees` is per-non-coinbase once `ok` is `True`.

- `randomx_pow_hash(header: bytes, seed: bytes, *, full_mem: bool, large_pages: bool, jit: bool, hard_aes: bool, secure_jit: bool, cache_entries: int) -> bytes32`  
  Stateless RandomX hashing used by TsarChain PoW. The binding internally caches VMs per thread/seed to avoid rebuilding datasets on every call.

- `SecureChannelNative(role, net_id, node_id, node_pub_hex, session_ttl, session_max_msg, key_bytes, nonce_bytes, node_priv_hex=None, aad_prefix=None)`  
  Native X25519 + Ed25519 authenticated handshake + HKDF + AES-256-GCM transport for TsarChain P2P links. Provides `client_build_hs1`, `client_accept_hs2`, `server_accept_hs1`, `encrypt`, and `decrypt`, enforcing TTL/msg-count/sequence windows entirely in Rust.

- `set_py_logger(callable)`  
  Optional hook so Rust logs can piggyback on TsarChain's logger.

- `json_read_file(path: str) -> str | None` and `json_write_file(path: str, data: str, pretty: bool = True)`  
  Helpers for existing on-disk JSON snapshots; reads return `None` when missing and writes are atomic (temp-file swap) with optional pretty formatting.

- `NativeStorage(backend, path, map_size_init=None, map_size_max=None, pretty_json=True)` / `open_storage(...)`  
  Thread-safe storage facade over LMDB or atomic JSON files. Exposes `put_bytes`, `put_json`, `get_bytes`, `get_json`, `delete`, `clear_db`, `iter_prefix`, and LMDB `copy`. LMDB automatically retries after `MapFull` by growing to `map_size_max`; JSON backend pretty-prints (optional) and persists via temp-file rename for durability.

- UTXO delta + apply (LMDB):  
  - `utxo_build_ops_compact(block_txs, spend_height)` -> list of ops (delete/insert) from compact tx tuples  
  - `NativeStorage.apply_utxo_ops(ops)` (LMDB backend) batch-apply UTXO ops in one transaction

- Compact tx codec (P2WPKH-focused):  
  - `serialize_tx_compact(tx_tuple, include_witness=True) -> bytes`  
  - `txid_from_compact(tx_tuple) -> bytes`, `wtxid_from_compact(tx_tuple) -> bytes`  
  - `sighash_bip143_compact(tx_tuple, input_index, script_code, value_sat, sighash_type)` (SIGHASH_ALL, no ANYONECANPAY)

> Endianness note: pass **little-endian txids** to `merkle_root` if you want a Bitcoin-compatible block header merkle root.

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

- **0.1.8** - Native RandomX miner now reports hashrate via `progress_queue` and respects `stop_event`/Ctrl+C using a stop watcher inside Rust threads; mining cancellation no longer waits for a full block and remains verified with light hash check in Python.
- **0.1.7** - Added native mempool validator for P2WPKH (no Python fallback) and native UTXO snapshot streaming for full-sync (chunked LMDB read). full-sync uses native streaming when `KV_BACKEND=lmdb`.
- **0.1.6** - Native UTXO apply (LMDB batch) now default (no Python fallback); compact tx codec exposed (serialize/txid/wtxid/sighash) and wired into txid/wtxid compute, mempool BIP143, and payload compact consensus; P2PKH legacy path deleted (only P2WPKH).
- **0.1.5** - LMDB storage enhancements: batch put/delete API, chunked prefix iteration, smoother map growth (doubling up to max) to avoid MapFull; thread-safe KV init and streaming iterators exposed to Python for lower memory use.
- **0.1.4** - Added `NativeStorage`/`open_storage` with LMDB or atomic JSON backends (prefix scans, temp-file persistence, optional pretty JSON, LMDB auto-grow + copy), plus `json_read_file`/`json_write_file` helpers.
- **0.1.3** - Added `SecureChannelNative` (X25519 handshake + HKDF + AES-256-GCM) so TsarChain P2P crypto now runs entirely in Rust, lowering latency and hardening TTL/msg quotas.
- **0.1.2** - Stateless RandomX hashing used by TsarChain PoW.
- **0.1.1** - Docs synced with code: expose `hash256`, `hash160`, `secp_verify_der_low_s_many`, native `sighash_bip143` (ALL); clarify merkle root behavior and parallel feature.
- **0.1.0** - Initial release.
