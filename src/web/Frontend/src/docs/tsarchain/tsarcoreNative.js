export const tsarcoreNative = {
  id: "tsarcore-native",
  title: "tsarcore_native (Rust + pyo3)",
  subtitle: "Native acceleration module for TsarChain with crypto, PoW, validation, and LMDB storage bindings.",
  category: "Tsarchain",
  badge: "Rust Crate",
  toc: [
    { id: "build-prerequisites", label: "1. Build Prerequisites" },
    { id: "whats-inside", label: "2. What's Inside" },
    { id: "unit-tests", label: "3. Unit Tests" },
    { id: "python-usage", label: "4. Usage (Python)" },
    { id: "safety-notes", label: "5. Safety Notes" },
    { id: "changelog", label: "6. Changelog" },
  ],
  sections: [
    {
      id: "build-prerequisites",
      title: "1. Build Prerequisites & Overview",
      content: `Native acceleration module for **TsarChain** with crypto, PoW, validation, and LMDB storage bindings.

### Build Prerequisites

- **Python 3.8+**
- **Rust toolchain (stable)** via \`rustup\`
- **maturin**
- **cmake** 4.2.0-rc2 (required to build the bundled RandomX backend)`
    },
    {
      id: "whats-inside",
      title: "2. What's Inside",
      content: `The core functionality of \`tsarcore_native\` is organized into the following Rust modules in \`src/\`:`,
      items: [
        {
          label: "lib.rs",
          text: "Exposes PyO3 native module bindings (`tsarcore_native`), implements core cryptographic hash functions (`hash256`, `hash160`), and orchestrates the RandomX VM cache."
        },
        {
          label: "generate_history_book.rs",
          text: "Provides history transactions pagination helpers, direction text formatters, and computes visual Address Grid layout data (`AddressGridData`) supporting both P2WPKH (44-character Citizen Address) and P2WSH (64-character Pool Address) for PDF History Book rendering."
        },
        {
          label: "generate_receipt.rs",
          text: "Generates QR codes as PNG, formats decimals and TSAR currency strings, and exposes receipt layout drawing helpers (table rows, transaction ID grids) for website backend."
        },
        {
          label: "graff_merkle.rs",
          text: "Implements the single SHA-256 Merkle tree used for chunked \"Graffiti\" archives, supporting path generation and client-side inclusion proof validation."
        },
        {
          label: "mining.rs",
          text: "A multi-threaded RandomX PoW mining orchestrator that checks block difficulty, tracks hashrate progress, and supports cooperative mining thread cancellation."
        },
        {
          label: "networking.rs",
          text: "Implements the P2P encryption handshake (`SecureChannelNative`) using X25519 static/ephemeral secrets, Ed25519 peer validation, HKDF key derivation, and sliding-window AES-256-GCM epoch key rotation."
        },
        {
          label: "storage.rs",
          text: "Features storage wrapper (`NativeStorage`) exposing high-performance memory-mapped LMDB (with thread-safe growable boundaries, smart drive auto-detection for HDD/SSD/NVMe, and drive-specific flag profiling)."
        },
        {
          label: "txcodec.rs",
          text: "Encodes and decodes consensus transaction byte payloads (varints, inputs, outputs, witness data) and generates BIP-143 transaction signatures and preimages."
        },
        {
          label: "utxo.rs",
          text: "Processes block transaction records to construct bulk UTXO set modifications (inserts and deletions of spent outputs), filtering out OP_RETURN data."
        },
        {
          label: "validation.rs",
          text: "Enforces consensus rules over blocks and transactions, checking coinbase maturity constraints, transaction vsize/weight limits, signature verification, and input/output fees."
        }
      ]
    },
    {
      id: "unit-tests",
      title: "3. Unit Tests",
      content: `Integration and unit tests are located in the \`tests/\` directory and match the structure of the source modules. They verify correctness of the Rust implementation independently of the Python runtime:`,
      items: [
        {
          label: "lib_test.rs",
          text: "Validates Python bindings interfaces, including hashing, secp256k1 sign/verify mechanisms, and basic RandomX VM hashing."
        },
        {
          label: "generate_history_book_test.rs",
          text: "Asserts direction string formatting and Address Grid chunking/highlighting logic for P2WPKH and P2WSH address types."
        },
        {
          label: "generate_receipt_test.rs",
          text: "Asserts formatting logic for receipts, QR code rendering limits, and table row drawing calculations."
        },
        {
          label: "graff_merkle_test.rs",
          text: "Exercises tree construction correctness, leaf verification paths, and error scenarios."
        },
        {
          label: "mining_test.rs",
          text: "Verifies the miner difficulty comparator, stop event cooperative cancellations, and multi-thread startup conditions."
        },
        {
          label: "networking_test.rs",
          text: "Tests peer key exchange handshake flows, decryption/encryption integrity, and sliding rekey thresholds."
        },
        {
          label: "storage_test.rs",
          text: "Validates key-value storage consistency, transaction atomicity, prefix matching, and LMDB auto-grow behavior."
        },
        {
          label: "txcodec_test.rs",
          text: "Tests transaction serialization codecs, txid/wtxid hashes, and P2WPKH transaction validation."
        },
        {
          label: "utxo_test.rs",
          text: "Asserts correct computation of UTXO updates from block records and OP_RETURN exclusions."
        },
        {
          label: "validation_test.rs",
          text: "Asserts consensus block execution rules, coinbase uniqueness, coin age maturity limits, and block limits."
        }
      ],
      command: {
        code: "cargo test",
        title: "Run Rust Tests",
        comment: "# Executes all unit and integration tests across the test suite"
      }
    },
    {
      id: "python-usage",
      title: "4. Usage (Python)",
      content: `\`\`\`python
import tsarcore_native as tc

assert tc.count_sigops(b"\\xac") == 1  # OP_CHECKSIG
d32 = bytes.fromhex("00"*32)
pk  = bytes.fromhex("02" + "11"*32)    # compressed (example only)
sig = b"\\x30..."                      # strict DER (example only)

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

# Storage (LMDB backend)
store = tc.open_storage(
    "lmdb",
    "/tmp/tsar.db",
    map_size_init=4 * 1024 * 1024,
    map_size_max=64 * 1024 * 1024,
    pretty_json=True,
    drive_type=None,  # Auto-detects HDD, SSD, or NVMe
)
store.put_json("utxo", b"\\x01", '{"height": 1, "amount": 5000}')
assert store.get_json("utxo", b"\\x01")["height"] == 1
rows = store.iter_prefix("utxo", b"")
store.copy("/tmp/tsar.db.backup", compact=True)
\`\`\``
    },
    {
      id: "safety-notes",
      title: "5. Safety notes",
      content: `- No \`unsafe\`, no panics, strict bounds checks when parsing transaction bytes and varints.
- \`secp_verify_der_low_s\` and the batch verifier reject high-\`S\` by default (set \`enforce_low_s=False\` in batch mode for legacy).
- \`sighash_bip143\` currently supports **\`SIGHASH_ALL\`** natively.`
    },
    {
      id: "changelog",
      title: "6. Changelog",
      table: {
        headers: ["Version", "Release Highlights & Changelog Details"],
        rows: [
          ["0.2.4", "**Smart Storage LMDB Engine**: Added native drive type auto-detection (HDD, SSD, NVMe via Windows IOCTL / Linux sysfs) and environment override (`TSAR_STORAGE_DRIVE_TYPE`). Automatically applies optimized LMDB flags (e.g. `MDB_NOSYNC`, `MDB_WRITEMAP`, `MDB_MAPASYNC`, `MDB_NORDAHEAD`) per drive profile to prevent mechanical disk seek stalls and eliminate crashes on HDD/SSD storage nodes."],
          ["0.2.3", "Added `generate_history_book` module exposing history pagination, direction formatting, and `draw_address_grid_data` for rendering visual Address Grids (P2WPKH Citizen Addresses & P2WSH Pool Addresses) in the History Book PDF generator."],
          ["0.2.2", "Removed `graff_merkle_path_for_bytes` and Python fallback `get_final_bytes` bindings to fully rely on memory-mapped LMDB pointers (`get_final_bytes_range` & `get_final_merkle_path`). This guarantees zero-copy scale for massive chunks and resolves out-of-memory crashes on the Graffiti Archival nodes."],
          ["0.2.1", "Native graffiti Merkle (single SHA-256) bindings added for root/path/verify/leaves; Python Merkle path removed in favor of native; per-call debug/warning logs added to help trace Merkle operations."],
          ["0.2.0", "Added consensus TX guardrails: vsize/weight and max inputs/outputs enforced in native validators (block + mempool P2WPKH), options expanded to carry new limits from Python, and debug logs trimmed. Aligns with TsarChain config MIN/MAX TX limits."],
          ["0.1.9", "SecureChannel gains automatic AEAD rekey per-message epoch (configurable via `P2P_REKEY_EVERY_MSG`); epoch keys are derived from the HKDF root with sliding TTL/msg windows so long-lived links rekey smoothly without dropping the connection."],
          ["0.1.8", "Native RandomX miner now reports hashrate via `progress_queue` and respects `stop_event`/Ctrl+C using a stop watcher inside Rust threads; mining cancellation no longer waits for a full block and remains verified with light hash check in Python."],
          ["0.1.7", "Added native mempool validator for P2WPKH (no Python fallback) and native UTXO snapshot streaming for full-sync (chunked LMDB read). full-sync uses native streaming when `KV_BACKEND=lmdb`."],
          ["0.1.6", "Native UTXO apply (LMDB batch) now default (no Python fallback); compact tx codec exposed (serialize/txid/wtxid/sighash) and wired into txid/wtxid compute, mempool BIP143, and payload compact consensus; P2PKH legacy path deleted (only P2WPKH)."],
          ["0.1.5", "LMDB storage enhancements: batch put/delete API, chunked prefix iteration, smoother map growth (doubling up to max) to avoid MapFull; thread-safe KV init and streaming iterators exposed to Python for lower memory use."],
          ["0.1.4", "Added `NativeStorage`/`open_storage` with LMDB."],
          ["0.1.3", "Added `SecureChannelNative` (X25519 handshake + HKDF + AES-256-GCM) so TsarChain P2P crypto now runs entirely in Rust, lowering latency and hardening TTL/msg quotas."],
          ["0.1.2", "Stateless RandomX hashing used by TsarChain PoW."],
          ["0.1.1", "Docs synced with code: expose `hash256`, `hash160`, `secp_verify_der_low_s_many`, native `sighash_bip143` (ALL); clarify merkle root behavior and parallel feature."],
          ["0.1.0", "Initial release."]
        ]
      }
    }
  ]
};
