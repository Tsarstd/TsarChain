# Graffiti Protocol Architecture

This document provides an in-depth technical overview of the Graffiti Protocol. The architecture relies on a hybrid design that couples lightweight on-chain UTXO execution with off-chain heavy data storage, prioritizing the permanent archiving of digital art and testimonies.

---


## Phase 1: Consensus & Proof-of-Work (PoW) Logic

At the core of the Graffiti Protocol is a bespoke consensus engine designed to enforce immutability while anchoring cultural artifacts natively into the blockchain state.

### 1. The Mining Orchestrator & Mempool Queue
The mining logic (`src/tsarchain/consensus/mining.py`) serves as the orchestrator for block creation. When a miner attempts to build a candidate block, it interacts directly with the `TxPool` (Mempool) applying specific priority algorithms.

**Mempool Queuing Policy**
Instead of solely relying on fee-based priority, the network categorizes transactions into two streams:
1. **Graffiti Posts**: Transactions carrying an `OP_RETURN` payload representing a new piece of art or testimony. These are sorted strictly by `_received_at` timestamp.
2. **Standard UTXOs**: Standard financial/token transfers, which are sorted by `fee` (descending) and then `_received_at`.

The orchestrator pulls the queued Graffiti transactions to the absolute front of the line, guaranteeing prioritized execution for cultural archiving.

> [!IMPORTANT]  
> **1 BLOCK = 1 GRAFFITI**
> To prevent spam and maintain the semantic weight of each block, the `_build_candidate_block` function enforces a strict quota. A candidate block **may only contain a maximum of 1 Graffiti POST transaction**. 
> If multiple `POST` transactions exist in the mempool, the orchestrator accepts the first one and explicitly skips the rest, leaving them queued for subsequent blocks.

### 2. Block Anchoring & Coinbase Etching
This is a defining feature of the Graffiti Protocol. It elevates the concept of block creation by tightly coupling the block reward directly to the artifact it preserves.

When building a block, the orchestrator triggers the `_select_graffiti_art_id` function to inspect the included `OP_RETURN` script. If a Graffiti `POST` is found, the node extracts its unique `art_id`.

In `src/tsarchain/core/coinbase.py`, the network generates the `CoinbaseTx` (the transaction rewarding the miner for solving the block). 
- **Default State**: If no Graffiti `POST` is present in the block, the coinbase generates a random hash using `block_id_generator()`.
- **Graffiti Anchoring**: If an `art_id` was extracted, it is aggressively injected into the `CoinbaseTx` as the `block_id`. 

> [!NOTE]  
> **Coinbase Etching**  
> By injecting the `art_id` into the Coinbase transaction, the protocol literally "etches" the identity of the digital artifact into the root of the block reward. It inextricably binds the financial incentive of the network to the preservation of the art.

### 3. RandomX Consensus & Native Extensions
The network relies on **RandomX** for ASIC-resistant Proof-of-Work, ensuring CPU-mineability and decentralized participation.

- **Rust Interoperability**: Because Python is not suited for raw hashing throughput, the core mining loops and dataset/cache initializations are offloaded to Rust (`tsarcore_native/src/mining.rs` and `lib.rs`). 
- **Python Wrapper**: `src/tsarchain/utils/helpers.py` bridges the gap, allowing the Python orchestrator to call the low-level Rust execution seamlessly.
- **Difficulty Adjustment**: `src/tsarchain/consensus/difficulty.py` continuously monitors block generation times, dynamically adjusting the PoW target to maintain stable block intervals.

### 4. Validation & Chain Operations
Once a miner successfully computes the PoW, the block is broadcasted.
- **Validation** (`validation.py`): Re-verifies all UTXO inputs, ensures the `1 BLOCK = 1 GRAFFITI` quota is intact, and validates the RandomX hash against the current difficulty.
- **Storage & State** (`chain_ops.py` & `chain_storage.py`): Valid blocks are committed to the LMDB database. The protocol correctly applies UTXO deltas and can orchestrate complex chain re-organizations (swapping and replacing blocks) if a longer valid chain is encountered.

---

## Phase 2: UTXO Ledger State & Mempool

The ledger state of the Graffiti Protocol tracks ownership, storage balances, and digital artifact lifecycles through a highly optimized UTXO (Unspent Transaction Output) framework.

### 1. UTXO Database & Validation Layer
The ledger's state transitions are managed by a combination of Python orchestrators and Rust native handlers.

- **`UTXOValidator` (`src/tsarchain/consensus/utxo_validate.py`)**: Responsible for managing both temporary (in-memory) and persisted states of the `UTXODB`. During block verification and network sync, this class coordinates state rebuilds (`rebuild_from_chain`) and periodic flushing (`maybe_flush_utxo`) to disk to optimize database performance.
- **Python-Rust Performance Hybrid (`src/tsarchain/storage/utxo_logic/validate.py`)**: To speed up blockchain transaction processing, `UTXOValidationMixin` compacts block transaction outputs into simple Python tuples (`_build_compact_block_txs`) and passes them directly to Rust via `native_utxo_build_ops_compact` (`tsarcore_native/src/utxo.rs`). The Rust native extension executes raw database operations (LMDB) or in-memory map modifications at maximum speed, returning the delta state.
- **UTXO Model Structuring**: UTXO keys are indexed as `txid_hex:vout` strings, mapping to the output amount, the script public key, coinbase status, and block height.

### 2. Graffiti Transaction Lifecycle in UTXO
The protocol intercepts all standard transaction delta calculations inside `src/tsarchain/storage/utxo_logic/graff_utxo.py` using `UTXOGraffitiMixin`. When an output contains an `OP_RETURN` payload, it is parsed as a Graffiti event:

#### A. The `POST` Event (Initialization)
- **Pool Derivation**: The protocol derives a unique, deterministic storage fee pool address for the piece of art using `derive_pool_address(art_id)`.
- **Fee Verification**: The system evaluates the uploaded file size (`calc_upload_fee_sats`) and enforces that the transaction outputs pay at least the minimum fee to the derived pool address. If the payment is insufficient, the block containing the POST will be rejected at the consensus level.
- **Registry Record**: Validated POSTs are recorded permanently into the `_graffiti_registry`.

#### B. The `COMMENT` Event (Interaction)
- **Royalty Split**: When users comment on a piece of graffiti, they can specify a fee and optional tip.
- **Consensus Enforcement**: The protocol uses `calc_comment_split` to divide the comment payment between the creator's address (creator royalty) and the storage pool address (storage fee). The UTXO layer validates that both outputs are paid correctly on-chain.

#### C. The `PAYOUT` Event (Node Incentives)
- **Archivist Claims**: Storage nodes (Archivists) prove they are holding the digital file and claim payouts from the artwork's pool balance.
- **Replay & Cap Validation**: The system validates that the epoch is not rewound, the payment recipients match the valid storage nodes, and the total withdrawal does not exceed the current `pool_balance`. It also records the cryptographic proof details (`proof_hash`, `proof_offset`, etc.) to the registry.

### 3. Mempool Verification Policy (`src/tsarchain/mempool/validation.py`)
Before standard or Graffiti transactions can enter the mempool (`TxPool`), they must pass verification by `TxMempoolValidator`:

- **Native Rule Enforcement**: Transactions are converted to compact types and verified in Rust using `native_validate_tx_p2wpkh_compact`. This enforces protocol limits: Coinbase maturity, maximum transaction inputs/outputs, maximum transaction weight/vsize limits, and low-s signature verification.
- **Mempool Soft Policies**: While consensus limits block-inclusion to 1 Graffiti POST per block, the mempool also implements soft limits (`_enforce_mempool_post_limit`) to reject overflow posts and protect the node's memory capacity.

---

## Phase 3: Rust Native Extension (`tsarcore_native`)

For performance-critical tasks, the Graffiti Protocol bypasses the performance limitations and the Global Interpreter Lock (GIL) of Python by offloading computations to a high-performance native extension compiled in Rust.

### 1. PyO3 Integration & Module Architecture
The `tsarcore_native` extension is compiled via `maturin` and directly links to the Python runtime using **PyO3** bindings. 

- **Bridge Interface (`src/tsarchain/utils/helpers.py`)**: Acts as the primary Python-side wrapper mapping Python functions to underlying low-level Rust calls (`tsarcore_native/src/lib.rs`).
- **Python-to-Rust Types**: PyO3 handles automatic type conversion (e.g. converting Python binary strings to Rust `&[u8]`, or mapping complex lists into Rust tuples), keeping the data passing boundary minimal.

### 2. High-Performance Hashing & RandomX VM Caching
PoW calculations require intensive hash checks which are executed natively inside `tsarcore_native/src/mining.rs`.

- **Mining vs Verification Hashing**:
  - **`pow_hash_miner` (Active Mining)**: Resolves whether full dataset allocations (`FLAG_FULL_MEM` using 2GB datasets) should be run to maximize CPU mining hash rates.
  - **`pow_hash_verify_light` (Validation)**: Executes in "Light" mode (using cache only, no massive memory overhead) to verify incoming block headers instantly.
- **Static RandomX VM Cache**: Building a new RandomX virtual machine (dataset/cache compilation) takes several seconds. To prevent this overhead on every single block validation, the Rust runtime implements `RANDOMX_VM_CACHE` inside `lib.rs`. It stores and maintains active VMs in memory statically, purging them only if inactive.

### 3. Parallel Validation with Rayon
To handle heavy validation loads during network sync or mempool dumps, the extension utilizes parallel signature checks.

- **`secp_verify_der_low_s_many`**: Multi-signature verification tasks are executed using Rust's Rayon library. Rayon divides the verification list across a thread pool utilizing `par_iter()`. Because this runs inside the Rust boundary, it executes outside the Python GIL, utilizing all available CPU cores concurrently.

### 4. Storage & UTXO Delta Optimization
Ledger updates are kept highly compact.

- **`NativeStorage` (`src/tsarcore_native/storage.rs`)**: Direct C/Rust binding to the **LMDB** engine. It reads and writes JSON blobs and transactional states natively without routing serialization through Python.
- **`utxo_build_ops_compact` (`src/tsarcore_native/utxo.rs`)**: Optimizes state transitions. Python sends transaction lists as compressed tuples (`_build_compact_block_txs`), and Rust applies the inputs/outputs delta instantly in memory and commits it to the LMDB database.

### 5. Proof of Retention Merkle Engine (`src/tsarcore_native/graff_merkle.rs`)
Archivists must cryptographically prove they hold large files. Rust accelerates this verification process:
- **`graff_merkle_root_for_file`**: Computes the Merkle root of files directly off the disk at native I/O speeds.
- **`graff_merkle_path_for_file`**: Extracts the exact Merkle path for a specified chunk index.
- **`graff_merkle_verify`**: Instantly validates a Proof of Retention challenge, ensuring nodes cannot easily fake possession of archived files.

---

## Phase 4: Graffiti Protocol Logic

The core logic of the Graffiti Protocol governs the creation, validation, storage pool distributions, and retention auditing of all cultural archives in the system.

### 1. Metadata Registry (`src/tsarchain/contracts/graffiti_registry.py`)
The `GraffitiRegistry` tracks state records for posts, comments, payouts, and proofs.
- **Dual-Database Adapter**:
  - **LMDB Backend (`_kv = True`)**: Under production configuration, the registry updates via high-performance prefix lookups (`graffiti:`).
  - **Atomic File Fallback (`AtomicJSONFile`)**: If key-value storage is disabled, the registry falls back to writing database states directly to a JSON file. The file utilizes custom checksum validations and backup rotations to mitigate data corruption.
- **State Collections**:
  - `posts`: Links art identifiers (`art_id`) to transactional metadata, hashes, size bounds, and current pool balances.
  - `comments`: Appends commenter signatures, timestamps, and payouts splits.
  - `payouts`: Tracks idempotent reward records to storage node operators.
  - `proofs`: Captures operational parameters for storage integrity proofs (epoch, offsets, sizes, storer).

### 2. Core Cryptographic Logic & P2WSH Pools (`src/tsarchain/contracts/graffiti.py`)
This module enforces validation policies and deterministic calculations for files.

- **Deterministic P2WSH Address Pools**: Each piece of digital art is tied to a deterministic Pay-to-Witness-Script-Hash (P2WSH) address derived from `_pool_redeem_script(art_id_hex)`. 
  - Koin balances built up inside this pool address are locked.
  - They can only be released if a valid transaction fulfills the redeem script conditions (verifying payout claims to storage providers).
- **Proof-of-Retention Challenges**: To prevent Archivists from claiming rewards without hosting files, the system utilizes deterministic byte-range audits.
  - **`calc_proof_challenge`**: Takes the file size, block height, and `art_id`. It divides the height by `GRAFFITI_PROOF_EPOCH_BLOCKS` to get the current validation `epoch`.
  - Using a seed hash (`magic_word | PROOF | art_id | epoch`), the challenge deterministically yields a random target `offset` and chunk `length` that the storage node must read and hash.
- **Epoch Division**: `compute_proof_epoch` groups block validations, ensuring proof challenges remain stable throughout the active epoch length.

### 3. Rust-Powered Merkle Proofs (`tsarcore_native/src/graff_merkle.rs`)
To satisfy Proof of Retention audits efficiently without exhausting system resources, the cryptographic engine builds Merkle proof trees directly inside the Rust extension:

- **Chunked File Hashing**: Instead of reading whole gigabyte-scale files into memory (RAM), `graff_merkle_root_for_file` opens a file stream, reads sequential chunk buffers from disk, hashes them individually, and builds the Merkle root.
- **Merkle Path Extraction**: When a node is challenged, `graff_merkle_path_for_file` traverses the tree levels. It compiles the sibling digests and their sides (`L` or `R`) relative to the challenged index.
- **O(log N) Verification**: The node verifies the retention proof using `graff_merkle_verify`. It reconstructs the root hash from the chunk and the provided Merkle path, comparing it instantly against the registered file root in `O(log N)` complexity.



