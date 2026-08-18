# TsarChain Storage RPC Specification

Technical documentation for the **`STORAGE`** RPC category in the TsarChain P2P Network (`src/tsarchain/network/rpc/storage_rpc.py` and `src/tsarchain/network/rpc/processing_msg.py`).

---

## 1. Architecture & Storage Node Authentication

Storage RPC provides a cryptographic bridge between TsarChain full nodes and distributed **Archivist Storage Nodes** (`src/archivist/`). Its core purpose is to enforce **Proof of Retention (PoR)** for decentralized Graffiti art storage and distribute epoch storage payouts.

```
┌────────────────────────┐                   ┌────────────────────────┐
│  Archivist Node (Peer) │                   │  Full Node / Miner     │
└───────────┬────────────┘                   └───────────┬────────────┘
            │                                            │
            │  1. HELLO (role: "NODE_STORAGE")           │
            ├───────────────────────────────────────────►│ (Registers in storage_peers)
            │                                            │
            │  2. GRAFFITI_PROOF_SUBMIT                  │
            │     (Chunk, Merkle Path, Seed, Nonce)      │
            ├───────────────────────────────────────────►│ (Verifies Merkle branch & challenge)
            │◄───────────────────────────────────────────┤ (Status: ok)
            │                                            │
            │  3. GRAFFITI_BUILD_PAYOUT                  │
            │     (art_id, epoch, broadcast: true)       │
            ├───────────────────────────────────────────►│ (Builds & broadcasts payout tx)
            │◄───────────────────────────────────────────┤ (Returns built tx / status ok)
```

### A. Sender Verification & Peer Resolution (`_resolve_storage_sender_meta`)
Calls to Storage RPC endpoints are strictly gated:
1. **Registered Storage Peer**: The sender must have performed a handshake with `role: "NODE_STORAGE"`, registering its IP, port, `node_id`, and `pubkey` in `network.storage_peers`.
2. **Valid Storer Address**: The metadata must contain a valid Bech32 (`tsar1...`) or legacy Tsar address.
3. **Public Key Pinning**: If a public key is registered for the `node_id`, the incoming `src_pubkey` must match.

### B. Anti-Replay Guard (`self.nonce_guard`)
Both storage RPCs require replay protection parameters:
- `ts` (Unix timestamp in seconds)
- `nonce` (Unique random string per request)

The request is rejected with `{"error": "replay_guard"}` if `ts` falls outside `CFG.REPLAY_WINDOW_SEC` or if the `(sender, nonce)` tuple has already been seen.

### C. Rate Limiting
Storage RPC calls are protected by a token bucket rate limiter:
- Key: `storage_rpc:<ip>`
- Parameters: `CFG.STORAGE_RPC_RL_IP_BURST`, `CFG.STORAGE_RPC_RL_WINDOW_S`, `CFG.STORAGE_RPC_RL_BACKOFF_S`.

---

## 2. Endpoint Summary

| RPC Type | Purpose | Auth Requirement | Rate Limit |
| :--- | :--- | :---: | :--- |
| **`GRAFFITI_PROOF_SUBMIT`** | Submit cryptographic Proof of Retention for an art chunk | Registered Storage Peer | `CFG.STORAGE_RPC_RL_*` |
| **`GRAFFITI_BUILD_PAYOUT`** | Build & broadcast storer reward transaction for verified proofs | Registered Storage Peer | `CFG.STORAGE_RPC_RL_*` |

---

## 3. Endpoint Specifications

### 1. `GRAFFITI_PROOF_SUBMIT`
Submits a Proof of Retention challenge solution for a specific Graffiti art payload in a given epoch.

- **Category**: `STORAGE_RPC_TYPES` (Storage Only)
- **Internal Handler**: `_handle_storage_proof_submit()`

#### Verification Pipeline
1. **Replay Check**: Validates `ts` and `nonce`.
2. **Field Validation**: Verifies `art_id`, `epoch`, `offset`, `length`, `hash`, `storer`, and `height`.
3. **Post Existence**: Looks up `art_id` in the on-chain Graffiti registry (`_graffiti_registry.get_post()`).
4. **Challenge Derivation**: Recomputes the expected deterministic byte range challenge via `GRAFFITI.calc_proof_challenge(art_id, size, height)`.
5. **Merkle Proof Verification**:
   - Decodes Base64 `chunk` bytes and validates `len(chunk) == length`.
   - Computes `SHA256(chunk)` and compares it against `hash`.
   - Verifies the Merkle inclusion path against the registered `mroot` using `GRAFFITI.verify_merkle_path()`.
6. **Conflict Check & Recording**: Ensures no conflicting proof hash exists for the `(art_id, storer, epoch)` tuple, then stores the proof in `_graffiti_registry`.

#### Request Payload
```json
{
  "type": "GRAFFITI_PROOF_SUBMIT",
  "art_id": "art_a1b2c3d4e5f6...",
  "epoch": 42,
  "height": 4200,
  "storer": "tsar1qxyz987...",
  "offset": 131072,
  "length": 65536,
  "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "seed": "seed_hex_value...",
  "chunk": "aGVsbG8gd29ybGQgY2h1bmsgZGF0YS4uLg==",
  "path": [
    {"dir": "left", "hash": "0123456789abcdef..."},
    {"dir": "right", "hash": "fedcba9876543210..."}
  ],
  "ts": 1740000100,
  "nonce": "rnd_nonce_9876"
}
```

#### Response Payload (Success)
```json
{
  "status": "ok",
  "art_id": "art_a1b2c3d4e5f6...",
  "epoch": 42
}
```

#### Error Responses
- `{"error": "forbidden: storage-only endpoint"}`: Node is not a registered storage peer.
- `{"error": "replay_guard"}`: Expired timestamp or duplicate nonce.
- `{"error": "unknown_art_id"}`: Art ID does not exist in chain storage.
- `{"error": "epoch_out_of_range", "tip_epoch": 42}`: Challenge height is outside accepted epoch drift window.
- `{"error": "merkle_path_invalid"}`: Merkle proof branch does not evaluate to root.
- `{"error": "proof_conflict"}`: Conflicting proof hash submitted for the same epoch.

---

### 2. `GRAFFITI_BUILD_PAYOUT`
Constructs a valid payout transaction claiming the storage reward for verified retained files and optionally broadcasts it to the mempool.

- **Category**: `STORAGE_RPC_TYPES` (Storage Only)
- **Internal Handler**: `_handle_storage_build_payout()`

#### Verification Pipeline
1. **Replay Check**: Validates `ts` and `nonce`.
2. **Recipient Validation**: Ensures recipient address matches authenticated `storer_addr`. Only 1 recipient allowed per payout.
3. **Proof Lookup**: Retrieves the latest verified proof from `_graffiti_registry.get_latest_proof(art_id, storer_addr)`.
4. **Epoch Check**: Ensures the epoch is valid, not in the future (`epoch <= tip_epoch`), and matches the verified proof.
5. **Cooldown Guard**: Enforces `CFG.ARCHIVIST_AUTO_PAYOUT_COOLDOWN_SEC` per `(art_id, storer)` to prevent spam.
6. **Transaction Generation**: Uses `GRAFFITI.build_payout_tx()` to construct SegWit transaction inputs/outputs and unlock storage contract UTXOs.
7. **Broadcast (Optional)**: If `broadcast: true`, injects the transaction into the network via Dandelion++ stem phase or standard transaction propagation.

#### Request Payload
```json
{
  "type": "GRAFFITI_BUILD_PAYOUT",
  "art_id": "art_a1b2c3d4e5f6...",
  "epoch": 42,
  "recipients": [
    {
      "addr": "tsar1qxyz987...",
      "amount": 5000000
    }
  ],
  "fee_rate": 2,
  "broadcast": true,
  "ts": 1740000200,
  "nonce": "rnd_nonce_1234"
}
```

#### Response Payload (Success)
```json
{
  "status": "ok",
  "tx": {
    "txid": "7c9e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda999",
    "version": 1,
    "locktime": 0,
    "inputs": [ ... ],
    "outputs": [ ... ]
  }
}
```

#### Error Responses
- `{"error": "missing_proof"}`: No valid Proof of Retention found in registry for this art ID and storer.
- `{"error": "epoch_in_future", "tip_epoch": 42}`: Requested payout epoch has not matured yet.
- `{"error": "payout_cooldown", "retry_after": 120}`: Rate cooldown between payouts has not elapsed.
- `{"error": "payout_recipient_mismatch"}`: Recipient address does not match authenticated storer address.
- `{"error": "broadcast_failed"}`: Transaction failed validation during mempool injection.
