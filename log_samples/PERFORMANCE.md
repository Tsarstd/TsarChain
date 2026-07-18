# Graffiti Protocol - Performance & Implementation Evidence

This document outlines the performance benchmarks and implementation evidence of the **Graffiti Protocol**, referencing the raw logs found in this directory. 

We highlight four key areas to demonstrate the efficiency and stability of the network under different loads and states:

## 1. Mining Validation Speed & RandomX Warmup (`miner.log`)
The mining logs provide evidence of our PoW (RandomX) block validation efficiency.

- **Fast Block Validation**: Once initialized, block validations (`pow_ms`) typically take **< 25 ms** per block (e.g., `22.413 ms` for height 1, and `18.46 ms` for height 2).
- **The Initial Warning (RandomX Warmup)**: 
  You might notice a warning during the very first block evaluation (Height 0):
  ```
  [WARNING] - tsarchain.network.cast.receive: [receive_block] slow total=5823.967 ms height=0 deser=0.174 lock=0.002 pre=0.082 val=5820.271 add=3.221 mempool=0.006 utxo=None bcast=0.029
  ```
  **Why does this happen?** This is standard expected behavior. RandomX requires the initialization of a large dataset and cache to provide ASIC-resistance. This setup phase runs once during node startup or epoch switch. The warning simply indicates that generating the cache took ~5.8 seconds, after which block validations become incredibly fast (around 18-22 ms).

## 2. Node Syncing & RPC Performance (`node_bootstrap.log`)
During the node bootstrap phase, RPC handles requests exceptionally quickly, allowing for rapid network synchronization.

- **Extremely Low Latency**: Core RPC calls execute in sub-millisecond times:
  - `GET_BALANCES`: ~`0.650 ms`
  - `GET_BLOCK_HASH`: ~`0.102 ms`
  - `GET_HEADERS` & `GET_MEMPOOL`: `< 0.05 ms`
- **Efficient Caching**: The log illustrates cache hits efficiently reducing lookup times (e.g., `cache_hit=True` cutting `GET_BLOCK_HASH` to `0.171 ms` including network overhead).

## 3. Storage Proofs & Integration (`storage_node.log`)
Graffiti Protocol integrates native storage capabilities for cultural archiving, validated via cryptographic proofs on-chain.

- **Handshake and Init**: Demonstrates seamless connections to the main blockchain network on port `38169`.
- **Commitment Flow**: Shows the `STOR_INIT` and `STOR_COMMIT` procedures correctly handling files (e.g., handling payloads of size `~6.5MB` securely).
- **Continuous Proofing**: Node execution continuously monitors the file integrity by responding to `STOR_PROOF_RUN` challenges at varying offsets, ensuring long-term data immutability.

## 4. Wallet Signing Speed (`wallet.log`)
The wallet handles transaction formation, security, and embedding digital artifact references.

- **Sub-millisecond Transaction Signing**: Preparing and signing transactions (`sign_prepared_tx`) typically clocks at **< 1 ms** (`0.605 ms`, `0.612 ms`), ensuring rapid throughput from the user's perspective.
- **OP_RETURN Data Capacity**: Shows the network confidently handling `OP_RETURN` payload bounds (e.g., accommodating `435 bytes` of Graffiti signature data while adhering to a strict `506 bytes` limit).
- **Local Artifact Fetching**: Safely retrieves referenced artifacts (e.g., `art=graf56222a903a7c`) from the decentralized storage network.

---

> Feel free to explore the `.log` files in this directory to view the raw execution data and confirm these benchmarks.
