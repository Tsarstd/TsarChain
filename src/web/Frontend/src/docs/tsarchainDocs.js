export const TSARCHAIN_DOCS = {
  architecture: {
    id: "architecture",
    title: "Graffiti Protocol Architecture",
    subtitle: "Hybrid Consensus, Ledger & Storage Subsystem",
    category: "Tsarchain",
    badge: "Technical Core",
    diagram: "/transactions_flow.svg",
    toc: [
      { id: "overview", label: "Architecture Overview" },
      { id: "project-folder-map", label: "Project Folder Map" },
      { id: "data-structures", label: "Data Structures (Interactive Previews)" },
      { id: "consensus-pow", label: "Consensus & Proof-of-Work (PoW)" },
      { id: "utxo-ledger-mempool", label: "UTXO Ledger State & Mempool" },
      { id: "rust-native-extension", label: "Rust Native Extension (tsarcore_native)" },
      { id: "graffiti-protocol-logic", label: "Graffiti Protocol Core Logic" },
    ],
    sections: [
      {
        id: "overview",
        title: "Architecture Overview",
        content: `This document provides an in-depth technical overview of the Graffiti Protocol. The architecture relies on a hybrid design that couples lightweight on-chain UTXO execution with off-chain heavy data storage, prioritizing the permanent archiving of digital art and testimonies.`
      },
      {
        id: "project-folder-map",
        title: "Project Folder Map",
        collapsibleTree: {
          title: "TsarChain Project Architecture Tree",
          code: `TsarChain/
├── apps/
│   ├── cli_archivist.py                     # Storage Node (Archivist CLI)
│   ├── cli_node_miner.py                    # Miner CLI (Full Node)
│   └── wallet.py                            # Wallet GUI (Kremlin Wallet) 
│
├── assets/                                  # Logo, img, diagrams
├── benchmarks/                              # tsarcore_native benchmark suite
├── docs/                                    # Whitepapers, Drafts & Specifications
├── scripts/                                 # Devnet orchestration & utility scripts
├── src/
│   ├── archivist/                           # Storage Node P2P & LMDB logic
│   ├── kremlin/                             # Wallet cryptographic core, UI, Double Ratchet
│   ├── tsarchain/
│   │   ├── consensus/                       # RandomX PoW, validation, chain operations
│   │   ├── contracts/                       # Graffiti registry & deterministic P2WSH
│   │   ├── core/                            # Block, CoinbaseTx, Transaction models
│   │   ├── mempool/                         # TxPool validation, sorting & limits
│   │   ├── network/                         # P2P SecureChannel, Dandelion++, RPC handlers
│   │   ├── storage/                         # LMDB database, UTXO delta validation
│   │   └── utils/                           # Config, logging, thread monitors
│   └── web/
│       ├── Backend/                         # Explorer API backend
│       └── Frontend/                        # React web explorer & documentation hub
├── tsarcore_native/                         # Rust + PyO3 Native Acceleration Crate
└── tests/                                   # Python & Rust Unit testing suite`
        }
      },
      {
        id: "data-structures",
        title: "Data Structures (Interactive Previews)",
        content: `The examples below illustrate real live serialized states across blocks, UTXOs, mempool, and Graffiti activity. Click **"Show Preview"** on any item to inspect its complete JSON payload:`,
        dataStructures: [
          {
            id: "tx-block-data",
            title: "1. Block Data Structure (.json)",
            subtitle: "Block height 10 validating 2300 coins transfer + Coinbase reward",
            code: `{
  "_meta": {
    "bits": 520891868,
    "chainwork": 42774,
    "comment_count": 0,
    "comments": [],
    "difficulty": 5381,
    "graffiti": [],
    "graffiti_post_count": 0,
    "hash": "0002ad9c5a26748032625d4a95d1df44e9bd4f7d69064c0dcc7e52673706c128",
    "height": 10,
    "merkle_root": "9042794daf2d482b486f912cbb043f22c1505c7d1f7fd07cceea8a55b9b2feaa",
    "nonce": 4030,
    "payout_count": 0,
    "payouts": [],
    "prev_block_hash": "0008509a86bf895c69201986b7fad8ac3013dec48020aab8975f835d812dcd38",
    "schema_version": 1,
    "size_bytes": 1695,
    "target": 2.151867455121296e73,
    "timestamp": 1764669449,
    "tx_count": 2,
    "vbytes": 1695,
    "version": 1,
    "weight": 6780
  },
  "bits": 520891868,
  "hash": "0002ad9c5a26748032625d4a95d1df44e9bd4f7d69064c0dcc7e52673706c128",
  "height": 10,
  "merkle_root": "9042794daf2d482b486f912cbb043f22c1505c7d1f7fd07cceea8a55b9b2feaa",
  "nonce": 4030,
  "prev_block_hash": "0008509a86bf895c69201986b7fad8ac3013dec48020aab8975f835d812dcd38",
  "timestamp": 1764669449,
  "transactions": [
    {
      "block_id": "Evan_Gershkovich_2023_fv8Zsb0I4",
      "fee": 0,
      "height": 10,
      "inputs": [
        {
          "amount": 0,
          "script_sig": "010a1f4576616e5f47657273686b6f766963685f323032335f6676385a7362304934",
          "txid": "0000000000000000000000000000000000000000000000000000000000000000",
          "vout": 4294967295,
          "witness": []
        }
      ],
      "is_coinbase": true,
      "locktime": 0,
      "outputs": [
        {
          "amount": 25000004900,
          "script_pubkey": "0014266dd5c8b1fb3a0d18710146713af668b762dc6f"
        }
      ],
      "reward": 25000004900,
      "to_address": "tsar1qyekatj93lvaq6xr3q9r8zwhkdzmk9hr0fmfrss",
      "txid": "4a5aa34596685b8eeff5f40ce6cf53fece1cd57e6a8cce9c984c7334ea36d2b4",
      "type": "Coinbase",
      "version": 1
    },
    {
      "fee": 4900,
      "inputs": [
        {
          "amount": 2500000000000,
          "script_sig": "",
          "txid": "9555fe396baf338bb3b8c27fa30b414ce1eeecd830a416895ab12eecf5188e45",
          "vout": 0,
          "witness": [
            "3045022100d51d37097042d95a552218df5130347e9b090630447b9e00d88a7eb52af4599b0220501544279d82de6d795588b538e5e3461cd962c25339ba723a7541f942a68a5d01",
            "0338e4581fec6cee44675bae99ff4eabe31d1ef412e54bb16f96ee97d796515e58"
          ]
        }
      ],
      "is_coinbase": false,
      "locktime": 0,
      "outputs": [
        {
          "amount": 230000000000,
          "script_pubkey": "00149fb49a362a364b57d2f05e7929109cedc7824ef4"
        },
        {
          "amount": 2269999995100,
          "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
        }
      ],
      "txid": "88bc192050945f1723ab416d8c53bc1b332d2d8fa737d3dfb26c931df9fc04b5",
      "version": 1
    }
  ],
  "version": 1
}`
          },
          {
            id: "tx-utxo-data",
            title: "2. UTXO Ledger State (.json)",
            subtitle: "Unspent outputs mapping txid:vout to address, script_type, and amounts",
            code: `{
  "4a5aa34596685b8eeff5f40ce6cf53fece1cd57e6a8cce9c984c7334ea36d2b4:0": {
    "address": "tsar1qyekatj93lvaq6xr3q9r8zwhkdzmk9hr0fmfrss",
    "block_height": 10,
    "is_coinbase": true,
    "script_type": "p2wpkh",
    "tx_out": {
      "amount": 25000004900,
      "script_pubkey": "0014266dd5c8b1fb3a0d18710146713af668b762dc6f"
    }
  },
  "88bc192050945f1723ab416d8c53bc1b332d2d8fa737d3dfb26c931df9fc04b5:0": {
    "address": "tsar1qn76f5d32xe9405hsteujjyyuahrcynh5cxjw23",
    "block_height": 10,
    "is_coinbase": false,
    "script_type": "p2wpkh",
    "tx_out": {
      "amount": 230000000000,
      "script_pubkey": "00149fb49a362a364b57d2f05e7929109cedc7824ef4"
    }
  },
  "88bc192050945f1723ab416d8c53bc1b332d2d8fa737d3dfb26c931df9fc04b5:1": {
    "address": "tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr",
    "block_height": 10,
    "is_coinbase": false,
    "script_type": "p2wpkh",
    "tx_out": {
      "amount": 2269999995100,
      "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
    }
  }
}`
          },
          {
            id: "tx-mempool-data",
            title: "3. MemPool Queue Data Structure (.json)",
            subtitle: "Unconfirmed transactions with fee rate, vbytes, and witness signatures",
            code: `{
  "meta": {
    "count": 1,
    "generated_at": 1764669428,
    "max_size_bytes": 1048576,
    "schema_version": 1,
    "virtual_size": 205
  },
  "schema_version": 1,
  "txs": [
    {
      "_meta": {
        "fee_rate": 23.902439024390244,
        "received_at": 1764669428.5156598,
        "schema_version": 1,
        "vbytes": 205,
        "weight": 820
      },
      "fee": 4900,
      "inputs": [
        {
          "amount": 2500000000000,
          "script_sig": "",
          "txid": "9555fe396baf338bb3b8c27fa30b414ce1eeecd830a416895ab12eecf5188e45",
          "vout": 0,
          "witness": [
            "3045022100d51d37097042d95a552218df5130347e9b090630447b9e00d88a7eb52af4599b0220501544279d82de6d795588b538e5e3461cd962c25339ba723a7541f942a68a5d01",
            "0338e4581fec6cee44675bae99ff4eabe31d1ef412e54bb16f96ee97d796515e58"
          ]
        }
      ],
      "is_coinbase": false,
      "locktime": 0,
      "outputs": [
        {
          "amount": 230000000000,
          "script_pubkey": "00149fb49a362a364b57d2f05e7929109cedc7824ef4"
        },
        {
          "amount": 2269999995100,
          "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
        }
      ],
      "txid": "88bc192050945f1723ab416d8c53bc1b332d2d8fa737d3dfb26c931df9fc04b5",
      "version": 1
    }
  ]
}`
          },
          {
            id: "graffiti-post-block",
            title: "4. Graffiti POST Block (Height 18) (.json)",
            subtitle: "Upload TX, OP_RETURN payload, and deterministic pool funding",
            code: `{
  "_meta": {
    "bits": 521525829,
    "chainwork": 73967,
    "difficulty": 2999,
    "graffiti": [
      {
        "art_id": "grafd99f16dde43a8c2740396ba6a71d8f1666612c4a9790d7060edfe236cfd8",
        "block_hash": "0000c537b986eb97881f942e6f5e716cbe544029fd3ea697eb85c99ee9f636f8",
        "creator": "tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr",
        "mime": "image/jpeg",
        "receipt": "rcpt_9b29cf795af60e77ee707df235f276e825fc0ee0f0c75b8b76d0dd29f7cdf701_1764670929_1764670929",
        "sha256": "9b29cf795af60e77ee707df235f276e825fc0ee0f0c75b8b76d0dd29f7cdf701",
        "size": 80358,
        "storer": "tsar1qzxzzf5az5guk43mf0z4d94uugat4jcejwglp07",
        "txid": "d852811a7ff8dc4c6502936dd0f0e0707693828da8a0cb973a7695ef0624472a"
      }
    ],
    "graffiti_post_count": 1,
    "hash": "0000c537b986eb97881f942e6f5e716cbe544029fd3ea697eb85c99ee9f636f8",
    "height": 18
  },
  "transactions": [
    {
      "block_id": "grafd99f16dde43a8c2740396ba6a71d8f1666612c4a9790d7060edfe236cfd8",
      "fee": 0,
      "height": 18,
      "is_coinbase": true,
      "to_address": "tsar1qyekatj93lvaq6xr3q9r8zwhkdzmk9hr0fmfrss",
      "reward": 25000000171
    },
    {
      "txid": "d852811a7ff8dc4c6502936dd0f0e0707693828da8a0cb973a7695ef0624472a",
      "fee": 171,
      "outputs": [
        {
          "amount": 80000000,
          "script_pubkey": "0020dbd880c2063b8b46b6cbda507d76f721f519f15caa9d4063378cd55359963c76"
        },
        {
          "amount": 2269919994929,
          "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
        },
        {
          "amount": 0,
          "script_pubkey": "6a4dbd01545341525f4752414631..."
        }
      ]
    }
  ]
}`
          },
          {
            id: "graffiti-comment-block",
            title: "5. Graffiti COMMENT Block (Height 22) (.json)",
            subtitle: "80% creator royalty, 10% storage pool split, and immutable on-chain comment",
            code: `{
  "_meta": {
    "height": 22,
    "hash": "000e99f426c6a97a5e9cd21def839b67b7d4321e9b99b62fdeec08fbb01cc59b",
    "comment_count": 1,
    "comments": [
      {
        "art_id": "grafd99f16dde43a8c2740396ba6a71d8f1666612c4a9790d7060edfe236cfd8",
        "commenter": "tsar1qn76f5d32xe9405hsteujjyyuahrcynh5cxjw23",
        "creator": "tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr",
        "amount": 100000000,
        "tip": 200000000,
        "txid": "a0ad4ea081325a40e61926b3657533750ed704ace00dadc0b087ea8d5fb20576"
      }
    ]
  },
  "transactions": [
    {
      "txid": "a0ad4ea081325a40e61926b3657533750ed704ace00dadc0b087ea8d5fb20576",
      "outputs": [
        {
          "amount": 280000000,
          "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
        },
        {
          "amount": 10000000,
          "script_pubkey": "0020dbd880c2063b8b46b6cbda507d76f721f519f15caa9d4063378cd55359963c76"
        },
        {
          "amount": 229709999798,
          "script_pubkey": "00149fb49a362a364b57d2f05e7929109cedc7824ef4"
        },
        {
          "amount": 0,
          "script_pubkey": "6a4d2801545341525f4752414631..."
        }
      ]
    }
  ]
}`
          },
          {
            id: "graffiti-payout-block",
            title: "6. Graffiti PAYOUT Block (Height 29) (.json)",
            subtitle: "Archivist storage reward claim from deterministic P2WSH pool",
            code: `{
  "_meta": {
    "height": 29,
    "hash": "0002b13e5a9b9b19098eb1d7fd9aa2ab7e5a9869bb20d038ef823a54790fc5d0",
    "payout_count": 1,
    "payouts": [
      {
        "art_id": "grafd99f16dde43a8c2740396ba6a71d8f1666612c4a9790d7060edfe236cfd8",
        "epoch": 0,
        "recipients": [
          {
            "addr": "tsar1qzxzzf5az5guk43mf0z4d94uugat4jcejwglp07",
            "amount": 60000000
          }
        ],
        "txid": "cf5a20bfc3ac20250b1556cad466c4d1a6e937a6e7c8f645a6ff961e78dfe46d"
      }
    ]
  }
}`
          },
          {
            id: "graffiti-registry-metadata",
            title: "7. Graffiti Registry Metadata (.json)",
            subtitle: "Indexed artwork records, retention proofs, comments, and pool statistics",
            code: `{
  "posts": {
    "grafd99f16dde43a8c2740396ba6a71d8f1666612c4a9790d7060edfe236cfd8": {
      "art_id": "grafd99f16dde43a8c2740396ba6a71d8f1666612c4a9790d7060edfe236cfd8",
      "block_hash": "0000c537b986eb97881f942e6f5e716cbe544029fd3ea697eb85c99ee9f636f8",
      "block_height": 18,
      "creator": "tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr",
      "mime": "image/jpeg",
      "pool_address": "tsar1qm0vgpssx8w95ddktmfg86ahhy863nu2u42w5qceh3n24xkvk83mqqa2jng",
      "sha256": "9b29cf795af60e77ee707df235f276e825fc0ee0f0c75b8b76d0dd29f7cdf701",
      "size": 80358,
      "stats": {
        "comments": 1,
        "creator_paid": 280000000,
        "last_paid_epoch": 0,
        "pool_balance": 29993000,
        "storage_paid": 10000000
      },
      "storer": "tsar1qzxzzf5az5guk43mf0z4d94uugat4jcejwglp07",
      "txid": "d852811a7ff8dc4c6502936dd0f0e0707693828da8a0cb973a7695ef0624472a"
    }
  },
  "proofs": {
    "grafd99f16dde43a8c2740396ba6a71d8f1666612c4a9790d7060edfe236cfd8": [
      {
        "epoch": 1,
        "hash": "4da974820fa3deac4f0925e845835f32623176054676a3cc28d318b45ee6d8ca",
        "height": 20,
        "length": 4096,
        "offset": 38125,
        "storer": "tsar1qzxzzf5az5guk43mf0z4d94uugat4jcejwglp07"
      }
    ]
  }
}`
          },
          {
            id: "network-state-data",
            title: "8. Network State Database (.json)",
            subtitle: "Consensus telemetry, circulating supply, hashrate, and miner leaderboards",
            code: `{
  "chain": {
    "avg_block_time_sec_window": 166.05,
    "est_network_hashrate_hps_window": 14,
    "genesis_hash": "00118ebfac2f0cbde5b21f1a53568fbf9f35e5ea1dce95ee502ba05e6f4adea0",
    "genesis_message": "Every person who is born free has the same rights and dignity. (Munir Said Thalib - 2004-09-07)",
    "target_block_time_sec": 37,
    "tip_difficulty": 2452,
    "tip_height": 31,
    "total_blocks": 32
  },
  "graffiti": {
    "comments": 1,
    "graffiti_on_mempool": 0,
    "payouts": 1,
    "pool_balances": 29993000,
    "posts": 1
  },
  "identity": {
    "address_prefix": "tsar",
    "network_id": "gulag-net",
    "pow_algo": "randomx"
  },
  "supply": {
    "circulating_estimate": 250125000000000,
    "current_block_subsidy": 25000000000,
    "max_supply": 25250000000000000,
    "next_halving_height": 235000
  }
}`
          }
        ]
      },
      {
        id: "consensus-pow",
        title: "Consensus & Proof-of-Work (PoW)",
        content: `The Mining Orchestrator & Mempool Queue :

The mining logic (\`src/tsarchain/consensus/mining.py\`) serves as the orchestrator for block creation. When a miner attempts to build a candidate block, it interacts directly with the \`TxPool\` applying strict priority algorithms.

**Mempool Queuing Policy :**

- **Graffiti Posts**: Transactions carrying an \`OP_RETURN\` payload representing a new piece of art or testimony. These are sorted strictly by \`_received_at\` timestamp.
- **Standard UTXOs**: Standard financial/token transfers, sorted by \`fee\` (descending) and then timestamp.

The orchestrator pulls queued Graffiti transactions to the absolute front of the line, guaranteeing prioritized execution for cultural archiving.

> **1 BLOCK = 1 GRAFFITI**
> To prevent spam and maintain the semantic weight of each block, the candidate block builder enforces a strict quota: **a block may contain a maximum of 1 Graffiti POST transaction**.

Block Anchoring & Coinbase Etching :

When building a block with a Graffiti \`POST\`, the orchestrator extracts the unique \`art_id\` and injects it directly into the \`CoinbaseTx\` as the \`block_id\`. This irrevocably etches the identity of the digital artifact into the root of the miner reward.

RandomX Consensus & Native Extensions :

- **Rust Interoperability**: Mining loops and VM cache initialization execute natively in Rust (\`tsarcore_native\`).
- **Difficulty Adjustment**: \`difficulty.py\` dynamically adjusts the target to maintain stable block intervals using LWMA principles.`
      },
      {
        id: "utxo-ledger-mempool",
        title: "UTXO Ledger State & Mempool",
        content: `Database & Validation Layer :

- \`UTXOValidator\`: Coordinates in-memory state rebuilds (\`rebuild_from_chain\`) and periodic disk flushing (\`maybe_flush_utxo\`).
- Python-Rust Hybrid : Compacts transaction records into Python tuples and executes bulk state transitions via \`native_utxo_build_ops_compact\` directly in LMDB.

Graffiti Transaction Lifecycle in UTXO :

- **POST** : Derives deterministic P2WSH pool address \`GRF_POOL(art_id)\`, enforces minimum upload endowment, records to \`_graffiti_registry\`.
- **COMMENT** : Splits comment payment automatically (80% creator, 10% storage pool, 10% miner fee).
- **PAYOUT** : Validates storage node retention proofs and releases pool funds.`
      },
      {
        id: "rust-native-extension",
        title: "Rust Native Extension (tsarcore_native)",
        content: `- **PyO3 Bindings**: High-speed boundary conversion between Python and Rust.
- **RandomX VM Cache**: Maintains active virtual machines statically in memory, preventing recompilation stalls.
- **Parallel Validation (Rayon)**: Multi-signature verification (\`secp_verify_der_low_s_many\`) runs across thread pools outside Python's GIL.
- **Merkle Proof Engine**: Computes single-SHA256 file Merkle roots and inclusion paths at native disk I/O speeds.`
      },
      {
        id: "graffiti-protocol-logic",
        title: "Graffiti Protocol Core Logic",
        content: `- **Deterministic P2WSH Pools**: Balances are locked in redeem scripts and released exclusively upon valid storage retention claims.
- **Retention Audits**: \`calc_proof_challenge\` computes a deterministic byte offset and chunk length per active epoch for each storer.
- **Logarithmic Verification**: Merkle proofs verify random byte chunks in \`O(log N)\` complexity without loading multi-gigabyte files into RAM.`
      }
    ]
  },

  api: {
    id: "api",
    title: "Graffiti Protocol - API & RPC Documentation",
    subtitle: "JSON-RPC over TCP Socket Protocol",
    category: "Tsarchain",
    badge: "Socket RPC",
    toc: [
      { id: "network-socket-overview", label: "1. Network & Socket Protocol Overview" },
      { id: "security-anti-spam", label: "2. Security & Anti-Spam (Rate Limiting & PoW)" },
      { id: "user-rpc", label: "3. User RPC Category (USER)" },
      { id: "miner-rpc", label: "4. Miner Consensus RPC (MINER)" },
      { id: "storage-rpc", label: "5. Storage Node RPC (STORAGE)" },
      { id: "archivist-rpc", label: "6. Archivist (Storage Layer) RPC" },
    ],
    sections: [
      {
        id: "network-socket-overview",
        title: "1. Network & Socket Protocol Overview",
        content: `This document serves as the primary reference for developers building on or integrating with the Graffiti Protocol node network. Communication between nodes, wallets, storage entities, and explorers operates entirely via JSON-RPC payloads transmitted over a raw TCP socket.

All requests and responses are encapsulated in raw JSON objects passed through a TCP socket. A typical request follows a structured pattern:

\`\`\`json
{
  "type": "ACTION_TYPE",
  "client": "my_client_id",
  "...": "additional payload parameters"
}
\`\`\`

The node processes the message via a core dispatcher (\`processing_msg.py\`) and categorizes the request into one of three distinct roles: **USER**, **MINER**, or **STORAGE**.`
      },
      {
        id: "security-anti-spam",
        title: "2. Security & Anti-Spam (Rate Limiting & PoW)",
        content: `To maintain a durable and attack-resistant decentralized network, Graffiti Protocol enforces strict rate limits and utilizes a Proof-of-Work (PoW) token challenge.

### 🛡️ \`ban_ip\` & Subnet Filtering

The network uses internal logic (found in \`ratelimit.py\`) to prevent spam:

- **Temporary Bans** : Connecting nodes sending malformed payloads, calling \`UNKNOWN\` RPC types, or attempting to access restricted \`MINER\` endpoints without authorization are immediately dropped and their IP/Subnet is banned via the \`ban_ip\` mechanism.
- **CGNAT Awareness** : Rate limits adapt to shared IPs to avoid nuking an entire subnet accidentally.

### 🧩 PoW Handshake Challenge (\`pow_token.py\`)

To bypass aggressive rate limits or authenticate a heavy query, a client can submit a stateless Proof-of-Work solution:

- The server issues a challenge token (\`issue_pow\`) requiring a specific \`difficulty\` level.
- The client calculates a \`nonce\` (\`solve_pow\`) that results in a SHA-256 hash containing a sufficient number of leading zero bits.
- The server instantly verifies the \`nonce\` (\`verify_pow\`) without keeping it in memory. This effectively mitigates DDoS attacks while preserving server state.`
      },
      {
        id: "user-rpc",
        title: "3. User RPC Category (USER)",
        content: `This is the public-facing API category used by wallets, blockchain explorers, and social chat apps. It handles transactions, fetching blocks, and posting Graffiti art.

### 1. Wallet & Transactions

- \`GET_BALANCES\` : Fetch UTXO balances for an address.
- \`CREATE_TX\` : Construct a new transaction (reguler tx).
- \`CREATE_TX_MULTI\` : Construct a new transaction (Post, Comment & Payout).
- \`NEW_TX\` : Broadcast a signed transaction to the mempool.

*Example (GET_BALANCES):*
\`\`\`json
{
  "type": "GET_BALANCES",
  "address": "tsar1...",
  "client": "wallet_app"
}
\`\`\`

### 2. Explorer Queries

- \`GET_TX_HISTORY\`, \`GET_TX_DETAIL\`: Retrieve transaction metadata.
- \`GET_BLOCK\`, \`GET_BLOCK_RANGE\`: Download block data.
- \`GET_MEMPOOL\`: Fetch pending transactions (including real-time stats for Graffiti posts).

### 3. Graffiti & Chat Protocol (Signal-X3DH)

- \`GRAFFITI_GET_POSTS\`, \`GRAFFITI_GET_COMMENTS\`, \`GRAFFITI_GET_ART\`: Fetch specific cultural archiving activity.
- \`CHAT_REGISTER\`, \`CHAT_SEND\`, \`CHAT_PULL\`, \`CHAT_RELAY\`: Operations for private and relayed peer-to-peer chat utilizing the X3DH key agreement protocol.`
      },
      {
        id: "miner-rpc",
        title: "4. Miner Consensus RPC (MINER)",
        content: `Restricted endpoints specifically used by validation nodes (Miners) to sync the blockchain and agree on the ledger state. Connections often require the \`MINER-AUTHORIZED\` scope via pinned public keys.

- \`HELLO\`: Initial peer handshake.
- \`GET_FULL_SYNC\` / \`FULL_SYNC\`: Bulk download of historical blockchain data.
- \`NEW_BLOCK\`: Propagate a freshly mined block to the network.
- \`GET_HEADERS\` / \`GET_BLOCKS\` / \`GET_BLOCK_HASH\`: Routine sync checks.

*Example (NEW_BLOCK):*
\`\`\`json
{
  "type": "NEW_BLOCK",
  "block": {
    "header": { ... },
    "transactions": [ ... ]
  },
  "rpc_source": "miner"
}
\`\`\``
      },
      {
        id: "storage-rpc",
        title: "5. Storage Node RPC (STORAGE)",
        content: `Specialized endpoints for nodes that participate in archiving the heavy digital media elements of Graffiti.

- \`GRAFFITI_PROOF_SUBMIT\`: Submits a cryptographic proof proving the node is holding the requested artifact chunk at a specific offset.
- \`GRAFFITI_BUILD_PAYOUT\`: Calculates and issues compensation for a storage node successfully passing integrity challenges.

*Example (GRAFFITI_PROOF_SUBMIT):*
\`\`\`json
{
  "type": "GRAFFITI_PROOF_SUBMIT",
  "art_id": "graf562...",
  "proof_data": "...",
  "epoch": 4
}
\`\`\``
      },
      {
        id: "archivist-rpc",
        title: "6. Archivist (Storage Layer) RPC",
        content: `These RPCs are specifically served by Storage Nodes (Archivists) to handle direct file uploads/downloads from users, and to communicate retention proofs with the main network.

### 1. Wallet to Archivist (\`wallet_route.py\`)

Handles the direct file transfer protocol from the end-user (wallet) to the storage node.

- \`STOR_INIT\`: Initializes an upload session, verifying file size and MIME type.
- \`STOR_PUT\`: Uploads the artifact data in chunks (\`base64\`).
- \`STOR_COMMIT\`: Finalizes the upload, verifies the SHA-256 hash, and generates a storage receipt.
- \`STOR_GET_BY_ART\`: Fetches/downloads a digital artifact using its \`art_id\` or \`graffiti_id\`.

*Example (STOR_INIT):*
\`\`\`json
{
  "type": "STOR_INIT",
  "graffiti_id": "grafb5d0...",
  "size_bytes": 6588704,
  "sha256": "a3b4c5...",
  "filename": "art.jpg"
}
\`\`\`

### 2. Node to Archivist (\`node_route.py\`)

Handles integration between the main blockchain bootstrap nodes and the storage nodes.

- \`STOR_INDEX\`: Returns the storage index and total \`bytes_used\`.
- \`STOR_PAID\`: Confirms that the user has paid for storage on-chain, finalizing the file.
- \`STOR_PROOF_RUN\`: Executes a cryptographic Proof-of-Retention challenge at a specific chunk offset.
- \`STOR_GC\`: Triggers garbage collection for unpaid/expired blobs.

*Example (STOR_PROOF_RUN):*
\`\`\`json
{
  "type": "STOR_PROOF_RUN",
  "graffiti_id": "grafb5d0...",
  "tip_height": 14500
}
\`\`\``
      }
    ]
  },

  performance: {
    id: "performance",
    title: "Performance & Evidence",
    subtitle: "Validation Benchmarks & Empirical Telemetry",
    category: "Tsarchain",
    badge: "Benchmarks",
    toc: [
      { id: "pow-warmup-validation", label: "1. PoW Validation & Warmup" },
      { id: "node-syncing-rpc", label: "2. Node Syncing & RPC Performance" },
      { id: "storage-proofs", label: "3. Storage Proofs & Integration" },
      { id: "wallet-throughput", label: "4. Wallet Signing Throughput" },
    ],
    sections: [
      {
        id: "pow-warmup-validation",
        title: "1. PoW Validation & Warmup",
        content: `The mining logs demonstrate high-efficiency Proof-of-Work validation:
- **Block Validation**: Once warmed up, block validation takes **< 25 ms** per block (e.g. \`18.46 ms\` at height 2).
- **Initial Warmup Phase**: The first block evaluation (Height 0) allocates and compiles the RandomX dataset cache (~5.8s), ensuring subsequent validations execute at sub-25ms speeds.`
      },
      {
        id: "node-syncing-rpc",
        title: "2. Node Syncing & RPC Performance",
        items: [
          { label: "GET_BALANCES", text: "~0.650 ms lookup time" },
          { label: "GET_BLOCK_HASH", text: "~0.102 ms" },
          { label: "GET_HEADERS / MEMPOOL", text: "< 0.050 ms" },
          { label: "LMDB Cache Hits", text: "< 0.171 ms including network transport overhead" }
        ]
      },
      {
        id: "storage-proofs",
        title: "3. Storage Proofs & Integration",
        content: `- **Handshake & Init**: Seamless connection on port \`38169\`.
- **Commitment Throughput**: \`STOR_INIT\` and \`STOR_COMMIT\` securely process large payloads (up to ~6.5MB+) with zero-copy LMDB memory maps.
- **Continuous PoR Audits**: Evaluates byte-range challenges deterministically at arbitrary offsets without loading full files into memory.`
      },
      {
        id: "wallet-throughput",
        title: "4. Wallet Signing Throughput",
        content: `- **Signing Speed**: Preparing and ECDSA signing transactions (\`sign_prepared_tx\`) takes **< 1 ms** (\`0.605 ms\`).
- **OP_RETURN Data Capacity**: Reliably packages graffiti payloads up to protocol bounds.`
      }
    ]
  },

  references: {
    id: "references",
    title: "References & Standards",
    subtitle: "Bitcoin Improvement Proposals & Cryptographic Specifications",
    category: "Tsarchain",
    badge: "Standards",
    toc: [
      { id: "bips", label: "Bitcoin Improvement Proposals (BIPs)" },
      { id: "bitcoin-references", label: "Bitcoin Developer Reference" },
      { id: "algorithms-libraries", label: "Algorithms & Libraries" },
      { id: "secure-messaging", label: "Secure Messaging (Signal-style)" },
      { id: "cryptographic-primitives", label: "Cryptographic Primitives" },
    ],
    sections: [
      {
        id: "bips",
        title: "Bitcoin Improvement Proposals (BIPs)",
        links: [
          { title: "BIP-141", url: "https://bips.dev/141/", desc: "Segregated Witness (Consensus layer)" },
          { title: "BIP-143", url: "https://bips.dev/143/", desc: "Transaction Signature Verification for Version 0 Witness Program" },
          { title: "BIP-173", url: "https://bips.dev/173/", desc: "Bech32 address format for native SegWit outputs" },
          { title: "BIP-39", url: "https://bips.dev/39/", desc: "Mnemonic code for generating deterministic keys" },
          { title: "BIP-146", url: "https://bips.dev/146/", desc: "Dealing with signature encoding malleability (Low-S)" }
        ]
      },
      {
        id: "bitcoin-references",
        title: "Bitcoin Developer Reference",
        links: [
          { title: "Transactions: CompactSize", url: "https://developer.bitcoin.org/reference/transactions.html", desc: "Varint and transaction serialization standards" },
          { title: "Block Chain & Merkle Root", url: "https://developer.bitcoin.org/reference/block_chain.html", desc: "Block header hashing and Merkle tree validation" }
        ]
      },
      {
        id: "algorithms-libraries",
        title: "Algorithms & Libraries",
        links: [
          { title: "LWMA Difficulty Algorithm", url: "https://github.com/zawy12/difficulty-algorithms/issues/3", desc: "Linearly Weighted Moving Average for responsive PoW adjustment" },
          { title: "libsecp256k1", url: "https://github.com/bitcoin-core/secp256k1", desc: "Optimized C library for EC operations on curve secp256k1" },
          { title: "RandomX Reference", url: "https://github.com/tevador/RandomX", desc: "ASIC-resistant Proof of Work algorithm" }
        ]
      },
      {
        id: "secure-messaging",
        title: "Secure Messaging (Signal-style)",
        links: [
          { title: "The X3DH Protocol", url: "https://signal.org/docs/specifications/x3dh", desc: "Extended Triple Diffie-Hellman Key Agreement" },
          { title: "The Double Ratchet Algorithm", url: "https://signal.org/docs/specifications/doubleratchet", desc: "Continuous key ratcheting for end-to-end encrypted messaging" }
        ]
      },
      {
        id: "cryptographic-primitives",
        title: "Cryptographic Primitives",
        links: [
          { title: "RFC 7748", url: "https://www.rfc-editor.org/rfc/rfc7748", desc: "Elliptic Curves for Security (X25519/X448)" },
          { title: "RFC 5869", url: "https://www.rfc-editor.org/rfc/rfc5869", desc: "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)" },
          { title: "NIST SP 800-38D", url: "https://csrc.nist.gov/pubs/sp/800/38/d/final", desc: "Galois/Counter Mode (GCM) and GMAC" }
        ]
      }
    ]
  },

  "tsarcore-native": {
    id: "tsarcore-native",
    title: "tsarcore_native Crate",
    subtitle: "Rust Engine, PyO3 Bindings & LMDB Storage",
    category: "Tsarchain",
    badge: "Rust Crate",
    toc: [
      { id: "core-modules", label: "1. Core Rust Modules" },
      { id: "unit-tests", label: "2. Unit Tests" },
      { id: "python-usage", label: "3. Python Usage Example" },
      { id: "safety-notes", label: "4. Safety Notes" },
      { id: "changelog", label: "5. Version Changelog" },
    ],
    sections: [
      {
        id: "core-modules",
        title: "1. Core Rust Modules",
        items: [
          { label: "lib.rs", text: "PyO3 bindings, double-SHA256, HASH160, and RandomX VM cache manager." },
          { label: "generate_history_book.rs", text: "Address Grid calculation (P2WPKH & P2WSH) for PDF History Book rendering." },
          { label: "generate_receipt.rs", text: "QR code generation, decimal formatters, and receipt layout drawing." },
          { label: "graff_merkle.rs", text: "Single SHA-256 Merkle tree for chunked archives and Proof of Retention." },
          { label: "mining.rs", text: "Multi-threaded RandomX PoW miner with hashrate progress queues." },
          { label: "networking.rs", text: "SecureChannelNative P2P handshake (X25519 + HKDF + AES-256-GCM)." },
          { label: "storage.rs", text: "NativeStorage LMDB wrapper with drive profiling (HDD/SSD/NVMe)." },
          { label: "txcodec.rs", text: "BIP-143 sighash, varints, and compact transaction serialization." },
          { label: "utxo.rs", text: "High-speed bulk UTXO delta modifications." },
          { label: "validation.rs", text: "Consensus block execution rules, low-S ECDSA, and SigOps limits." }
        ]
      },
      {
        id: "unit-tests",
        title: "2. Unit Tests",
        content: `Run the standalone Rust test suite:
\`\`\`bash
cd tsarcore_native
cargo test
\`\`\``
      },
      {
        id: "python-usage",
        title: "3. Python Usage Example",
        code: `import tsarcore_native as tc

# 1. Sigops Counting
assert tc.count_sigops(b"\\xac") == 1  # OP_CHECKSIG

# 2. Parallel Signature Batch Verification
pairs = [(pk_bytes, msg_digest, sig_der)]
results = tc.secp_verify_der_low_s_many(pairs, enforce_low_s=True, parallel=True)

# 3. RandomX PoW Hashing
header80 = b"\\x00" * 80
seed = b"epoch-0-seed"
rx_hash = tc.randomx_pow_hash(header80, seed, full_mem=False, jit=True)

# 4. Native LMDB Storage
store = tc.open_storage("lmdb", "data/node", map_size_max=64*1024*1024)
store.put_json("utxo", b"txid:0", '{"amount": 50000000}')`
      },
      {
        id: "safety-notes",
        title: "4. Safety Notes",
        content: `- Zero \`unsafe\` blocks in transaction parsers; strict bounds checking on varints.
- \`secp_verify_der_low_s\` strictly enforces BIP-146 Low-S canonical signatures.
- Memory-mapped LMDB pointers eliminate out-of-memory errors on large archival chunks.`
      },
      {
        id: "changelog",
        title: "5. Version Changelog",
        table: {
          headers: ["Version", "Highlights"],
          rows: [
            ["v0.2.4", "Smart Storage LMDB Engine with drive auto-detection (HDD/SSD/NVMe profiling)"],
            ["v0.2.3", "Address Grid data rendering for P2WPKH and P2WSH addresses in History Book"],
            ["v0.2.2", "Zero-copy memory-mapped LMDB Merkle path lookups"],
            ["v0.2.1", "Single SHA-256 Merkle root and inclusion path validation"],
            ["v0.2.0", "Consensus transaction vsize/weight and SigOps limit enforcement in Rust"],
            ["v0.1.9", "Sliding-window AEAD rekeying for P2P links without disconnects"]
          ]
        }
      }
    ]
  }
};
