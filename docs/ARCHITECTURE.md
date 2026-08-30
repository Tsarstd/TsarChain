# Graffiti Protocol Architecture

<p align="center">
  <img src="/assets/diagrams/transactions_flow.svg" alt="Transactions Flow">
</p>


This document provides an in-depth technical overview of the Graffiti Protocol. The architecture relies on a hybrid design that couples lightweight on-chain UTXO execution with off-chain heavy data storage, prioritizing the permanent archiving of digital art and testimonies.


---


## 🏗️ Project & Data Structure's

- ***Project Folder Map***
  <details>
    <summary>See Preview</summary>

  ```markdown

    TsarChain/
    ├── apps/
    │   │
    │   ├── cli_archivist.py                     # Storage Node (Archivist CLI)
    │   ├── cli_node_miner.py                    # Miner CLI (Full Node)
    │   └── wallet.py                            # Wallet GUI (Kremlin Wallet) 
    │
    ├── assets/                                  # Logo, img, etc.
    ├── benchmarks/                              # tsarcore_native bechmarks test
    ├── docs/                                    # Documentation, Whitepaper & Draft Protocol
    ├── scripts/                                 # Development utility scripts
    ├── src/
    │   │
    │   ├── archivist/
    │   │   ├── cosmetic_archivist/
    │   │   │   ├── interface.py                 # colorama CLI module
    │   │   │   └── tui.py                       # TUI for CLI
    │   │   │
    │   │   ├── archivist_orchestrator.py        # Storage Node CLI/Main logic
    │   │   ├── connect.py                       # P2P network logic ( send & receive )
    │   │   ├── database_archivist.py            # database logic
    │   │   ├── node_route.py                    # Outbound Node RPC client bridge
    │   │   ├── server_archivist.py              # Storage server & local engine module
    │   │   ├── storage_guard.py                 # Ratelimit guard archivist
    │   │   └── wallet_route.py                  # Inbound Wallet RPC route
    │   │
    │   ├── kremlin/                            
    │   │   ├── dialogs/
    │   │   │   └── log_viewer.py                # Log viewer GUI dialog
    │   │   │
    │   │   ├── security/
    │   │   │   ├── chat/
    │   │   │   │     ├── chat_common.py         # Helper & Common chat logic
    │   │   │   │     ├── double_ratchet.py      # Double Rachet Logic
    │   │   │   │     └── triple_xdh.py          # 3XDH Logic
    │   │   │   │
    │   │   │   └── data_security.py             # Wallet security management
    │   │   │
    │   │   ├── services/
    │   │   │   ├── contact_management.py        # Contacts Management
    │   │   │   ├── explorer_providers.py        # Explorer API Providers
    │   │   │   ├── graffiti_service.py          # Post, Upload & Comment graffiti service logic
    │   │   │   ├── media.py                     # VLC media player
    │   │   │   ├── rpc_kremlin.py               # RPC API logic
    │   │   │   ├── send_services.py             # send TX logic
    │   │   │   └── tx_history.py                # History Transactions cached Management
    │   │   │
    │   │   ├── tab_ui/
    │   │   │   ├── explore/
    │   │   │   │   ├── address_search.py        # Address result UI explore
    │   │   │   │   ├── block_search.py          # Block result UI explore
    │   │   │   │   ├── graffiti_search.py       # Graffiti result UI explore
    │   │   │   │   ├── main_tab.py              # Main Tab UI Explore
    │   │   │   │   └── txid_search.py           # Txid result UI explore
    │   │   │   │
    │   │   │   ├── app_sidebar.py               # Sidebar Tab Logic
    │   │   │   ├── chat_tab.py                  # Chat Tab UI Module
    │   │   │   ├── dev_tab.py                   # Dev Tab UI Module
    │   │   │   ├── graffiti_tab.py              # Graffiti Tab UI Module
    │   │   │   ├── history_tab.py               # History Tab UI Module
    │   │   │   ├── lockscreen.py                # Lockscreen Module
    │   │   │   ├── network_tab.py               # Network Info Tab UI Module
    │   │   │   ├── send_tab.py                  # Send Tx Tab UI Module
    │   │   │   └── wallet_tab.py                # Wallet Management Tab UI Module
    │   │   │
    │   │   ├── theme.py                         # Light & Dark Theme Module
    │   │   ├── ui_state.py                      # Busy Manager
    │   │   └── ui_utils.py                      # UI helpers
    │   │ 
    │   ├── tsarchain/
    │   │   ├── consensus/
    │   │   │   ├── blockchain.py                # Blockhain initialize module
    │   │   │   ├── chain_ops.py                 # swap tip, pruning mempool, and add block logic
    │   │   │   ├── chain_storage.py             # Backup & database chain management
    │   │   │   ├── difficulty.py                # Difficulty Consensus Logic
    │   │   │   ├── genesis.py                   # Create genesis & validate genesis logic
    │   │   │   ├── mining.py                    # Mining flow looping logic
    │   │   │   ├── rewards.py                   # Coinbase reward logic
    │   │   │   ├── utxo_validate.py             # UTXO sync and validate
    │   │   │   └── validation.py                # Consensus core validation block & Transactions
    │   │   │
    │   │   ├── contracts/          
    │   │   │   ├── graffiti_registry.py         # Graffiti metadata database
    │   │   │   └── graffiti.py                  # Graffiti core logic
    │   │   │
    │   │   ├── core/               
    │   │   │   ├── block.py                     # Block data structure init
    │   │   │   ├── coinbase.py                  # coinbase logic
    │   │   │   └── tx.py                        # Transaction Logic
    │   │   │
    │   │   ├── mempool/
    │   │   │   ├── orphan.py                    # Orphan check
    │   │   │   ├── policy.py                    # Mempool policy logic
    │   │   │   ├── pool.py                      # Mempool initialize
    │   │   │   ├── scripts.py                   # Script & serialize
    │   │   │   ├── storage.py                   # Mempool Storage Logic
    │   │   │   ├── types.py                     # Normalize prevout set
    │   │   │   └── validation.py                # Mempool core valodation logic
    │   │   │
    │   │   ├── miner/
    │   │   │   ├── cosmetic
    │   │   │   │   ├── interface.py             # colorama CLI module
    │   │   │   │   └── tui.py                   # TUI for CLI
    │   │   │   │
    │   │   │   └── orchestrator.py              # miner/node CLI logic
    │   │   │
    │   │   ├── network/
    │   │   │   ├── cast/
    │   │   │   │   ├── base.py                  # Proxy Handler
    │   │   │   │   ├── chain_utils.py           # validate incoming chain logic
    │   │   │   │   ├── gossip.py                # gossip block
    │   │   │   │   ├── mempool_sync.py          # mempool sync p2p
    │   │   │   │   ├── receive.py               # receive p2p data logic
    │   │   │   │   └── utxo_local.py            # rebuild local UTXO
    │   │   │   │
    │   │   │   ├── node_logic/
    │   │   │   │   ├── chat_state.py            # chat initialize
    │   │   │   │   ├── discovery.py             # discovery peers logic
    │   │   │   │   ├── handlers.py              # handle p2p data logic
    │   │   │   │   ├── peers.py                 # reward and penalty peers
    │   │   │   │   ├── ratelimit.py             # rate limiting logic
    │   │   │   │   ├── rpc_client.py            # peer caching & request management
    │   │   │   │   ├── server_node.py           # starting server logic
    │   │   │   │   ├── storage_registry.py      # registry storage node
    │   │   │   │   └── sync.py                  # sync logic
    │   │   │   │
    │   │   │   ├── rpc/
    │   │   │   │   ├── user_rpc/
    │   │   │   │   |   ├── category/
    |   │   │   │   │   |   ├── chat.py                # All Chat RPC on Wallet
    |   │   │   │   │   |   ├── explorer.py            # Exploring Tsarchain RPC (Block Detail, Tx Details, etc)
    |   │   │   │   │   |   ├── graff_activities.py    # All Graffiti RPC
    |   │   │   │   │   |   ├── networking.py          # Ping, Get peers & Stor List
    |   │   │   │   │   |   └── transactions.py        # All Transactions RPC
    |   │   │   │   │   |
    │   │   │   │   |   ├── common.py                  # common helper
    │   │   │   │   |   └── dispatcher.py              # Handler Map RPC
    │   │   │   │   |
    │   │   │   │   ├── miner_rpc.py                   # miner RPC api gateway
    │   │   │   │   ├── processing_msg.py              # role base & security RPC api
    │   │   │   │   └── storage_rpc.py                 # storage RPC api gateway
    │   │   │   │
    │   │   │   ├── rpc_helper/
    |   │   │   │   ├── base.py                        # Proxy Handler
    |   │   │   │   ├── chat.py                        # Helper for chat rpc
    |   │   │   │   ├── explorer.py                    # Explorer helper 'block,tx details, etc'
    |   │   │   │   ├── guard.py                       # Guar tb_allow rpc
    |   │   │   │   ├── history.py                     # History tx helper rpc
    |   │   │   │   └── tx.py                          # All Transaction model helper (regular, post, comment, payouts)
    |   │   │   │
    │   │   │   ├── broadcast.py                       # Broadcast initialize
    │   │   │   ├── dandelion_pp.py                    # minimal dandelion ++ modul
    │   │   │   ├── node.py                            # Node initialize
    │   │   │   ├── peers_storage.py                   # keys management storage
    │   │   │   ├── pow_token.py                       # POW toke module
    │   │   │   └── protocol.py                        # handshake & p2p transport protocol
    │   │   │
    │   │   ├── storage/
    │   │   │   ├── utxo_logic/
    │   │   │   │   ├── balances.py                    # Balance lookup logic
    │   │   │   │   ├── database.py                    # UTXO database logic
    │   │   │   │   ├── graff_utxo.py                  # graffiti UTXO logic
    │   │   │   │   └── validate.py                    # core validation UTXO logic
    │   │   │   │
    │   │   │   ├── kv.py                              # LMDB database logic
    │   │   │   └── utxo.py                            # UTXO initialize
    │   │   │
    │   │   └── utils/
    │   │       ├── benchmarks.py                      # Benchmark decorator for method functions
    │   │       ├── bootstrap.py                       # auto backup / snapshot logic
    │   │       ├── config.py                          # ALL project Configuration
    │   │       ├── helpers.py                         # script helpers
    │   │       ├── thread_check.py                    # thread monitoring
    │   │       └── tsar_logging.py                    # logging module
    │   │
    │   └── web/
    │       ├── Backend/                               # ALL Backend Website Module
    │       └── Frontend/                              # ALL Frontend Website Module
    │
    ├── tools/                                         # LMDB database tools & Snapshot maintenance
    │
    ├── tsarcore_native/
    │        ├── src/                                  # ALL Native Module (Rust + PyO3)
    │        └── tests/                                # Unit Test For Rust
    │
    └── tests/                                         # All Python Unit testing

  ```
  </details>

#### 1. 💸 Example of a Standard Transaction & Mining Lifecycle (Block Height 6)
The serialized data below demonstrates a standard financial transfer and block consensus lifecycle:
> **Activity Storyline**:
> - **Sender**: `tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr` transfers **1,200 TSAR** (`120,000,000,000` sats) to recipient `tsar1qn76f5d32xe9405hsteujjyyuahrcynh5cxjw23`.
> - **Inputs & Change**: The transaction consumes 3 UTXOs totaling `250,050,000,000,000` sats, producing `120,000,000,000` sats to the recipient and returning `249,929,999,990,616` sats back to the sender as unspent change.
> - **Network Fee**: The difference between inputs and outputs yields a transaction fee of **9,384 sats**.
> - **Miner Execution**: Miner `tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr` solves PoW at **Block Height 6** (Block ID: `Widji_Thukul_1998_ycVSTvaTl`, Nonce: `920`, Difficulty: `5018`) and receives the block subsidy of 250 TSAR + 9,384 sats fee, totaling `"reward": 25000009384`. Notice that Coinbase transactions strictly display `"reward"` and omit the redundant `"fee": 0`, while the block header records `"total_fee": 9384`.

- ***Block Data Structure (Height 6):***
  > Storage Engine: Stored as pure binary blocks (80B Header + 24B Meta + Serialized Witness Txs) indexed by `h:{height:012d}` with a global `__meta__` header.
  <details>
    <summary>See Preview (Block Height 6)</summary>

  ```json
  "h:000000000006": {
    "height": 6,
    "version": 1,
    "prev_block_hash": "000e9e3a6e336735311599ca61cf2bd9223b5acc1ebd6fa8593ccef288664a9c",
    "merkle_root": "715696c865a49556730be207d9b865b6098884e8b376cc0a4a814f03451cc16b",
    "timestamp": 1787992798,
    "difficulty": 5018,
    "chainwork": 19951,
    "bits": 520949608,
    "nonce": 920,
    "hash": "000cca3103f2e51f2d7fc863a0d6a0faaa6cdf59cdef9d5ec504f9da155708de",
    "total_fee": 9384,
    "transactions": [
      {
        "version": 1,
        "inputs": [
          {
            "txid": "0000000000000000000000000000000000000000000000000000000000000000",
            "vout": 4294967295,
            "amount": 0,
            "script_sig": "01061b5769646a695f5468756b756c5f313939385f79635653547661546c",
            "witness": []
          }
        ],
        "outputs": [
          {
            "amount": 25000009384,
            "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
          }
        ],
        "locktime": 0,
        "txid": "fb26388bd2d22e7c7136820bb6ef49b551606155bd3d980600df065616332e8c",
        "is_coinbase": true,
        "type": "Coinbase",
        "to_address": "tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr",
        "reward": 25000009384,
        "block_id": "Widji_Thukul_1998_ycVSTvaTl",
        "height": 6
      },
      {
        "version": 1,
        "inputs": [
          {
            "txid": "3e2a4f4fca0f9f052eda60968cd8132350aaeb6d14bc90f1a5b67be1c4570ec7",
            "vout": 0,
            "amount": 25000000000,
            "script_sig": "",
            "witness": [
              "30450221008c42ce48ad16df48230352d8e4a67280cc264ec1cb0fad4125f22e3b3a91c4f2022052332a1648fe668ff6b79a35d15312f87d04690f02ae48e99d54bbbe02860d9501",
              "0338e4581fec6cee44675bae99ff4eabe31d1ef412e54bb16f96ee97d796515e58"
            ]
          },
          {
            "txid": "56b8535a7e5d448bd2e9281a5252721940a28fa7061d1ff7eebad77762a92bc5",
            "vout": 0,
            "amount": 25000000000,
            "script_sig": "",
            "witness": [
              "3045022100ef2658fd25953a828c083962f46bba753358d185680bbd146131ccd962b3eba3022060df0b75072d36c1551c20cd0a5daf0946bc20cda7fb338fdbb2c97b8c75a6ba01",
              "0338e4581fec6cee44675bae99ff4eabe31d1ef412e54bb16f96ee97d796515e58"
            ]
          },
          {
            "txid": "48a8a5daaaddad645dc4ec8557740101410c82b49abd37f530a71720642ff75d",
            "vout": 0,
            "amount": 250000000000000,
            "script_sig": "",
            "witness": [
              "3045022100ffa18ed9ecf89f84afe2f51c8184ec63a0ae19817679924126abb443517dd24a02200df23da22c3b3fe6a066100af77fee221ef47ebb46974d98180b207c6325d34b01",
              "0338e4581fec6cee44675bae99ff4eabe31d1ef412e54bb16f96ee97d796515e58"
            ]
          }
        ],
        "outputs": [
          {
            "amount": 120000000000,
            "script_pubkey": "00149fb49a362a364b57d2f05e7929109cedc7824ef4"
          },
          {
            "amount": 249929999990616,
            "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
          }
        ],
        "locktime": 0,
        "txid": "48fcebb8ea89b09d2db51ec842867a17f9b9194a363f3d7d7ee0dfd15b39a5b6",
        "fee": 9384,
        "is_coinbase": false
      }
    ]
  }
  ```
  </details>

- ***UTXO Data Structure :***
  > Storage Engine: Compact binary struct `<Q?qH` (19 bytes: amount, is_coinbase, block_height, spk_len) + raw `script_pubkey` bytes keyed by `txid:vout`.
  <details>
    <summary>See Preview (UTXO State)</summary>

  ```json
  {
    "__meta__": {
      "schema_version": 1,
      "generated_at": 1787997234,
      "backend": "lmdb",
      "utxo_set_size": 16,
      "tip_height_hint": 16
    },
    "cea7d1c2149cb009f9ea9671bdb87346a2136701e8c7639d67ea1f71b1e1ab27:1": {
      "amount": 114959994186,
      "is_coinbase": false,
      "block_height": 8,
      "script_pubkey": "00149fb49a362a364b57d2f05e7929109cedc7824ef4",
      "address": "tsar1qn76f5d32xe9405hsteujjyyuahrcynh5cxjw23"
    },
    "5d4bca9582e09e2bc91613cdc20372f5c6344f167ebdef9188d21514169a93e0:0": {
      "amount": 25000009384,
      "is_coinbase": true,
      "block_height": 10,
      "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a",
      "address": "tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr"
    },
    "fbd48a867f3d832c9ea8141f12ae6e34ea22dac7b82ac9d646db220e9102b4f0:0": {
      "amount": 280000000,
      "is_coinbase": false,
      "block_height": 11,
      "script_pubkey": "00149fb49a362a364b57d2f05e7929109cedc7824ef4",
      "address": "tsar1qn76f5d32xe9405hsteujjyyuahrcynh5cxjw23"
    }
  }
  ```
  </details>

- ***MemPool Data Structure:***
  > Storage Engine: Compact binary header `<dIII` (received_at, fee, vsize, weight) + serialized witness `Tx` bytes keyed by `txid`.
  <details>
    <summary>See Preview</summary>

  ```json
  {
    "7636d98618633c95ac5891405f4ec34b8b4b1973c1d944c447744422f0136cc3": {
      "version": 1,
      "inputs": [
        {
          "txid": "fbd48a867f3d832c9ea8141f12ae6e34ea22dac7b82ac9d646db220e9102b4f0",
          "vout": 0,
          "amount": 280000000,
          "script_sig": "",
          "witness": [
            "30440220236e0f38f30423f096e0e27fdd9809922a4e520b14403d7e847fe96160b726bb022040d9a45a391e2c592204bbd0b8df2ce007653306e4f0fccb8e3456b04b109b9d01",
            "020f4c2347cb74eee085bae4d7579305ca58beeb1a2797493e371efb78e7e7d558"
          ]
        }
      ],
      "outputs": [
        {
          "amount": 21000000000,
          "script_pubkey": "0014e1171c06610cfbf85af0cfe1e53060e436585ddf"
        },
        {
          "amount": 33279992928,
          "script_pubkey": "00149fb49a362a364b57d2f05e7929109cedc7824ef4"
        }
      ],
      "locktime": 0,
      "txid": "7636d98618633c95ac5891405f4ec34b8b4b1973c1d944c447744422f0136cc3",
      "fee": 7072,
      "is_coinbase": false,
      "_meta": {
        "received_at": 1787997212.4835243,
        "fee": 7072,
        "vbytes": 389,
        "weight": 1556
      }
    }
  }
  ```
  </details>

---

#### 2. 🎨 Example of Graffiti Lifecycle Activities (Upload, Comment & Storage Payout)
The examples below illustrate the 3 progressive stages of the Graffiti Protocol lifecycle across **Block Height 8**, **Block Height 11**, and **Block Height 14**:

##### A. Graffiti POST: Media Upload & Escrow Staking (Block Height 8)
> **Activity Storyline**:
> - **Creator**: `tsar1qn76f5d32xe9405hsteujjyyuahrcynh5cxjw23` uploads a 65.08 MB video MP4 (`65,087,599` bytes) with Merkle root `d9e827b5...` split into 636 chunks.
> - **Escrow Staking**: Staking **50.4 TSAR** (`5,040,000,000` sats) locked to storage escrow pool `tsar1qe8refmphnysxyp67elcfzfke4jhn338nyssnctka2m48rfzvvpsswgq0cf`, assigning Archivist node `tsar1qzxzzf5az5guk43mf0z4d94uugat4jcejwglp07` as the designated data storer.
> - **Consensus**: Confirmed in **Block Height 8** with tx fee `5,814` sats (`total_fee: 15198`).

- ***Block Data Structure (Graffiti POST - Height 8):***
  <details>
    <summary>See Preview (Block Height 8)</summary>

  ```json
  "h:000000000008": {
    "height": 8,
    "version": 1,
    "prev_block_hash": "000a2567301ebfb7cd1b2436d948807c7692a1e7d6b2251ce2f802af80f0dd1b",
    "merkle_root": "39db418529d961827c1025f7581f2a227e14d1d1e5faa763ca8a32c1c4a56072",
    "timestamp": 1787992854,
    "difficulty": 6375,
    "chainwork": 31342,
    "bits": 520767416,
    "nonce": 6824,
    "hash": "0005a227d9a253b9cc640829e38b0e85108572fdfb2fcadf58b4e0f4f5724103",
    "total_fee": 15198,
    "transactions": [
      {
        "version": 1,
        "inputs": [
          {
            "txid": "0000000000000000000000000000000000000000000000000000000000000000",
            "vout": 4294967295,
            "amount": 0,
            "script_sig": "01084067726166383635376262633264383562633833363066333165323532613135336261666632393039633536363161643131333834636166656639306433633366",
            "witness": []
          }
        ],
        "outputs": [
          {
            "amount": 25000015198,
            "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
          }
        ],
        "locktime": 0,
        "txid": "6da8cc5d21132597e3b0dfc07fc4b172931e0ec0c1cf1f15e124729702e612b2",
        "is_coinbase": true,
        "type": "Coinbase",
        "to_address": "tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr",
        "reward": 25000015198,
        "block_id": "graf8657bbc2d85bc8360f31e252a153baff2909c5661ad11384cafef90d3c3f",
        "height": 8
      },
      {
        "version": 1,
        "inputs": [
          {
            "txid": "48fcebb8ea89b09d2db51ec842867a17f9b9194a363f3d7d7ee0dfd15b39a5b6",
            "vout": 0,
            "amount": 120000000000,
            "script_sig": "",
            "witness": [
              "3044022009dfe6d27bb25a51725d0edc78966f376d8a8bd4561c015a66a10eb2d177c4c102200f3369206106b80d630e58b887ed28884292d7633328a7ad1ded4ebec8fb045901",
              "020f4c2347cb74eee085bae4d7579305ca58beeb1a2797493e371efb78e7e7d558"
            ]
          }
        ],
        "outputs": [
          {
            "amount": 5040000000,
            "script_pubkey": "0020c9c794ec37992062075ecff09126d9acaf38c4f324213c2edd56ea71a44c6061"
          },
          {
            "amount": 114959994186,
            "script_pubkey": "00149fb49a362a364b57d2f05e7929109cedc7824ef4"
          },
          {
            "amount": 0,
            "script_pubkey": "6a4d1c02545341525f47524146317c7b22736861323536223a2237303961353862316161393736313663633566353366303966643363643563666131356435626637623538616665633561363237393533653434353132313861222c226172745f6964223a2267726166383635376262633264383562633833363066333165323532613135336261666632393039633536363161643131333834636166656639306433633366222c2273697a65223a36353038373539392c226d696d65223a22766964656f2f6d7034222c2273746f726572223a227473617231717a787a7a6635617a3567756b34336d66307a346439347575676174346a63656a77676c703037222c2272656365697074223a22726370745f373039613538623161613937363136636335663533663039666433636435636661313564356266376235386166656335613632373935336534343531323138615f31373837393932383334222c226576656e74223a22504f5354222c2263726561746f72223a227473617231716e3736663564333278653934303568737465756a6a79797561687263796e683563786a773233222c226d726f6f74223a2264396538323762353338363365373937333566396261383365346164646363343833643561653765396430623365643730663263653562616338333432306536222c226d6368756e6b223a3130323430302c226d636f756e74223a3633362c227473223a313738373939323833377d"
          }
        ],
        "locktime": 0,
        "txid": "cea7d1c2149cb009f9ea9671bdb87346a2136701e8c7639d67ea1f71b1e1ab27",
        "fee": 5814,
        "is_coinbase": false
      }
    ]
  }
  ```
  </details>

- ***Graffiti Post Registry:***
  <details>
    <summary>See Preview</summary>

  ```json
  {
    "graf8657bbc2d85bc8360f31e252a153baff2909c5661ad11384cafef90d3c3f": {
      "sha256": "709a58b1aa97616cc5f53f09fd3cd5cfa15d5bf7b58afec5a627953e4451218a",
      "size": 65087599,
      "mime": "video/mp4",
      "storer": "tsar1qzxzzf5az5guk43mf0z4d94uugat4jcejwglp07",
      "receipt": "rcpt_709a58b1aa97616cc5f53f09fd3cd5cfa15d5bf7b58afec5a627953e4451218a_1787992834",
      "creator": "tsar1qn76f5d32xe9405hsteujjyyuahrcynh5cxjw23",
      "block_hash": "0005a227d9a253b9cc640829e38b0e85108572fdfb2fcadf58b4e0f4f5724103",
      "mroot": "d9e827b53863e79735f9ba83e4addcc483d5ae7e9d0b3ed70f2ce5bac83420e6",
      "mchunk": 102400,
      "mcount": 636,
      "art_id": "graf8657bbc2d85bc8360f31e252a153baff2909c5661ad11384cafef90d3c3f",
      "txid": "cea7d1c2149cb009f9ea9671bdb87346a2136701e8c7639d67ea1f71b1e1ab27",
      "block_height": 8,
      "pool_address": "tsar1qe8refmphnysxyp67elcfzfke4jhn338nyssnctka2m48rfzvvpsswgq0cf",
      "amount_paid": 5040000000,
      "stats": {
        "pool_balance": 0,
        "creator_paid": 280000000,
        "storage_paid": 10000000,
        "comments": 1,
        "last_paid_epoch": 0
      }
    }
  }
  ```
  </details>

- ***Archivist Storage Indexer:***
  <details>
    <summary>See Preview</summary>

  ```json
  {
    "art:graf8657bbc2d85bc8360f31e252a153baff2909c5661ad11384cafef90d3c3f": "709a58b1aa97616cc5f53f09fd3cd5cfa15d5bf7b58afec5a627953e4451218a_1787992834",
    "file:709a58b1aa97616cc5f53f09fd3cd5cfa15d5bf7b58afec5a627953e4451218a_1787992834": {
      "size_bytes": 65087599,
      "sha256": "709a58b1aa97616cc5f53f09fd3cd5cfa15d5bf7b58afec5a627953e4451218a",
      "filename": "testing.mp4",
      "mime": "video/mp4",
      "paid": true,
      "expire_at_height": 0,
      "confirmed_at_height": 8,
      "state": "stored",
      "path": "data/archivist/storage/blobs/709a58b1aa97616cc5f53f09fd3cd5cfa15d5bf7b58afec5a627953e4451218a_1787992834.bin",
      "received_bytes": 65087599,
      "chunk_size": 10485760,
      "created_ts": 1787992834,
      "mroot": "d9e827b53863e79735f9ba83e4addcc483d5ae7e9d0b3ed70f2ce5bac83420e6",
      "mchunk": 102400,
      "mcount": 636,
      "art_id": "graf8657bbc2d85bc8360f31e252a153baff2909c5661ad11384cafef90d3c3f",
      "updated_ts": 1787992837,
      "receipt_id": "rcpt_709a58b1aa97616cc5f53f09fd3cd5cfa15d5bf7b58afec5a627953e4451218a_1787992834",
      "txid_paid": "cea7d1c2149cb009f9ea9671bdb87346a2136701e8c7639d67ea1f71b1e1ab27",
      "last_proof_epoch": 1,
      "last_proof_ts": 1787993199,
      "last_proof_offset": 33689600,
      "last_proof_length": 102400,
      "last_proof_hash": "8e30b47146bb18498c8535afc8e3ba4e6142190ca0605bf1679e9954c000df32",
      "last_proof_height": 15,
      "missed_proofs": 0,
      "proof_fail_reason": "",
      "proof_status": "ok"
    }
  }
  ```
  </details>

---

##### B. Graffiti COMMENT: Social Appreciation & Revenue Split (Block Height 11)
> **Activity Storyline**:
> - **Commenter**: `tsar1quyt3cpnppnalskhsels72vrqusm9shwl229mwq` posts comment `"wkwkwkwkw masoook"` on artwork `graf8657bbc...`.
> - **Payment Split**: Pays 1 TSAR comment fee + 2 TSAR creator tip (total 3 TSAR). The on-chain consensus splits this deterministically:
>   1. **2.8 TSAR** (`280,000,000` sats) sent directly to Creator `tsar1qn76f5d32xe9405hsteujjyyuahrcynh5cxjw23`.
>   2. **0.1 TSAR** (`10,000,000` sats) sent to Storage Pool `tsar1qe8refmphnysxyp67elcfzfke4jhn338nyssnctka2m48rfzvvpsswgq0cf`.
>   3. Change returned to the commenter.
> - **Consensus**: Confirmed in **Block Height 11** with tx fee `6,868` sats (`total_fee: 6868`).

- ***Block Data Structure (Graffiti COMMENT - Height 11):***
  <details>
    <summary>See Preview (Block Height 11)</summary>

  ```json
  "h:000000000011": {
    "height": 11,
    "version": 1,
    "prev_block_hash": "000ab3dd0e3647b13fb240dbb7fb191617253c1150073441c6b0d32647c2c6ae",
    "merkle_root": "deb8e616636feb55f42192b21b0af6d555a43e2e12d3967213a5e236f8ed0f5c",
    "timestamp": 1787992953,
    "difficulty": 4750,
    "chainwork": 46605,
    "bits": 520997899,
    "nonce": 2996,
    "hash": "00048c8ea8e7d0a6bcc6b6329f2c3cc70db2b229bb2630f589f8fbdaddf40b1d",
    "total_fee": 6868,
    "transactions": [
      {
        "version": 1,
        "inputs": [
          {
            "txid": "0000000000000000000000000000000000000000000000000000000000000000",
            "vout": 4294967295,
            "amount": 0,
            "script_sig": "010b205368697265656e5f4162755f416b6c65685f323032325f3041394d4568313034",
            "witness": []
          }
        ],
        "outputs": [
          {
            "amount": 25000006868,
            "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
          }
        ],
        "locktime": 0,
        "txid": "e841b36aea957934923b47c3c5e82eb06c4367c6f55918c2890c0040004d1a6e",
        "is_coinbase": true,
        "type": "Coinbase",
        "to_address": "tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr",
        "reward": 25000006868,
        "block_id": "Shireen_Abu_Akleh_2022_0A9MEh104",
        "height": 11
      },
      {
        "version": 1,
        "inputs": [
          {
            "txid": "54d9b7d4a7feae09bdfea5956f0407a4374e545f08eeb432ea44d752db69ab3a",
            "vout": 0,
            "amount": 160000000000,
            "script_sig": "",
            "witness": [
              "304402202d3929df98f083ace00314c82702667ccc197a4aee1b0b7c7430d0b3aeed294b0220268c35cfc710c43c6e7193450ebc868d12cd285a017206e2adf66208a861f2d301",
              "022986cb2d336e016d249ab09eb637aa2e3e1e2d567f1fbc97308a750949a57fda"
            ]
          }
        ],
        "outputs": [
          {
            "amount": 280000000,
            "script_pubkey": "00149fb49a362a364b57d2f05e7929109cedc7824ef4"
          },
          {
            "amount": 10000000,
            "script_pubkey": "0020c9c794ec37992062075ecff09126d9acaf38c4f324213c2edd56ea71a44c6061"
          },
          {
            "amount": 159709993132,
            "script_pubkey": "0014e1171c06610cfbf85af0cfe1e53060e436585ddf"
          },
          {
            "amount": 0,
            "script_pubkey": "6a4d4001545341525f47524146317c7b226576656e74223a22434f4d4d454e54222c226172745f6964223a2267726166383635376262633264383562633833363066333165323532613135336261666632393039633536363161643131333834636166656639306433633366222c22636f6d6d656e74223a2237373662373736623737366237373662373732303664363137333666366636663662222c22616d6f756e74223a3130303030303030302c22746970223a3230303030303030302c2263726561746f72223a227473617231716e3736663564333278653934303568737465756a6a79797561687263796e683563786a773233222c22636f6d6d656e746572223a227473617231717579743363706e70706e616c736b6873656c73373276727175736d397368776c3232396d7771222c227473223a313738373939323933387d"
          }
        ],
        "locktime": 0,
        "txid": "fbd48a867f3d832c9ea8141f12ae6e34ea22dac7b82ac9d646db220e9102b4f0",
        "fee": 6868,
        "is_coinbase": false
      }
    ]
  }
  ```
  </details>

- ***Graffiti Comment Registry:***
  <details>
    <summary>See Preview</summary>

  ```json
  {
    "graf8657bbc2d85bc8360f31e252a153baff2909c5661ad11384cafef90d3c3f": [
      {
        "txid": "fbd48a867f3d832c9ea8141f12ae6e34ea22dac7b82ac9d646db220e9102b4f0",
        "block_height": 11,
        "comment": "776b776b776b776b77206d61736f6f6f6b",
        "commenter": "tsar1quyt3cpnppnalskhsels72vrqusm9shwl229mwq",
        "amount": 100000000,
        "tip": 200000000,
        "creator_paid": 280000000,
        "storage_paid": 10000000,
        "ts": 1787992938
      }
    ]
  }
  ```
  </details>

---

##### C. Proof-of-Retention & Storage Payout: Archivist Reward (Block Height 14)
> **Activity Storyline**:
> - **Proof-of-Retention**: Archivist node `tsar1qzxzzf5az5guk43mf0z4d94uugat4jcejwglp07` fulfills Proof-of-Retention challenges verifying 100 KB chunks across epochs.
> - **Escrow Release**: The network consensus triggers an automatic payout transaction spending from escrow pool address `tsar1qe8refmphnysxyp67elcfzfke4jhn338nyssnctka2m48rfzvvpsswgq0cf`.
> - **Reward Disbursement**: Archivist receives **50.49976982 TSAR** (`5,049,976,982` sats) for successfully retaining and serving the digital file.
> - **Consensus**: Confirmed in **Block Height 14** with tx fee `23,018` sats (`total_fee: 23018`).

- ***Block Data Structure (Graffiti PAYOUT - Height 14):***
  <details>
    <summary>See Preview (Block Height 14)</summary>

  ```json
  "h:000000000014": {
    "height": 14,
    "version": 1,
    "prev_block_hash": "00014d7762ddde6fa86049064614b7114b799fefa9cdf987f4fbde504a8687cd",
    "merkle_root": "7f9c6087967512d67b8e6486f3a5d71f44f36c4e8e4ae8b8e980c33f0b84daab",
    "timestamp": 1787993086,
    "difficulty": 4521,
    "chainwork": 62176,
    "bits": 521043699,
    "nonce": 5748,
    "hash": "000cfff77aef211e61582a9ff9561df90ba655e3bc2a695f5d7ed93d982591c0",
    "total_fee": 23018,
    "transactions": [
      {
        "version": 1,
        "inputs": [
          {
            "txid": "0000000000000000000000000000000000000000000000000000000000000000",
            "vout": 4294967295,
            "amount": 0,
            "script_sig": "010e1841695f5765697765695f323031315f6e3763745677576d51",
            "witness": []
          }
        ],
        "outputs": [
          {
            "amount": 25000023018,
            "script_pubkey": "0014ed93adff3a7ebbb9f8dcdb055b689cd604fd981a"
          }
        ],
        "locktime": 0,
        "txid": "ac571f2fc5c18a804d94d89a4c6a5fbe240e0e27218bd078eacf34a15de9cffe",
        "is_coinbase": true,
        "type": "Coinbase",
        "to_address": "tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr",
        "reward": 25000023018,
        "block_id": "Ai_Weiwei_2011_n7ctVwWmQ",
        "height": 14
      },
      {
        "version": 1,
        "inputs": [
          {
            "txid": "cea7d1c2149cb009f9ea9671bdb87346a2136701e8c7639d67ea1f71b1e1ab27",
            "vout": 0,
            "amount": 5040000000,
            "script_sig": "",
            "witness": [
              "8657bbc2d85bc8360f31e252a153baff2909c5661ad11384cafef90d3c3f",
              "1e8657bbc2d85bc8360f31e252a153baff2909c5661ad11384cafef90d3c3f87"
            ]
          },
          {
            "txid": "fbd48a867f3d832c9ea8141f12ae6e34ea22dac7b82ac9d646db220e9102b4f0",
            "vout": 1,
            "amount": 10000000,
            "script_sig": "",
            "witness": [
              "8657bbc2d85bc8360f31e252a153baff2909c5661ad11384cafef90d3c3f",
              "1e8657bbc2d85bc8360f31e252a153baff2909c5661ad11384cafef90d3c3f87"
            ]
          }
        ],
        "outputs": [
          {
            "amount": 5049976982,
            "script_pubkey": "0014118424d3a2a2396ac76978aad2d79c4757596332"
          },
          {
            "amount": 0,
            "script_pubkey": "6a4dfa01545341525f47524146317c7b226576656e74223a225041594f5554222c226172745f6964223a2267726166383635376262633264383562633833363066333165323532613135336261666632393039633536363161643131333834636166656639306433633366222c2265706f6368223a302c22726563697069656e7473223a5b7b2261646472223a227473617231717a787a7a6635617a3567756b34336d66307a346439347575676174346a63656a77676c703037222c22616d6f756e74223a353034393937363938327d5d2c2270726f6f665f6f6666736574223a323335353230302c2270726f6f665f6c656e677468223a3130323430302c2270726f6f665f68617368223a2262356266363666393435343764306466396463333661636463613535343733326632306335366534343538313832653839633034623961366261306261323962222c2270726f6f665f73656564223a2232646365653164616166623661313062626366376166383765646233333939653637353333383961366130393762633632303533353234653732346664636432222c2270726f6f665f686569676874223a382c2270726f6f665f65706f6368223a302c2270726f6f665f73746f726572223a227473617231717a787a7a6635617a3567756b34336d66307a346439347575676174346a63656a77676c703037227d"
          }
        ],
        "locktime": 0,
        "txid": "0575fbbeeb4042654fb0d4b9830c999900dc8adc19a1405d59cffc0a1066a7fd",
        "fee": 23018,
        "is_coinbase": false
      }
    ]
  }
  ```
  </details>

- ***Graffiti Proof-of-Retention Log:***
  <details>
    <summary>See Preview</summary>

  ```json
  {
    "graf8657bbc2d85bc8360f31e252a153baff2909c5661ad11384cafef90d3c3f": [
      {
        "storer": "tsar1qzxzzf5az5guk43mf0z4d94uugat4jcejwglp07",
        "epoch": 0,
        "offset": 2355200,
        "length": 102400,
        "hash": "b5bf66f94547d0df9dc36acdca554732f20c56e4458182e89c04b9a6ba0ba29b",
        "height": 8,
        "seed": "2dcee1daafb6a10bbcf7af87edb3399e6753389a6a097bc62053524e724fdcd2",
        "ts": 1787993125
      }
    ]
  }
  ```
  </details>

- ***Graffiti Payout History:***
  <details>
    <summary>See Preview</summary>

  ```json
  {
    "graf8657bbc2d85bc8360f31e252a153baff2909c5661ad11384cafef90d3c3f": [
      {
        "txid": "0575fbbeeb4042654fb0d4b9830c999900dc8adc19a1405d59cffc0a1066a7fd",
        "block_height": 14,
        "recipients": {
          "tsar1qzxzzf5az5guk43mf0z4d94uugat4jcejwglp07": 5049976982
        },
        "amount": 5049976982,
        "epoch": 0
      }
    ]
  }
  ```
  </details>

---

#### 3. 🌐 Example of Network State Data Structure
State is the database for overall network consensus statistics, supply emissions, and snapshot metrics.
- ***State Data Structure:***
  > Storage Engine: Stored as structured snapshot under key `k:snapshot` alongside atomic keys `k:total_blocks` and `k:total_supply`.
  <details>
    <summary>See Preview</summary>

  ```json
  {
    "k:snapshot": {
      "schema_version": 1,
      "last_updated": "2026-08-29T16:53:54.568866+07:00",
      "total_blocks": 17,
      "total_supply": 250400000000000,
      "identity": {
        "network_id": "gulag-net",
        "address_prefix": "tsar",
        "network_magic_hex": "54534152434841494e",
        "pow_algo": "randomx"
      },
      "chain": {
        "total_blocks": 17,
        "tip_height": 16,
        "genesis_hash": "0008e6acb33e675bcc3d51865376686ab936df1f5d9af9f1f4f97bf53d7c35e7",
        "genesis_message": "Every person who is born free has the same rights and dignity. (Munir Said Thalib - 2004-09-07)",
        "tip_hash": "00095ffbbd2f2a668194befded1adc1fd2397a801fe21892bb450940e6bd7df1",
        "tip_timestamp": 1787993179,
        "tip_bits": 521007324,
        "tip_target_hex": "0xdf0dc00000000000000000000000000000000000000000000000000000000",
        "tip_difficulty": 4701,
        "tip_chainwork": 71549,
        "median_time_past": 1787992953,
        "max_bits": 530579455,
        "target_block_time_sec": 37,
        "total_block_size_bytes": 11640,
        "avg_block_time_sec_window": 34.625,
        "est_network_hashrate_hps_window": 135
      },
      "supply": {
        "max_supply": 25250000000000000,
        "emitted_subsidy": 250400000000000,
        "circulating_estimate": 250349999978920,
        "immature_coinbase": 50000021080,
        "utxo_total_value": 250400000000000,
        "coinbase_maturity": 3,
        "current_block_subsidy": 25000000000,
        "current_epoch": 0,
        "next_halving_height": 235000,
        "blocks_to_halving": 234983
      },
      "transactions": {
        "total_txs": 26,
        "total_non_coinbase_txs": 9,
        "total_fees_paid": 100130,
        "mempool_txs": 2,
        "mempool_vbytes_estimate": 1250,
        "mempool_bytes_estimate": 1250,
        "mempool_max_bytes": 2097152
      },
      "utxo": {
        "utxo_set_size": 16
      },
      "graffiti": {
        "posts": 2,
        "comments": 1,
        "graffiti_on_mempool": 0,
        "payouts": 2,
        "pool_balances": 0,
        "total_graffiti_storage": 70868531
      },
      "miners_snapshot": {
        "top_miners": [
          [
            "tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr",
            17
          ]
        ]
      }
    },
    "k:total_blocks": 17,
    "k:total_supply": 250400000000000
  }
  ```
  </details>

> ℹ️ All data structures above represent the streaming and fixed LMDB storage models in the monorepo.
The Storage model in this project is `.mdb` LMDB.


---


## Consensus & Proof-of-Work (PoW) Logic

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

## UTXO Ledger State & Mempool

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

## Rust Native Extension (`tsarcore_native`)

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

- **`NativeStorage` (`src/tsarcore_native/storage.rs`)**: Direct C/Rust binding to the **LMDB** engine.
- **`utxo_build_ops_compact` (`src/tsarcore_native/utxo.rs`)**: Optimizes state transitions. Python sends transaction lists as compressed tuples (`_build_compact_block_txs`), and Rust applies the inputs/outputs delta instantly in memory and commits it to the LMDB database.

### 5. Proof of Retention Merkle Engine (`src/tsarcore_native/graff_merkle.rs`)
Archivists must cryptographically prove they hold large files. Rust accelerates this verification process:
- **`graff_merkle_root_for_file`**: Computes the Merkle root of files directly off the disk at native I/O speeds.
- **`graff_merkle_path_for_file`**: Extracts the exact Merkle path for a specified chunk index.
- **`graff_merkle_verify`**: Instantly validates a Proof of Retention challenge, ensuring nodes cannot easily fake possession of archived files.

---

## Graffiti Protocol Logic

The core logic of the Graffiti Protocol governs the creation, validation, storage pool distributions, and retention auditing of all cultural archives in the system.

### 1. Metadata Registry (`src/tsarchain/contracts/graffiti_registry.py`)
The `GraffitiRegistry` tracks state records for posts, comments, payouts, and proofs.
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



