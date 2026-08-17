export const apiAndRpc = {
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
- \`NEW_BLOCK\`: Propagate a freshly mined block to the network.
- \`GET_HEADERS\` / \`GET_BLOCKS\` / \`GET_BLOCK_HASH\`: Routine sync checks and block batch downloads.

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
};
