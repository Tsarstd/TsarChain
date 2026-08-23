export const graffitiprotocolEn = {
  download: {
    label: "Graffiti Protocol - Draft v0.1 (EN)",
    url: "https://drive.google.com/file/d/1Xv_tr2Y0eKso62d6LPeVHBi1v8K_DF_N/view?usp=drive_link",
    filename: "Graffiti Protocol - Draft v0.1 (EN).pdf"
  },
  title: "Graffiti Protocol",
  subtitle: "Draft Protocol Specification v0.1",
  tagline: "No corps, No middlemen, No buzzers — share your art and let your voice be remembered",
  author: "Tsar Studio - November 14, 2025",
  contact: "tsar.studiodesign@gmail.com",
  toc: [
    { id: "manifesto", label: "Manifesto" },
    { id: "core-ideas", label: "1. Core Ideas" },
    { id: "roles-responsibilities", label: "2. Roles & Responsibilities" },
    { id: "economic-flows", label: "3. Economic Flows" },
    { id: "data-model", label: "4. Data Model & Identifiers" },
    { id: "storage-layer", label: "5. Storage Layer (Permanent)" },
    { id: "wire-format", label: "6. Wire Format (On-Chain Hints)" },
    { id: "settlement-payout", label: "7. Settlement & Payout" },
    { id: "limits-abuse-privacy", label: "8. Limits, Abuse, and Privacy" },
    { id: "worked-example", label: "9. Worked Example" },
    { id: "protocol-parameters", label: "10. Protocol Parameters" },
    { id: "security-threats", label: "11. Security Model & Anti-Buzzer Posture" },
    { id: "notes", label: "12. Notes & Development Status" },
  ],
  sections: [
    {
      id: "manifesto",
      title: "Manifesto",
      content: `GRAFFITI is a protocol for loud art and louder truth. Not an NFT, not a stock, not a brand collab. Each work is a digital monument — permanently archived by TsarChain Storage Nodes and anchored to a block.

Public comments are permanent too: once broadcast, they cannot be edited or silently removed at the protocol level. Instead of chasing viral views, GRAFFITI focuses on **"durability, traceability, and fair rewards for creators"**.

There is no central moderator with a "ban" button. If someone wants to speak here, they contribute to the cost of storage — and the artist earns a share.

GRAFFITI is a **"pro digital sovereignty archival layer"** within the broader TsarChain ecosystem: a way for communities to preserve culture and conversation over time, while each node operator and user remains responsible for complying with the laws in their own jurisdiction.`
    },
    {
      id: "core-ideas",
      title: "1. Core Ideas",
      features: [
        {
          title: "Not an NFT",
          desc: "No transferable ownership. GRAFFITI is an archive of art & voice, not a speculation vehicle."
        },
        {
          title: "Block Anchor",
          desc: "A work's identity binds its content hash with the block hash in which the upload TX is included."
        },
        {
          title: "Permanence",
          desc: "Files are replicated by Storage Nodes; on-chain commitments reference what must exist off-chain."
        },
        {
          title: "Immutable Comments",
          desc: "Each comment is a paid on-chain event; comment text is stored on-chain within safe byte limits."
        },
        {
          title: "Automatic Royalty",
          desc: "80% of every comment fee goes to the creator, 10% to the Storage Pool, and ~10% to miners as fee."
        },
        {
          title: "Moderatorless",
          desc: "The protocol is neutral. Local enforcement (if any) is a node operator choice."
        }
      ]
    },
    {
      id: "roles-responsibilities",
      title: "2. Roles & Responsibilities",
      items: [
        { label: "Creator (Artist)", text: "Uploads art, pays an upload fee, receives 80% royalty from every paid comment." },
        { label: "Citizen (Commenter)", text: "Pays to append a permanent comment to the work; can add an optional direct tip." },
        { label: "Miner", text: "Validates and mines blocks; collects ~10% of each comment as transaction fee." },
        { label: "Storage Node (Archivist)", text: "Permanently stores replicated copies (R). Earns 10% from comments plus a share of the upload endowment via Proof of Retention." },
        { label: "Indexer / Explorer", text: "Indexes GRAFFITI events and renders artworks, metadata, and comment threads." }
      ]
    },
    {
      id: "economic-flows",
      title: "3. Economic Flows",
      content: `The protocol enforces mathematically hardcoded revenue distributions without intermediaries:

- **3.1 Upload Fee**: Creator pays based on file size: \`UPLOAD_FEE\` with \`MIN_BILLABLE_SIZE\` (100KB). 100% of this fee goes directly to the work's Storage Pool endowment to fund long-term retention.
- **3.2 Comment Fee**: Each comment includes \`comment_amount\` (≥ \`COMMENT_FEE_MIN\`).
  - **80%** → Creator address (royalty).
  - **10%** → Work's Storage Pool (micropayment for replicas).
  - **~10%** → Miners as transaction fee (achieved by making total outputs = 90% of inputs).
- **3.3 Tips**: Optional \`tip_amount\` goes 100% directly to the creator address.`
    },
    {
      id: "data-model",
      title: "4. Data Model & Identifiers",
      content: `Art Object Identifiers:


- File hash: \`Hc = SHA256(file_blob)\`
- Anchor block: \`Hb = block_hash where upload TX is confirmed\`
- Creator: \`addr_c\` (P2WPKH)
- Art ID: \`art_id = SHA256("GRAFFITI" || Hc || Hb || addr_c)\`

Comment Object:


- Max length: \`COMMENT_MAX_BYTES\` (280 Bytes)
- Comment ID: \`comment_id = SHA256(art_id || txid || vout_index)\`
- Stored on-chain via compact data carrier field ( \`OP_RETURN\` payload ).`
    },
    {
      id: "storage-layer",
      title: "5. Storage Layer (Permanent)",
      content: `- **Replication factor R**: Default 5 replicas using consistent hashing on a node ring keyed by \`art_id\`.
- **Storage Pool Address**: Deterministic P2WSH script hash address per art: \`pool_addr = GRF_POOL(art_id)\`.
- **Proof of Retention (PoR)**: Every \`EPOCH_BLOCKS\`, each storing node proves possession via random byte-range challenges. The active epoch balance in \`pool_addr\` is split among successful provers.
- **Endowment**: If no new comments arrive, the initial upload fee acts as a perpetual base endowment for periodic payouts.`
    },
    {
      id: "wire-format",
      title: "6. Wire Format (On-Chain Hints)",
      code: `GRF_MAGIC = 0x47524631 ("GRF1")
Events: POST, COMMENT, PAYOUT

// POST payload:
{ magic: GRF_MAGIC, event: "POST", Hc, size_kb, mime, addr_c, R_hint, meta_short }
Outputs: [ pool_addr (upload endowment) ]

// COMMENT payload:
{ magic: GRF_MAGIC, event: "COMMENT", art_id, comment_utf8_hex }
Outputs: [ 80% -> addr_c, 10% -> pool_addr ]; 10% miner fee via input-output delta.`
    },
    {
      id: "settlement-payout",
      title: "7. Settlement & Payout",
      content: `- **On POST**: Upload fee moves to \`pool_addr\`. Funds unlock gradually per \`EPOCH_BLOCKS\` for nodes passing retention proofs.
- **On COMMENT**: The 80% / 10% / 10% split is enforced strictly on-chain; no central escrow.
- **Penalties**: Nodes failing K consecutive epochs for a work receive no payout for those epochs (shares are redistributed to active, honest provers).`
    },
    {
      id: "limits-abuse-privacy",
      title: "8. Limits, Abuse, and Privacy",
      content: `- **Comment Size**: Constrained by \`COMMENT_MAX_BYTES\` (280B); UTF-8 counted by raw bytes (emojis included).
- **Wallet Rate Limit**: UI cooldown per address per artwork to reduce spam bursts.
- **Pseudonymity**: Comments originate from user addresses; users may generate fresh addresses per comment for optimal privacy.
- **Neutrality**: Storage is voluntary and non-custodial. Node operators configure local replication policies.`
    },
    {
      id: "worked-example",
      title: "9. Worked Example",
      content: `**Scenario**:


Creator uploads a **720KB** image → Billable size = 800KB.
   \`UPLOAD_FEE\` (0.8 TSAR) × 8 = **6.4 TSAR** upload fee deposited into \`pool_addr\`.


Citizen posts **Comment A (2 TSAR)**:
   - **1.6 TSAR** → Creator address
   - **0.2 TSAR** → \`pool_addr\`
   - **0.2 TSAR** → Miner block reward fee


Citizen posts **Comment B (2 TSAR + 5 TSAR tip)**:
   - **1.6 TSAR** (royalty) + **5.0 TSAR** (tip) = **6.6 TSAR** → Creator
   - **0.2 TSAR** → \`pool_addr\`
   - **0.2 TSAR** → Miner fee


**Epoch Payout** : Storage nodes passing byte-challenge Merkle proofs claim payouts from the \`pool_addr\` balance.`
    },
    {
      id: "protocol-parameters",
      title: "10. Protocol Parameters (config.py)",
      table: {
        headers: ["Parameter", "Default (v0.1)", "Description"],
        rows: [
          ["UPLOAD_FEE", "0.8 TSAR", "Upload fee per 100KB (rounded up)"],
          ["MIN_BILLABLE_SIZE", "100 KB", "Minimum billable chunk size"],
          ["REPLICATION_R", "5", "Target permanent replica count"],
          ["EPOCH_BLOCKS", "720", "Retention audit epoch (~1 day @2m/block)"],
          ["COMMENT_MAX_BYTES", "280 Bytes", "Maximum on-chain comment UTF-8 payload"],
          ["COMMENT_FEE_MIN", "1.0 TSAR", "Minimum comment fee"],
          ["ROYALTY_CREATOR", "0.80 (80%)", "Creator share of comment fee"],
          ["SHARE_STORAGE", "0.10 (10%)", "Storage pool share of comment fee"],
          ["SHARE_MINER_FEE", "~0.10 (10%)", "Miner fee via transaction delta"]
        ]
      }
    },
    {
      id: "security-threats",
      title: "11. Security Model & Anti-Buzzer Posture",
      content: `- **Sybil Storage Resistance**: Mitigated by per-epoch RandomX-seeded byte-range challenges & Merkle proofs across distinct node IDs.
- **Comment Flooding**: Economic friction via \`COMMENT_FEE_MIN\` (1 TSAR) + wallet rate limits.
- **No Gatekeepers**: The network has no takedown coordinator; storage is voluntary, diverse nodes guarantee resilience.
- **Buzzers**: Paid speakers directly fund creators and the immutable archive.`
    },
    {
      id: "notes",
      title: "12. Notes & Development Status",
      content: `We honor difficult ideas and honest conversation, not harm. The aesthetic is underground by design: self-custody, no gatekeepers, receipts on-chain.

TsarChain and GRAFFITI sit inside a wider vision:
- A **"digital preservation system for cultural heritage and creativity"**.
- A **"pro digital sovereignty"** network where creators keep more control over how their work is stored and discovered.
- An *experimental project, independent, and community-driven.*

*This is an initial draft.*
*The Graffiti Protocol is still under development.*
*The draft may be amended over time, but the initial idea will remain consistent.*`
    }
  ]
};
