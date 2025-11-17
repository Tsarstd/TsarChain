'''
- Manifesto

GRAFFITI is a protocol for loud art and louder truth. Not an NFT, not a stock, not a brand collab.
Each work is a digital monument - permanently archived by
TsarChain Storage Nodes and anchored to a block. 

Public comments are permanent too: once broadcast, they cannot be edited or silently removed at the
protocol level. Instead of chasing viral views, GRAFFITI focuses on **durability, traceability, and fair
rewards for creators**.

There is no central moderator with a “ban” button. If someone wants to speak here, they contribute to the
cost of storage — and the artist earns a share.

GRAFFITI is a **pro digital sovereignty archival layer** within the broader TsarChain ecosystem
a way for communities to preserve culture and conversation over time, while each node operator and user
remains responsible for complying with the laws in their own jurisdiction.

1. Core Ideas

	• Not an NFT: No transferable ownership. GRAFFITI is an archive of art & voice, not a speculation. 

	• Block Anchor: A work's identity binds its content hash with the block hash in which
		the upload TX is included. 

	• Permanence: Files are replicated by Storage Nodes; on-chain commitments reference what
		must exist off-chain. 

	• Immutable Comments: Each comment is a paid on-chain event; comment text is stored on-chain
		within safe byte limits. 

	• Automatic Royalty: 80% of every comment fee goes to the creator, 10% to the Storage Pool,
		~10% to miners as fee. 

	• Moderatorless: The protocol is neutral. Local enforcement (if any) is a node operator choice.
 
2. Roles & Responsibilities

	• Creator (Artist): Uploads art, pays an upload fee, receives 80% royalty from every paid comment. 

	• Citizen (Commenter): Pays to append a permanent comment to the work; can add an optional tip. 

	• Miner: Validates and mines blocks; collects ~10% of each comment as transaction fee (input-output delta). 

	• Storage Node: Permanently stores replicated copies (R). Earns 10% from comments plus a share
		of the upload endowment. 

	• Indexer/Explorer: Indexes GRAFFITI events and renders works & comment threads.
 
3. Economic Flows

3.1 Upload Fee :

	Creator pays based on file size: UPLOAD_FEE with MIN_BILLABLE_SIZE (SIZE = 100KB).
	Default allocation: 100% to the work's Storage Pool endowment to fund long-term
	retention (tunable in config.py).

3.2 Comment Fee :

	Each comment includes comment_amount ( ≥ COMMENT_FEE_MIN).
	Automatic split:

		• 80% -> creator address (royalty). 
		• 10% -> work's Storage Pool (micropayment for replicas). 
		• ~10% -> miners as fee (achieved by making total outputs = 90% of inputs).

3.3 Tips Optional tip_amount goes 100% to the creator


4. Data Model & Identifiers

4.1 Art Object

	• File hash: Hc = SHA256(file_blob).
	• Anchor block: Hb = block hash where the upload TX is confirmed.
	• Creator: addr_c (P2WPKH/P2SH depending on TsarChain config).
	• art_id: SHA256("GRAFFITI" || Hc || Hb || addr_c).
	• Optional metadata: mime_type, size_kb, title (≤ 64B), tags (≤ 128B).

4.2 Comment Object

	• Max length: COMMENT_MAX_BYTES (e.g., 280B).
	• comment_id: SHA256(art_id || txid || vout_index).
	• Comment text: stored on-chain (UTF8 -> hex) via a compact data carrier field.
	• Anti spam lever: COMMENT_FEE_MIN + optional wallet UI rate limiting.


5. Storage Layer (Permanent)

	• Replication factor R: (default 5) using consistent hashing on a node ring keyed by art_id.

	• Storage Pool Address: A deterministic address per art_id: pool_addr = GRV_POOL(art_id).

	• Proof of Retention: every EPOCH_BLOCKS, each storing node proves possession via random
		byte range challenges; the current epoch's pool_addr balance is split among successful provers.

	• Endowment: If no new comments arrive, the initial upload fee acts as a base endowment
		for periodic payouts.


6. Wire Format (On Chain Hints)

Use a compact data carrier tag (OP_RETURN style) for simple & deterministic indexing.
GRV_MAGIC = 0x47525631 ("GRV1") Events: POST, COMMENT 

POST payload (pseudo): { magic: GRV_MAGIC, event: POST, Hc, size_kb, mime, addr_c, R_hint, meta_short }
Outputs: [ pool_addr (upload endowment) ] 

COMMENT payload (pseudo): { magic: GRV_MAGIC, event: COMMENT, art_id, comment_utf8_hex }
Outputs: [ 80% -> addr_c, 10% -> pool_addr ]; 10% miner fee via input-output delta.


7. Settlement & Payout

	• On POST: the upload fee moves to the work's pool_addr. Funds unlock gradually per EPOCH_BLOCKS
		for nodes passing retention proofs. 

	• On COMMENT: the split in §3.2 is enforced on chain; no centralized distributor. 

	• Penalty: Nodes failing K consecutive epochs for a work receive no payout for those epochs
		(share redistributed to successful provers).


8. Limits, Abuse, and Privacy

	• Comment size: constrained by COMMENT_MAX_BYTES; UTF8 counted by bytes (emojis included). 

	• Wallet rate limit: optional UI cooldown per address per art to reduce spam floods. 

	• Pseudonymity: comments originate from user addresses; allow new address per comment for better privacy. 

	• Illegal content: the protocol is neutral; storage is voluntary and non custodial.
		Node operators may set local policies.

 
9. Explorer & Indexer API (Sketch)

	• GET_ART(art_id): { Hc, Hb, addrC, size_kb, mime, meta, replication, pool_addr }. 

	• GET_COMMENTS(art_id, paging): list { comment_id, txid, height, addr_from, text }. 

	• GET_STORAGE_STATUS(art_id): ring nodes, latest retention proofs, payout schedule. 

	• SEARCH(query): text/tags (optionally mirrors off chain index).


10. Worked Example

File: 720KB -> billable = 800KB. UPLOAD_FEE (0.8 TSAR) * 8 = 6.4 TSAR upload_fee -> pool_addr. 

Comment A: 2 TSAR -> 1.6 to creator, 0.2 to pool_addr, 0.2 miner fee. 

Comment B (with Tip): 5 TSAR tip -> 1.6 royalty (from 2 TSAR) + 5.0 tip to creator; 0.2 to
pool_addr; 0.2 miner fee. 

Payout: Per epoch, storage nodes passing proofs split the available pool for this work.



11. Parameters (config.py)


	PARAM								Default (v0.1)					Notes

	UPLOAD_FEE							0.8 TSAR				        Upload fee per 100KB (rounded up)
	MIN_BILLABLE_SIZE				    100 KB						    Minimum billable chunk
	REPLICATION_R						5						        Permanent replication factor
	EPOCH_BLOCKS						720						        Retention epoch (~1 day @2m/block)
	COMMENT_MAX_BYTES					280								Max on chain comment bytes
	COMMENT_FEE_MIN						1 TSAR						    Minimum comment fee
	ROYALTY_CREATOR						0.80							Creator share of comment fee
	SHARE_STORAGE						0.10						    Storage pool share of comment fee
	SHARE_MINER_FEE						~0.10							Miner fee via I/O delta
 
 
12. Security Model (Short)

	• TX signing follows TsarChain standards (P2WPKH/P2SH). GRAFFITI adds new event types,
		not a new consensus.

	• Clients validate file downloads via content hash Hc and block anchor Hb.

	• Pool payouts are deterministic and auditable via pool_addr and retention logs.


13. Threat Notes & Anti Buzzer Posture

	• Sybil Storage: mitigated by per epoch retention proofs & split among distinct node IDs. 

	• Comment Flooding: economic friction via COMMENT_FEE_MIN + wallet cooldown. 

	• Content Takedown: protocol has none. Storage is voluntary; diverse nodes = resilience.
		Buzzers must pay to speak - artists earn.


### --- Next Implementation Steps (Dev Notes) --- 

	- Retention Proof Scheduler: rancang worker storage node yang periodik menjalankan byte-range challenge sebelum pool balance dibagikan; log penalti jika bukti absen.
 
	- Storage Automation: definisikan template transaksi on-chain untuk payout pool (mis. script khusus) sehingga klaim bisa otomatis mengikuti aturan konsensus.
'''
