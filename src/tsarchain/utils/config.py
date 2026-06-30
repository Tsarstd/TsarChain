# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173; LWMA-Zawy; Signal-DoubleRatchet; NIST-800-38D-AES-GCM

'''
    ██     ██   ████   ██  ██  ██  ██   ████   ██     ██   ████   ██  ██ 
    ███   ███  ██  ██  ██  ██  ██ ██   ██  ██  ███   ███  ██  ██  ██  ██ 
    ██ ███ ██  ██████  ██████  ████    ██████  ██ ███ ██  ██████  ██████ 
    ██     ██  ██  ██  ██  ██  ████    ██  ██  ██     ██  ██  ██  ██  ██ 
    ██     ██  ██  ██  ██  ██  ██ ██   ██  ██  ██     ██  ██  ██  ██  ██ 
    ██     ██  ██  ██  ██  ██  ██  ██  ██  ██  ██     ██  ██  ██  ██  ██ 

 ██  ██   ████   ██   ██   ████  ████████  ████  ████████  ██  ██   ████  ████ 
 ██ ██   ██  ██  ███  ██  ██        ██      ██      ██     ██  ██  ██      ██  
 ████    ██  ██  ██ ████  ██        ██      ██      ██     ██  ██  ██      ██  
 ████    ██  ██  ██  ███   ███      ██      ██      ██     ██  ██   ███    ██  
 ██ ██   ██  ██  ██   ██     ██     ██      ██      ██     ██  ██     ██   ██  
 ██  ██   ████   ██   ██  ████      ██     ████     ██      ████   ████   ████ 
 
=============================================================================
 -------- !!! CONSENSUS-CRITICAL REMINDER - READ BEFORE EDITING !!! --------
=============================================================================

The values below **MUST BE IDENTICAL** across all nodes.
Changing them may cause different block/tx validity (hard fork) unless otherwise stated.

  1) GENESIS / CHAIN IDENTITY
   - GENESIS_HASH_HEX
   - ALLOW_AUTO_GENESIS
   - GENESIS_BLOCK_ID_DEFAULT

  2) MONETARY
   - INITIAL_REWARD, BLOCKS_PER_HALVING, COINBASE_MATURITY
   - MAX_SUPPLY
   - MAX_COINBASE_EXTRADATA

  3) DIFFICULTY & TIMESTAMPS
   - INITIAL_BITS, MAX_BITS, TARGET_BLOCK_TIME, LWMA_WINDOW
   - FUTURE_DRIFT, MTP_WINDOWS
   - ENABLE_DIFF_CLAMP, DIFF_CLAMP_MAX_UP, DIFF_CLAMP_MAX_DOWN
   - ENABLE_EDA, EDA_WINDOW, EDA_TRIGGER_RATIO, EDA_EASE_MULTIPLIER

  4) BLOCK & TRANSACTION LIMITS
   - MAX_BLOCK_BYTES, MAX_TXS_PER_BLOCK
   - MAX_SIGOPS_PER_BLOCK, MAX_SIGOPS_PER_TX

  5) SCRIPT RULES / OP_RETURN / GRAFFITI
   - MAX_GRAFFITI_OPRET
   - GRAFFITI_MAGIC
   - GRAFFITI_EXPIRE_AFTER_BLOCKS
   - GRAFFITI_PROOF_EPOCH_BLOCKS
   - GRAFFITI_PROOF_EPOCH_DRIFT
   - MAX_GRAFFITI_ON_MEMPOOL
   - GRAFFITI_MIN_BILLABLE_SIZE
   - GRAFFITI_UPLOAD_FEE_PER_CHUNK
   - GRAFFITI_COMMENT_MAX_BYTES
   - GRAFFITI_COMMENT_MIN_FEE
   - GRAFFITI_COMMENT_BP_DENOM
   - GRAFFITI_COMMENT_CREATOR_BP
   - GRAFFITI_COMMENT_STORAGE_BP

  6) FORK-CHOICE & REORG
   - ENABLE_CHAINWORK_RULE, ENABLE_REORG_LIMIT, REORG_LIMIT

  7) POW (RandomX) - CONSENSUS CRITICAL
   - POW_ALGO, RANDOMX_STATIC_KEY
   - RANDOMX_KEY_EPOCH_BLOCKS

NOT CONSENSUS (safety differs between nodes):
   - RANDOMX_FULL_MEM, RANDOMX_LARGE_PAGES, RANDOMX_JIT, etc. (performance tuning only)
   - port/BOOTSTRAP, timeout, connection limit, anti-DoS, logging/path
   - option UI/wallet

NETWORK ISOLATION (not a fork, but cannot connect to each other):
   - DEFAULT_NET_ID / NET_ID_DEV / NET_ID_PROD, NETWORK_MAGIC

=============================================================================
'''

import os
import appdirs


# =============================================================================
# 1. MODE & APPLICATION
# =============================================================================
# ---- RUNTIME PROFILE ----
MODE   = "dev"  # default runtime profile, switch to "prod" for live nodes
IS_DEV = (MODE.lower() == "dev")  # cached boolean to simplify dev/prod toggles

# ---- APP METADATA ----
APP_NAME        = "Kremlin"  # display name used for user data directories
APP_AUTHOR      = "TsarStudio"  # vendor string passed into platform dir helpers
WALLET_DATA_DIR = appdirs.user_data_dir(APP_NAME, APP_AUTHOR)  # OS-specific wallet folder resolved via appdirs


# =============================================================================
# 2. DATABASE & SNAPSHOTS
# =============================================================================
# ---- DATA SCHEMA ----
# Bump when changing on-disk JSON/LMDB structures (state, utxo, mempool, block cache)
DATA_SCHEMA_VERSION = 1

# ---- KV BACKEND ----
KV_BACKEND         = "lmdb"  # active key-value backend implementation (lmdb & json)
LMDB_DATA_FILE     = "data/node"  # main LMDB data file path
LMDB_MAP_SIZE_INIT = 4 * 1024 * 1024  # initial LMDB map size (4 MB)
LMDB_MAP_SIZE_MAX  = 64 * 1024 * 1024 * 1024  # upper LMDB map cap (64 GB)
KV_ITER_CHUNK      = 512 # number of entries per chunk when iterating prefix scans (LMDB)

# ---- WEB CACHE (LMDB) ----
WEB_DATABASE_PATH  = "data/web"  # dedicated LMDB path for web cache
LMDB_WEB_SIZE_INIT = 100 * 1024  # initial web LMDB size (100 KB)
LMDB_WEB_SIZE_MAX  = 128 * 1024 * 1024 * 1024  # max web LMDB size (64 GB)

# ---- SNAPSHOT SIGNING ----
SNAPSHOT_REQUIRE_SIGNATURE = False  # demand signed snapshot manifests when True
SNAPSHOT_MANIFEST_URL      = ""  # optional URL supplying snapshot manifest
SNAPSHOT_FILE_URL          = ""  # optional URL for snapshot binary
SNAPSHOT_PUBKEY_HEX        = ""  # hex-encoded pubkey used to verify snapshot signature

# ---- SNAPSHOT MODES ----
SNAPSHOT_BOOTSTRAP_ENABLED = False  # allow nodes to bootstrap via snapshot downloads
SNAPSHOT_BOOTSTRAP_FOR_GUI = False  # enable snapshot bootstrap path for miner_gui.py
SNAPSHOT_BOOTSTRAP_FOR_CLI = False  # enable snapshot bootstrap path for cli_node_miner.py

# ---- SNAPSHOT TRANSFER ----
SNAPSHOT_HTTP_TIMEOUT    = 90  # HTTP timeout applied to snapshot downloads
SNAPSHOT_CHUNK_BYTES     = 2 * 1024 * 1024  # chunk size when streaming snapshot data
SNAPSHOT_MIN_SIZE_BYTES  = 15 * 1024  # ignore snapshot files smaller than this
SNAPSHOT_META_PATH       = "data/node/snapshot.meta.json"  # cached metadata file for snapshots
SNAPSHOT_MAX_AGE_SECONDS = 12 * 3600  # maximum tolerated snapshot age (12h)
SNAPSHOT_USER_AGENT      = "TsarChainSnapshot/1.0"  # UA string used when fetching snapshots

# ---- SNAPSHOT BACKUP ----
SNAPSHOT_BACKUP_DIR   = "data/snapshot"  # folder storing backup snapshots
BACKUP_SNAPSHOT       = False  # toggle to keep automatic backup copies
BLOCK_BACKUP_SNAPSHOT = 15  # Align last backup marker to nearest interval to avoid drift across restarts


# =============================================================================
# 3. FILESYSTEM LAYOUT
# =============================================================================
# ---- CORE STATE FILES ----
STATE_FILE              = "data_json/node/State/state.json"  # serialized node state snapshot
BLOCK_FILE              = "data_json/node/Block/blockchain.json"  # block archive used before DB bootstrap
UTXOS_FILE              = "data_json/node/UTXOS/utxos.json"  # fallback UTXO dump for light tooling
MEMPOOL_FILE            = "data_json/node/Mempools/txpools.json"  # persistent mempool cache file

CHAIN_JOURNAL_FILE      = os.path.join(os.path.dirname(BLOCK_FILE), "blockchain.journal")  # append-only delta log for JSON mode
CHAIN_JOURNAL_MAX_BYTES = 8 * 1024 * 1024
STATE_HEIGHT_CACHE_TTL  = 2.0  # height for utxo validation & cache

# ---- ARCHIVIST LMDB PATH ----
ARCHIVIST_INDEX_DB_PATH = "data/archivist/storage/index_db"
ARCHIVIST_FINAL_DB_PATH = "data/archivist/storage/final_db"
ARCHIVIST_KEY_PATH      = "data/archivist/archivist_key.json" # primary node identity key storage path

# ---- WALLET KEY FILES ----
USER_KEY_PATH = "data_user/user_key.json"  # default user keypair location
REGISTRY_PATH = "data_user/wallet_registry.json"  # registry of created wallets
CHAT_STATE    = "data_user/chat_config.json"  # cached chat preferences and pointers

# ---- CHAT KEY FILES ----
CHAT_KEYS_DIR = "data_user/chat_keys"
PREKEY_DIR    = "data_user/chat_prekeys"

# ---- NODE KEYS FILES ----
KEYS_DATA_DIR         = "data/keys"  # root folder for node-specific secrets
NODE_KEY_PATH         = os.path.join(KEYS_DATA_DIR, "node.json")  # primary node identity key storage path
PEER_KEYS_PATH        = os.path.join(KEYS_DATA_DIR, "node/peer_keys.json")  # known peer key cache linked to node_data


# =============================================================================
# 4. CHAIN IDENTITY & GENESIS
# =============================================================================
# ---- NETWORK IDENTIFIERS ----
NET_ID_DEV     = "gulag-net"  # dev network identifier string advertised on handshake
NET_ID_PROD    = "sputnik-net"  # production network identifier string
ADDRESS_PREFIX = "tsar"  # bech32-style prefix for wallet addresses
DEFAULT_NET_ID = NET_ID_DEV if IS_DEV else NET_ID_PROD  # active network id chosen from MODE
NETWORK_MAGIC  = b"TSARCHAIN"  # handshake magic to avoid cross-network chatter
ZERO_HASH      = b"\x00" * 32  # convenience zero-hash constant for comparisons
CANONICAL_SEP  = (",", ":")  # tuple of separators used when building canonical ids

# ---- GENESIS SETTINGS ----
ALLOW_AUTO_GENESIS       = 0 # enable (1) or disable (0) automatic genesis construction
GENESIS_HASH_HEX         = "00033012747f1ddc47c018caab0a0bd7e26c55db45224d17d39bd4ec9a9f21e2"  # reference hash of committed genesis block
GENESIS_BLOCK_ID_DEFAULT = "Every person who is born free has the same rights and dignity. (Munir Said Thalib - 2004-09-07)"  # default human-readable genesis identifier
# ascii-only tribute list embedded within genesis metadata

# ---- BLOCK ID LIST ----
VOICE_SOVEREIGNTY_FIGURES = [
    
    # Whistleblower / voice sovereignty figures
    ("Munir", 2004),
    ("Widji Thukul", 1998),
    ("Marsinah", 1993),
    ("Jamal Khashoggi", 2018),
    ("Daphne Caruana Galizia", 2017),
    ("Anna Politkovskaya", 2006),
    ("Berta Caceres", 2016),
    ("Marielle Franco", 2018),
    ("Shireen Abu Akleh", 2022),
    ("Javier Valdez Cardenas", 2017),
    ("Pavel Sheremet", 2016),
    ("Lasantha Wickrematunge", 2009),
    ("Narges Mohammadi", 2023),
    ("Liu Xiaobo", 2017),
    ("Ai Weiwei", 2011),
    ("Edward Snowden", 2013),
    ("Chelsea Manning", 2010),
    ("Julian Assange", 2010),
    ("Raif Badawi", 2014),
    ("Mahsa Amini", 2022),
    ("Nasrin Sotoudeh", 2010),
    ("Ilham Tohti", 2014),
    ("Wa Lone and Kyaw Soe Oo", 2017),
    ("Maria Ressa", 2018),
    ("Evan Gershkovich", 2023),
    
    # Graffiti / street art pioneers
    ("Jean Michel Basquiat", 1980),
    ("Keith Haring", 1980),
    ("Futura 2000", 1982),
    ("Dondi White", 1980),
    ("Lady Pink", 1980),
    ("Lee Quinones", 1979),
    ("Banksy", 2005),
    ("Shepard Fairey", 2008),
    ("Os Gemeos", 1999),
    ("Blu", 2007),
    ("Darbotz", 2004),
]


# =============================================================================
# 5. MONETARY POLICY
# =============================================================================
# ---- UNIT CONSTANTS ----
TSAR = 100_000_000  # atomic unit (8 decimals) equivalent to satoshis

# ---- EMISSION SCHEDULE ----
MAX_SUPPLY             = 252_500_000 * TSAR  # hard cap on total minted supply
INITIAL_REWARD         = 250 * TSAR  # block subsidy at height zero
BLOCKS_PER_HALVING     = 235_000  # interval before subsidy halves
COINBASE_MATURITY      = 3  # required confirmations before spending coinbase
MAX_COINBASE_EXTRADATA = 95  # soft limit for coinbase metadata bytes (based on GENESIS_BLOCK_ID_DEFAULT length)

# ---- GENESIS BONUSES ----
GENESIS_REWARD        = True  # well, this is actually pre-mine. use for developing purposes only
GENESIS_REWARD_AMOUNT = 2_500_000 * TSAR  # allocation granted when genesis reward is enabled


# =============================================================================
# 6. CONSENSUS & DIFFICULTY
# =============================================================================
# ---- BASE DIFFICULTY ----
INITIAL_BITS      = 0x1F9FFFFF  # starting difficulty bits assigned to block zero
MAX_BITS          = 0x1F9FFFFF  # cap for easiest allowed difficulty
TARGET_BLOCK_TIME = 68  # aim for ~68 seconds block cadence
LWMA_WINDOW       = 75  # block count considered by LWMA difficulty algo
FUTURE_DRIFT      = 600  # max seconds a block timestamp may lead wall clock
MTP_WINDOWS       = 11  # number of blocks in median time past calculation

# ---- PROOF OF WORK ----
POW_ALGO                 = "randomx"
RANDOMX_STATIC_KEY       = "tsar-dev-seed"
RANDOMX_KEY_SALT         = b"tsar-randomx"
RANDOMX_KEY_EPOCH_BLOCKS = 128     # rotate RandomX seed every N blocks
RANDOMX_FULL_MEM         = False  # allocate ~2GB dataset for mining/validation - default 'False' can be changed in CLI
RANDOMX_LARGE_PAGES      = False  # set True only if huge pages configured OS-wide
RANDOMX_JIT              = True
RANDOMX_SECURE_JIT       = True
RANDOMX_HARD_AES         = True
RANDOMX_CACHE_MAX        = 4      # max RandomX VM entries cached in rust binding

# ---- CACHE LIMITS (LRU) ----
HASH_CACHE_MAX          = 5000   # max entries hash cache (LRU)
RPC_CONN_CACHE_MAX      = 32     # max cached RPC channels/sockets (LRU)

# ---- BLOCK & TX LIMITS ----
MAX_BLOCK_BYTES      = 1_200_000  # block size limit (approx 1.2 MB)
MAX_TXS_PER_BLOCK    = 5_000  # guardrail on number of tx per block
MAX_SIGOPS_PER_BLOCK = 40_000  # signature operation ceiling per block
MAX_SIGOPS_PER_TX    = 6_000  # signature operation ceiling per transaction
MAX_TX_VSIZE         = 10_000  # maximum virtual size (vbytes) per transaction
MIN_TX_VSIZE         = 100     # minimum virtual size (vbytes) per transaction
MAX_TX_WEIGHT        = 40_000  # maximum weight units per transaction
MIN_TX_WEIGHT        = 400     # minimum weight units per transaction
MAX_TX_INPUTS        = 1_000   # hard cap on number of inputs per transaction
MAX_TX_OUTPUTS       = 1_000   # hard cap on number of outputs per transaction

# ---- FORK CHOICE ----
ENABLE_CHAINWORK_RULE = True  # enforce cumulative chainwork comparison for forks
ENABLE_REORG_LIMIT    = True  # enable reorg depth bounding
REORG_LIMIT           = 1000  # maximum blocks allowed for automatic reorg

# ---- DIFF CLAMP ----
ENABLE_DIFF_CLAMP   = True  # clamp difficulty adjustments to damp volatility
DIFF_CLAMP_MAX_UP   = 1.5  # ratio cap for upward difficulty moves
DIFF_CLAMP_MAX_DOWN = 0.4  # ratio floor for downward difficulty moves

# ---- EMERGENCY DIFFICULTY ----
ENABLE_EDA          = True  # emergency difficulty adjustment switch (often off on prod)
EDA_WINDOW          = 48  # number of blocks observed by EDA
EDA_TRIGGER_RATIO   = 3.0  # slowdown ratio that triggers EDA easing
EDA_EASE_MULTIPLIER = 2.0  # difficulty divisor applied when EDA fires

# ---- MINING UTILS ----
MINING_COOLDOWN_AFTER_BLOCK = 0.5

# =============================================================================
# 7. TRANSACTION FEES & MEMPOOL
# =============================================================================
# ---- FEE POLICY ----
DEFAULT_FEE_RATE_SATVB = 34  # wallet default feerate in sat/vbyte
MIN_FEE_RATE_SATVB     = 34  # allowed minimum feerate floor
MAX_FEE_RATE_SATVB     = 10_000  # safety cap to avoid absurd fees

# ---- WEIGHT ESTIMATES ----
TX_BASE_VBYTES       = 10  # serialized tx overhead used for projections
SEGWIT_INPUT_VBYTES  = 68  # assumed weight of a P2WPKH input
SEGWIT_OUTPUT_VBYTES = 31  # assumed weight of a P2WPKH output
DUST_THRESHOLD_SAT   = 294  # outputs smaller than this are treated as dust
MAX_DECIMALS         = 8  # UI precision for wallet rendering

# ---- MEMPOOL LIMITS ----
MEMPOOL_MAX_SIZE        = 2 * 1024 * 1024  # maximum in-memory mempool footprint (bytes)
MAX_GRAFFITI_ON_MEMPOOL = 7                # NOTE: do not change the value above GRAFFITI_EXPIRE_AFTER_BLOCKS


# =============================================================================
# 8. NETWORK & SYNC
# =============================================================================
# ---- PORTS & BOOTSTRAP ----
PORT_RANGE_DEV  = (38169, 38178)  # port span reserved for dev deployments
PORT_RANGE_PROD = (40196, 40205)  # port span reserved for production nodes

STORAGE_PORT_RANGE_DEV  = (39200, 39209)
STORAGE_PORT_RANGE_PROD = (41200, 41209)

BOOTSTRAP_DEV = (
    ("127.0.0.1", 38169),
) # loopback bootstrap peers for development

BOOTSTRAP_PROD = (
    ("127.0.0.1", 40197),
) # loopback bootstrap peers for production

if IS_DEV:
    PORT_START, PORT_END = PORT_RANGE_DEV  # active listening range for dev mode
    BOOTSTRAP_NODES      = BOOTSTRAP_DEV  # list of seed peers for dev mode
    STORAGE_PORT_START, STORAGE_PORT_END = STORAGE_PORT_RANGE_DEV
else:
    PORT_START, PORT_END = PORT_RANGE_PROD  # active listening range for prod mode
    BOOTSTRAP_NODES      = BOOTSTRAP_PROD  # list of seed peers for prod mode
    STORAGE_PORT_START, STORAGE_PORT_END = STORAGE_PORT_RANGE_PROD

BOOTSTRAP_NODE           = BOOTSTRAP_NODES[0]  # preferred bootstrap peer entry

# ---- SOCKET DEFAULTS ----
BUFFER_SIZE              = 65536  # socket buffer size for P2P reads (~64 KB)
HANDSHAKE_TIMEOUT        = 10  # seconds allowed to finish handshake
DISCOVERY_INTERVAL       = 5  # seconds between peer discovery scans
SYNC_INTERVAL            = 20  # seconds between standard sync pulls
FAST_SYNC_INTERVAL       = 5  # seconds between fast-sync loops
SYNC_TIMEOUT             = 15  # seconds before abandoning slow sync requests
CONNECT_TIMEOUT          = 2  # TCP dial timeout per peer attempt
BROADCAST_FAIL_THRESHOLD = 2  # consecutive failures before backing off broadcasting
BROADCAST_FAIL_BACKOFF_S = 120  # seconds to wait when broadcast keeps failing

# ---- ANTI-DOS LIMITS ----
MAX_ADDRS_PER_REQ              = 15  # max addresses accepted per addr message
MAX_HISTORY_LIMIT              = 200  # cap on stored addr history per peer
MAX_UTXO_ADDR_LEN              = 64  # sanity limit for UTXO address strings
NONCE_PER_SENDER_MAX           = 256  # per-sender nonce cache bound
NONCE_GLOBAL_MAX               = 100_000  # global nonce cache bound across senders

HANDSHAKE_RL_PER_IP_BURST      = 20  # burst limit when rate-limiting handshakes
HANDSHAKE_RL_PER_IP_WINDOW_S   = 30  # time window for handshake rate limit
HANDSHAKE_RL_PER_NODE_BURST    = 80  # burst limit per node_id to avoid CGNAT false positives

HANDSHAKE_RL_PER_NODE_WINDOW_S = 10  # time window for per-node limiter
HANDSHAKE_RL_SUBNET_BURST      = 100  # burst cap per /24 subnet (IPv4) or /64 (IPv6) for floods
HANDSHAKE_RL_SUBNET_WINDOW_S   = 20  # subnet limiter window (seconds)

CGNAT_IP_BURST_MULT            = 3  # multiplier to loosen per-IP limits when identity is present
TEMP_BAN_SECONDS               = 300  # duration for temporary ban entries
BAN_MALICIOUS_RPC              = 600  # temp ban duration when receiving unregistered RPC types

POW_TOKEN_TTL_S                = 120  # default TTL for PoW challenge/cookie
RPC_POW_DIFFICULTY_TX          = 16  # difficulty bits for TX submit / wallet-heavy RPC
RPC_POW_DIFFICULTY_READ        = 12  # difficulty bits for read-only RPC (info/history/graffiti)
RPC_POW_DIFFICULTY_CHAT        = 14  # difficulty bits for chat presence/send/lookup

# ---- FULL SYNC GUARD ----
ENABLE_FULL_SYNC          = False
FULL_SYNC_MAX_BLOCKS      = 5_000  # cap on blocks served per full-sync round
FULL_SYNC_MIN_INTERVAL    = 60  # seconds a peer must wait between full-sync requests
FULL_SYNC_BACKOFF_INITIAL = 120  # starting backoff between full sync retries
FULL_SYNC_BACKOFF_MAX     = 600  # maximum backoff delay between full sync retries
MAX_MSG                   = 3 * 1024 * 1024  # upper bound for inbound message payloads
MEMPOOL_SYNC_MIN_INTERVAL = 20  # seconds between mempool sync batches
MEMPOOL_INLINE_MAX_TX     = 100  # tx count allowed inline before streaming
MEMPOOL_FLUSH_INTERVAL    = 5.0  # seconds between mempool flush to disk

# ---- SYNC WINDOWS ----
HEADERS_BATCH_MAX         = 4096  # number of headers requested per batch
HEADERS_LOCATOR_DEPTH     = 64  # entries kept in locator list when syncing
HEADERS_FANOUT            = 32  # peers to fan out header requests to
HEADERS_SYNC_MIN_INTERVAL = 1  # seconds between header sync loops
BLOCK_DOWNLOAD_BATCH_MAX  = 2048  # concurrent block download cap
CHAIN_FLUSH_INTERVAL      = 1  # blocks between lightweight chain persistence
CHAIN_FORCE_FULL_FLUSH    = False  # force full persistence on every save when True
UTXO_FLUSH_INTERVAL       = 10  # block interval between UTXO set flushes

# ---- PEER QUOTAS ----
MAX_OUTBOUND_PEERS         = 20  # outbound connection ceiling
MAX_INBOUND_PEERS          = 25  # inbound connection ceiling
MAX_INBOUND_PER_IP         = 8  # inbound peers allowed per IP
PEER_SCORE_START           = 10  # initial trust score assigned to new peers
PEER_SCORE_FAILURE_PENALTY = 5  # decrements applied on failure events
PEER_SCORE_REWARD          = 1  # increments applied on good behavior
PEER_SCORE_MIN             = -40  # floor value before dropping the peer


# =============================================================================
# 9. SECURITY & CRYPTOGRAPHY
# =============================================================================
# ---- P2P ENCRYPTION ----
P2P_ENC_REQUIRED     = True  # enforce AEAD encryption for all node links
P2P_AEAD_KEY_BYTES   = 32  # key size used for AES-256-GCM sessions
P2P_AEAD_NONCE_BYTES = 12  # nonce size for GCM packets
P2P_AEAD_AAD_PREFIX  = b"TSAR|P2P|v1"  # additional data binding network id/version
P2P_SESSION_TTL_S    = 3600  # seconds before rekeying P2P session
P2P_SESSION_MAX_MSG  = 10000  # message count before forcing new keys
P2P_REKEY_EVERY_MSG  = 2000  # rotate AEAD keys automatically every N messages per direction

# ---- DANDELION++ ----
ENABLE_DANDELION_PP       = True  # enable Dandelion++ stem/fluff relay for transactions
MIN_PEERS_FOR_DANDELION   = 5     # minimum peer count before enabling Dandelion++ path
MIN_FLUFF_DELAY_S         = 1.5
MAX_FLUFF_DELAY_S         = 6.0

# ---- SYNC INFO CADENCE ----
SYNC_INFO_MIN_INTERVAL           = 60  # seconds between sync-info gossip messages
SYNC_INFO_MIN_INTERVAL_BOOTSTRAP = 300.0  # slower sync-info rate for bootstrap node

# ---- REPLAY GUARDS ----
ENVELOPE_REQUIRED    = True  # require message envelopes for replay protection
ENFORCE_HELLO_PUBKEY = True  # reject peers that omit long-term pubkeys
REPLAY_WINDOW_SEC    = 60  # Acceptable skew window for anti-replay stamps


# =============================================================================
# 10. CHAT & PRESENCE
# =============================================================================
# ---- CHAT PAYLOAD LIMITS ----
CHAT_MAX_CT_BYTES     = 2 * 1024  # ciphertext size cap per chat message
CHAT_TS_DRIFT_S       = 120  # tolerated timestamp drift for chat payloads
CHAT_TTL_S            = 86400  # chat retention window (seconds)
CHAT_MAILBOX_MAX      = 250  # messages kept per recipient mailbox
CHAT_GLOBAL_QUEUE_MAX = 20_000  # max pending chat messages globally
CHAT_PULL_MAX_ITEMS   = 50  # entries returned per chat pull request

# ---- CHAT POLLING ----
CHAT_POLL_INTERVAL_MS       = 3000  # default polling interval for chat client
CHAT_POLL_INITIAL_MS        = 4000  # initial backoff before first poll
CHAT_PUBLISH_MIN_INTERVAL_S = 10  # throttle between chat publish attempts

# ---- CHAT RATE LIMITS ----
CHAT_RL_ADDR_BURST   = 25  # per-address burst allowance for chat msgs
CHAT_RL_ADDR_WINDOWS = 10  # seconds over which per-address burst is evaluated
CHAT_RL_IP_BURST     = 50  # per-IP burst allowance for chat msgs
CHAT_RL_IP_WINDOWS   = 10  # seconds over which per-IP burst is evaluated
CHAT_BACKOFF_S       = 13  # seconds to wait after rate limiter trips

# ---- PRESENCE RELAY ----
PRESENCE_RL_ADDR_BURST   = 2  # per-address burst allowance for presence relays
PRESENCE_RL_ADDR_WINDOWS = 10  # seconds window for presence addr limiter
PRESENCE_MAX_HOPS        = 3  # maximum hops for relayed presence updates
PRESENCE_TTL_S           = 3600  # lifespan of presence announcements

# ---- ONION-LITE ROUTING ----
CHAT_FORCE_RELAY = False  # force onion-lite multi-hop routing when true
CHAT_NUM_HOPS    = 1  # number of relay hops used for onion-lite mode

# ---- CHAT STORAGE ----
CHAT_SESSION_DIR           = os.path.join("data_user", "chat_sessions")  # folder storing per-chat sessions
CHAT_KEY_TTL_SEC           = 15 * 60  # interval before e2e session keys rotate
CHAT_PWD_CACHE_TTL_SEC     = 180  # seconds before keystore password must be re-entered
CHAT_RATCHET_MAX_SKIP      = 200  # guardrail for skipped ratchet messages
CHAT_RATCHET_INDEX_MAX     = 1_000_000  # maximum double-ratchet index allowed
CHAT_OPK_MIN_THRESHOLD     = 5  # minimum one-time pre-keys kept ready
CHAT_OPK_REFILL_COUNT      = 20  # number of pre-keys generated when refilling
CHAT_SPK_ROTATE_INTERVAL_S = 24 * 3600  # seconds between signed pre-key rotations
CHAT_OPK_MAX_STORED        = 200  # hard cap untuk jumlah OPK yang disimpan node per alamat
CHAT_HISTORY_MAX_PER_PEER  = 200  # maksimum entri riwayat chat per pasangan alamat


# =============================================================================
# 11. RPC & CACHE
# =============================================================================
# ---- RPC TIMEOUTS ----
CONNECT_TIMEOUT_SCAN = 1.25  # timeout for quick port scanning during discovery
RPC_TIMEOUT          = 4.0   # wallet RPC request timeout in seconds
RPC_CONN_TTL_SEC     = 60.0  # seconds a cached channel/socket stays warm before re-handshake
RPC_PREFETCH_TIMEOUT = 1.5   # quick dial timeout for pre-connect
MAX_HANDSHAKE_BYTES  = 16 * 1024  # cap size for initial handshake frames (HS1/HS2/envelope sniff)

# ---- CLIENT THROTTLING ----
NODE_CACHE_TTL          = 60    # seconds cached node metadata stays valid
WALLET_RPC_MIN_INTERVAL = 0.45  # minimum spacing between wallet RPC calls

# ---- PING LOOKUP THROTTLING ----
PING_RL_IP_BURST    = 5 # ping requests allowed per IP before throttling
PING_RL_IP_WINDOW_S = 10 # time window (seconds) evaluated by the limiter
PING_RL_BACKOFF_S   = 30 # seconds to backoff when the limiter trips

# ---- GET PEERS LOOKUP THROTTLING ----
GET_PEERS_RL_IP_BURST    = 5 # get_peers requests allowed per IP before throttling
GET_PEERS_RL_IP_WINDOW_S = 10 # time window (seconds) evaluated by the limiter
GET_PEERS_RL_BACKOFF_S   = 30 # seconds to backoff when the limiter trips

# ---- BALANCE LOOKUP THROTTLING ----
BALANCE_RL_IP_BURST    = 15   # balance queries allowed per IP before throttling
BALANCE_RL_IP_WINDOW_S = 4   # time window (seconds) evaluated by the limiter
BALANCE_RL_BACKOFF_S   = 3   # seconds to backoff when the limiter trips

# ---- INFO SNAPSHOT THROTTLING ----
INFO_RL_IP_BURST    = 4   # GET_INFO / GET_NETWORK_INFO allowed per IP within window
INFO_RL_IP_WINDOW_S = 8   # seconds evaluated by limiter
INFO_RL_BACKOFF_S   = 5   # backoff applied when limit exceeded

# ---- HISTORY / UTXO LOOKUP THROTTLING ----
HISTORY_RL_IP_BURST    = 30   # GET_TX_HISTORY/DETAIL/GET_UTXOS burst allowance
HISTORY_RL_IP_WINDOW_S = 60   # seconds window for history limiter
HISTORY_RL_BACKOFF_S   = 3   # seconds to back off when tripped

# ---- MEMPOOL INLINE THROTTLING ----
MEMPOOL_INLINE_RL_BURST    = 15   # inline mempool dumps allowed before throttling
MEMPOOL_INLINE_RL_WINDOW_S = 20  # seconds window to evaluate inline dump rate
MEMPOOL_INLINE_RL_BACKOFF  = 10  # seconds to wait after hitting inline limiter

# ---- CHAT REGISTER/PREKEY THROTTLING ----
CHAT_REG_RL_IP_BURST       = 15   # chat register/prekey submissions allowed per IP
CHAT_REG_RL_WINDOW_S       = 30  # seconds window for chat register limiter
CHAT_REG_RL_BACKOFF_S      = 5  # cooldown after chat register limiter trips
CHAT_REG_RL_ADDR_BURST     = 10   # chat register limiter per address
CHAT_REG_RL_ADDR_WINDOW_S  = 30  # seconds window for chat register per-address limiter
CHAT_REG_RL_ADDR_BACKOFF_S = 20  # cooldown after chat register per-address limiter trips

# ---- CHAT LOOKUP THROTTLING ----
CHAT_LOOKUP_RL_IP_BURST       = 20   # lookup pubkey chat per IP
CHAT_LOOKUP_RL_IP_WINDOW_S    = 10   # jendela waktu limiter lookup pubkey
CHAT_LOOKUP_RL_BACKOFF_S      = 5    # backoff setelah limiter lookup pubkey kena
CHAT_LOOKUP_RL_ADDR_BURST     = 10   # limiter lookup pubkey per alamat
CHAT_LOOKUP_RL_ADDR_WINDOW_S  = 10 # jendela waktu limiter per alamat
CHAT_LOOKUP_RL_ADDR_BACKOFF_S = 8 # backoff setelah limiter per alamat kena

# ---- USER RPC THROTTLING ----
BLOCK_FETCH_RL_IP_BURST    = 20   # GET_BLOCK (hash/height) requests allowed per IP
BLOCK_FETCH_RL_WINDOW_S    = 5   # seconds window for block fetch limiter
BLOCK_FETCH_RL_BACKOFF_S   = 2   # backoff after block fetch limiter trips

# ---- BLOCK RANGE (WEB) ----
BLOCK_RANGE_RL_IP_BURST    = 50   # GET_BLOCK_RANGE (height) requests allowed per IP
BLOCK_RANGE_RL_WINDOW_S    = 15   # seconds window for block fetch limiter
BLOCK_RANGE_RL_BACKOFF_S   = 3   # backoff after block fetch limiter trips

TX_SUBMIT_RL_IP_BURST       = 12  # NEW_TX submissions allowed per IP before throttling
TX_SUBMIT_RL_WINDOW_S       = 6   # seconds window for tx submit limiter
TX_SUBMIT_RL_BACKOFF_S      = 6   # backoff after tx submit limiter trips
TX_SUBMIT_RL_ADDR_BURST     = 10  # per-address tx submit limiter
TX_SUBMIT_RL_ADDR_WINDOW_S  = 10  # seconds window for per-address limiter
TX_SUBMIT_RL_ADDR_BACKOFF_S = 8  # backoff after per-address limiter trips

GRAFFITI_RL_IP_BURST       = 100  # graffiti read RPC burst allowance (posts/comments/art/payouts)
GRAFFITI_RL_WINDOW_S       = 30   # seconds window for graffiti read limiter
GRAFFITI_RL_BACKOFF_S      = 3   # backoff applied on graffiti limiter hit

STOR_LIST_RL_IP_BURST      = 4   # storage listing requests allowed per IP
STOR_LIST_RL_WINDOW_S      = 10  # seconds window for storage listing limiter
STOR_LIST_RL_BACKOFF_S     = 8   # backoff after storage listing limiter trips

CHAT_RELAY_RL_IP_BURST     = 16  # chat relay hops allowed per IP
CHAT_RELAY_RL_WINDOW_S     = 6   # seconds window for chat relay limiter
CHAT_RELAY_RL_BACKOFF_S    = 4   # backoff when chat relay limiter trips

CHAT_RELAY_MAX_HOPS        = 4   # maximum hops accepted in CHAT_RELAY route
CHAT_RELAY_MAX_INNER_BYTES = 32 * 1024  # cap serialized inner payload to avoid abuse

# ---- MINER RPC THROTTLING ----
MINER_INFO_RL_IP_BURST     = 8   # GET_INFO / GET_BLOCK_HASH requests per IP
MINER_INFO_RL_WINDOW_S     = 3   # seconds window for miner info limiter
MINER_INFO_RL_BACKOFF_S    = 4   # backoff after miner info limiter trips

MINER_HEADERS_RL_IP_BURST  = 100  # GET_HEADERS bursts per IP
MINER_HEADERS_RL_WINDOW_S  = 10   # seconds window for header limiter
MINER_HEADERS_RL_BACKOFF_S = 2   # backoff after header limiter trips

MINER_BLOCKS_RL_IP_BURST   = 50  # GET_BLOCKS bursts per IP
MINER_BLOCKS_RL_WINDOW_S   = 5   # seconds window for block fetch limiter
MINER_BLOCKS_RL_BACKOFF_S  = 2   # backoff after block limiter trips

MINER_SYNC_RL_IP_BURST     = 32  # full-sync / chain bursts per IP
MINER_SYNC_RL_WINDOW_S     = 5   # seconds window for miner sync limiter
MINER_SYNC_RL_BACKOFF_S    = 3   # backoff after miner sync limiter trips

MINER_NEWBLOCK_RL_IP_BURST  = 16  # NEW_BLOCK announcements per IP
MINER_NEWBLOCK_RL_WINDOW_S  = 5   # seconds window for new block limiter
MINER_NEWBLOCK_RL_BACKOFF_S = 3   # backoff after new block limiter trips

MINER_MEMPOOL_RL_IP_BURST  = 6   # MEMPOOL sync requests per IP
MINER_MEMPOOL_RL_WINDOW_S  = 10  # seconds window for mempool limiter
MINER_MEMPOOL_RL_BACKOFF_S = 6   # backoff after mempool limiter trips

# ---- STORAGE RPC THROTTLING ----
STORAGE_RPC_RL_IP_BURST    = 30   # storage proof/payout submissions per IP
STORAGE_RPC_RL_WINDOW_S    = 60  # seconds window for storage RPC limiter
STORAGE_RPC_RL_BACKOFF_S   = 3  # backoff after storage RPC limiter trips

# ---- STORAGE SERVER (ARCHIVIST) THROTTLING ----
STOR_INIT_RL_IP_BURST      = 3   # STOR_INIT per IP burst
STOR_INIT_RL_WINDOW_S      = 20  # seconds window for init limiter
STOR_INIT_RL_BACKOFF_S     = 15  # backoff after init limiter trips

STOR_PUT_RL_IP_BURST       = 25  # STOR_PUT chunks per IP burst
STOR_PUT_RL_WINDOW_S       = 10  # seconds window for put limiter
STOR_PUT_RL_BACKOFF_S      = 10  # backoff after put limiter trips

STOR_COMMIT_RL_IP_BURST    = 6   # STOR_COMMIT per IP burst
STOR_COMMIT_RL_WINDOW_S    = 20  # seconds window for commit limiter
STOR_COMMIT_RL_BACKOFF_S   = 15  # backoff after commit limiter trips

STOR_GET_RL_IP_BURST       = 10  # STOR_GET_BY_ART per IP burst
STOR_GET_RL_WINDOW_S       = 10  # seconds window for get limiter
STOR_GET_RL_BACKOFF_S      = 10  # backoff after get limiter trips

STOR_ADMIN_RL_IP_BURST     = 8   # admin/node calls (INDEX/GC/PAID/PROOF) per IP burst
STOR_ADMIN_RL_WINDOW_S     = 20  # seconds window for admin limiter
STOR_ADMIN_RL_BACKOFF_S    = 20  # backoff after admin limiter trips

BAN_UNKNOWN_STORAGE_RPC    = 90  # temp-ban when receiving unknown STOR_* message types
STOR_POW_DIFFICULTY        = 20  # difficulty bits for PoW challenge on storage RPC

# =============================================================================
# 12. SCRIPT, GRAFFITI & STORAGE POLICY
# =============================================================================
# ---- MAGIC CONSTANTS ----
GRAFFITI_MAGIC     = b"TSAR_GRAF1|"  # domain separator for graffiti commitments
GRAFFITI_POOL_SALT = b"TSAR_GRAFFITI_POOL|"  # seed when deriving deterministic pool addresses

# ---- ART ID ----
ART_ID_PREFIX      = "graf"
ART_ID_PREFIX_LEN  = len(ART_ID_PREFIX)
ART_ID_BODY_LEN    = 60  # hex chars retained after adding prefix to keep 64 chars total

# ---- OP_RETURN POLICY ----
MAX_GRAFFITI_OPRET    = 580  # graffiti payload limit capped under script limit

# ---- GRAFFITI ----
GRAFFITI_MIN_BILLABLE_SIZE    = 1 * 1024 * 1024
GRAFFITI_UPLOAD_FEE_PER_CHUNK = 0.8 * TSAR
GRAFFITI_REPLICATION_R        = 3
GRAFFITI_COMMENT_MAX_BYTES    = 140
GRAFFITI_COMMENT_MIN_FEE      = 1 * TSAR
GRAFFITI_COMMENT_BP_DENOM     = 10_000    # denominator (basis points) for split percentages
GRAFFITI_COMMENT_CREATOR_BP   = 8_000     # 80%
GRAFFITI_COMMENT_STORAGE_BP   = 1_000     # 10% (remaining -> miners as fee tip)
GRAFFITI_EXPIRE_AFTER_BLOCKS  = 8        # default retention window after graffiti confirmed on-chain
GRAFFITI_PROOF_EPOCH_BLOCKS   = 15        # block interval between retention proofs
GRAFFITI_PROOF_EPOCH_DRIFT    = 1         # allowed epoch drift for proof/payout (future/past)
GRAFFITI_PROOF_CHUNK_BYTES    = 100 * 1024  # bytes challenged per proof (deterministic)
GRAFFITI_MAX_SIZE_BYTES       = 150 * 1024 * 1024  # hard cap for upload/download payload
GRAFFITI_MAX_MSG_BYTES        = 151 * 1024 * 1024  # per-message cap for graffiti transfer (storage RPC) STOR_INIT/STOR_PUT
GRAFFITI_ALLOWED_MIME         = ("image/jpeg", "video/mp4", "video/x-matroska", "application/pdf")  # whitelist MIME types
GRAFFITI_ALLOWED_EXT          = ("jpg", "jpeg", "mp4", "mkv", "pdf")  # extension fallback when MIME unavailable

# ---- STORAGE POLICY ----
STORAGE_UPLOAD_CHUNK          = 10 * 1024 * 1024  # chunk size used when slicing storage payloads

# ---- CONTRACT METADATA ----
CONTRACTS_DIR      = "data_json/node/Contracts"  # storage root for contract-like payloads
GRAFFITI_FILE      = os.path.join(CONTRACTS_DIR, "graffiti.json")  # graffiti metadata archive path

# ---- ARCHIVIST ----
ARCHIV_PEER_KEYS                   = "data/archivist/data_peer/storage_peer_keys.json"
STORAGE_DIR                        = "data/archivist/storage"  # folder holding uploaded storage blobs
STORAGE_SIZE_INIT                  = 100 * 1024 * 1024  # initial storage size allocation (100MB)
STORAGE_MAX_BYTES                  = 128 * 1024 * 1024 * 1024  # cap on cumulative storage usage (64GB)
RETENTION_GC_SEC                   = 3  # interval between retention garbage collection runs
ARCHIVIST_AUTO_PAYOUT_GUARD_FILE   = os.path.join(STORAGE_DIR, "payout_guard/auto_payout_guard.json")
ARCHIVIST_AUTO_PAYOUT_COOLDOWN_SEC = 135


# =============================================================================
# 13. LOGGING
# =============================================================================
# ---- BASE OUTPUT ----
LOG_SHOW_PROCESS     = False  # include process metadata in log context when True
LOG_PROC_PLACEHOLDER = "-"  # value used when process info is hidden
DEBUG_BENCHMARKS     = True  # for benchmarking needs for each computing logic/process

# ---- MODE PROFILES ----
if IS_DEV:
    # ---- DEV PROFILE ----
    LOG_LEVEL                   = "TRACE"  # very verbose logging for development
    LOG_FORMAT                  = "plain"  # plain text logs ease local debugging
    LOG_TO_CONSOLE              = False  # mirror logs to stdout for dev loops
    LOG_RATE_LIMIT_SECONDS      = 0.0  # disable console throttling in dev
    LOG_FILE_RATE_LIMIT_SECONDS = 0.0  # disable file throttling in dev
    LOG_ROTATE_MAX_BYTES        = 5_000_000  # rollover log files after ~5MB in dev
    LOG_BACKUP_COUNT            = 3  # retain a few rotated dev log files
    FILTER_REDAX                = False # sensitive area, priv_key, .etc (debuging only)
else:
    # ---- PROD PROFILE ----
    LOG_LEVEL                   = "INFO"  # balanced verbosity for production
    LOG_FORMAT                  = "json"  # JSON logs simplify ingestion in prod
    LOG_TO_CONSOLE              = False  # suppress console spam for daemons
    LOG_RATE_LIMIT_SECONDS      = 2.0  # throttle console spam in prod
    LOG_FILE_RATE_LIMIT_SECONDS = 1.0  # throttle file spam in prod
    LOG_ROTATE_MAX_BYTES        = 10_000_000  # rollover log files after ~10MB in prod
    LOG_BACKUP_COUNT            = 7  # keep more history on production nodes
    FILTER_REDAX                = True # true for prod

