# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md
# Refs: NIST-800-38D-AES-GCM

'''
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
   - OPRET_MAX_BYTES, OPRET_REQUIRE_LAST, OPRET_ONLY_ONE
   - OPRET_ALLOW_PUSHDATA1, OPRET_ALLOW_PUSHDATA2
   - MAX_STORAGE_OPRET, GRAFFITI_MAGIC

  6) FORK-CHOICE & REORG
   - ENABLE_CHAINWORK_RULE, ENABLE_REORG_LIMIT, REORG_LIMIT

NOT CONSENSUS (safety differs between nodes):
   port/BOOTSTRAP, timeout, connection limit, anti-DoS, logging/path,
   option UI/wallet.

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

# ---- SYNC OVERRIDES ----
FULL_SYNC_DEV  = False  # opt-in full sync flag for development builds
FULL_SYNC_PROD = False  # opt-in full sync flag for production deployments

# ---- APP METADATA ----
APP_NAME        = "Kremlin"  # display name used for user data directories
APP_AUTHOR      = "TsarStudio"  # vendor string passed into platform dir helpers
WALLET_DATA_DIR = appdirs.user_data_dir(APP_NAME, APP_AUTHOR)  # OS-specific wallet folder resolved via appdirs


# =============================================================================
# 2. FILESYSTEM LAYOUT
# =============================================================================
# ---- CORE STATE FILES ----
STATE_FILE   = "data/State/state.json"  # serialized node state snapshot
BLOCK_FILE   = "data/Block/blockchain.json"  # block archive used before DB bootstrap
UTXOS_FILE   = "data/UTXOS/utxos.json"  # fallback UTXO dump for light tooling
MEMPOOL_FILE = "data/Mempools/txpools.json"  # persistent mempool cache file

# ---- WALLET FILES ----
WALLETS_DIR   = "data_user"  # root folder for local wallet assets
USER_KEY_PATH = "data_user/user_key.json"  # default user keypair location
REGISTRY_PATH = "data_user/wallet_registry.json"  # registry of created wallets
CHAT_STATE    = "data_user/chat_config.json"  # cached chat preferences and pointers

# ---- NODE KEYS ----
NODE_DATA_DIR         = "data_node"  # root folder for node-specific secrets
NODE_KEY_PATH         = os.path.join(NODE_DATA_DIR, "node_key.json")  # primary node identity key storage path
PEER_KEYS_PATH        = os.path.join(NODE_DATA_DIR, "peer_keys.json")  # known peer key cache linked to node_data
LEGACY_NODE_KEY_PATH  = "data_user/node_key.json"  # backward-compatible node key path for migration
LEGACY_PEER_KEYS_PATH = "data_user/peer_keys.json"  # legacy peer key cache kept for upgrade smoothness

# ---- CONTRACT STORAGE ----
CONTRACTS_DIR      = "data/Contracts"  # storage root for contract-like payloads
GRAFFITI_FILE      = os.path.join(CONTRACTS_DIR, "graffiti.json")  # graffiti metadata archive path
STORAGE_NODES_FILE = os.path.join(CONTRACTS_DIR, "storage_nodes.json")  # known storage provider registry


# =============================================================================
# 3. CHAIN IDENTITY & GENESIS
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
ALLOW_AUTO_GENESIS       = 0  # enable (1) or disable (0) automatic genesis construction
GENESIS_HASH_HEX         = "00000097434976000f41af4d492f549160c86485bd06d28609ea9c393ce9f06a"  # reference hash of committed genesis block
GENESIS_BLOCK_ID_DEFAULT = "Every person who is born free has the same rights and dignity. (Munir Said Thalib - 2004-09-07)"  # default human-readable genesis identifier
# ascii-only tribute list embedded within genesis metadata

# ---- BLOCK ID LIST ----
VOICE_SOVEREIGNTY_FIGURES = [
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
]  # public figures remembered inside special ops


# =============================================================================
# 4. MONETARY POLICY
# =============================================================================
# ---- UNIT CONSTANTS ----
TSAR = 100_000_000  # atomic unit (8 decimals) equivalent to satoshis

# ---- EMISSION SCHEDULE ----
MAX_SUPPLY             = 252_500_000 * TSAR  # hard cap on total minted supply
INITIAL_REWARD         = 250 * TSAR  # block subsidy at height zero
BLOCKS_PER_HALVING     = 235_000  # interval before subsidy halves
COINBASE_MATURITY      = 10  # required confirmations before spending coinbase
MAX_COINBASE_EXTRADATA = 100  # soft limit for coinbase metadata bytes

# ---- GENESIS BONUSES ----
GENESIS_REWARD        = True  # toggle to allow special-case payouts at genesis
GENESIS_REWARD_AMOUNT = 2_500_000 * TSAR  # allocation granted when genesis reward is enabled


# =============================================================================
# 5. CONSENSUS & DIFFICULTY
# =============================================================================
# ---- BASE DIFFICULTY ----
INITIAL_BITS      = 0x1E00FFFF  # starting difficulty bits assigned to block zero
MAX_BITS          = 0x1F0FFFFF  # cap for easiest allowed difficulty
TARGET_BLOCK_TIME = 37  # aim for ~37 seconds block cadence
LWMA_WINDOW       = 75  # block count considered by LWMA difficulty algo
FUTURE_DRIFT      = 600  # max seconds a block timestamp may lead wall clock
MTP_WINDOWS       = 11  # number of blocks in median time past calculation

# ---- BLOCK & TX LIMITS ----
MAX_BLOCK_BYTES      = 1_200_000  # block size limit (approx 1.2 MB)
MAX_TXS_PER_BLOCK    = 5_000  # guardrail on number of tx per block
MAX_SIGOPS_PER_BLOCK = 40_000  # signature operation ceiling per block
MAX_SIGOPS_PER_TX    = 6_000  # signature operation ceiling per transaction

# ---- FORK CHOICE ----
ENABLE_CHAINWORK_RULE = True  # enforce cumulative chainwork comparison for forks
ENABLE_REORG_LIMIT    = True  # enable reorg depth bounding
REORG_LIMIT           = 1000  # maximum blocks allowed for automatic reorg

# ---- DIFF CLAMP ----
ENABLE_DIFF_CLAMP   = True  # clamp difficulty adjustments to damp volatility
DIFF_CLAMP_MAX_UP   = 1.8  # ratio cap for upward difficulty moves
DIFF_CLAMP_MAX_DOWN = 0.5  # ratio floor for downward difficulty moves

# ---- EMERGENCY DIFFICULTY ----
ENABLE_EDA          = True  # emergency difficulty adjustment switch (often off on prod)
EDA_WINDOW          = 48  # number of blocks observed by EDA
EDA_TRIGGER_RATIO   = 5.0  # slowdown ratio that triggers EDA easing
EDA_EASE_MULTIPLIER = 2.5  # difficulty divisor applied when EDA fires


# =============================================================================
# 6. TRANSACTION FEES & MEMPOOL
# =============================================================================
# ---- FEE POLICY ----
DEFAULT_FEE_RATE_SATVB = 35  # wallet default feerate in sat/vbyte
MIN_FEE_RATE_SATVB     = 1  # allowed minimum feerate floor
MAX_FEE_RATE_SATVB     = 10_000  # safety cap to avoid absurd fees

# ---- WEIGHT ESTIMATES ----
TX_BASE_VBYTES       = 10  # serialized tx overhead used for projections
SEGWIT_INPUT_VBYTES  = 68  # assumed weight of a P2WPKH input
SEGWIT_OUTPUT_VBYTES = 31  # assumed weight of a P2WPKH output
DUST_THRESHOLD_SAT   = 294  # outputs smaller than this are treated as dust
MAX_DECIMALS         = 8  # UI precision for wallet rendering

# ---- MEMPOOL LIMITS ----
MEMPOOL_MAX_SIZE = 1 * 1024 * 1024  # maximum in-memory mempool footprint (bytes)


# =============================================================================
# 7. NETWORK & SYNC
# =============================================================================
# ---- PORTS & BOOTSTRAP ----
PORT_RANGE_DEV  = (38169, 38178)  # port span reserved for dev deployments
PORT_RANGE_PROD = (40196, 40205)  # port span reserved for production nodes

BOOTSTRAP_DEV = (
    ("127.0.0.1", 38169),
) # loopback bootstrap peers for development

BOOTSTRAP_PROD = (
    ("127.0.0.1", 40197),
) # loopback bootstrap peers for production

if IS_DEV:
    PORT_START, PORT_END = PORT_RANGE_DEV  # active listening range for dev mode
    BOOTSTRAP_NODES      = BOOTSTRAP_DEV  # list of seed peers for dev mode
else:
    PORT_START, PORT_END = PORT_RANGE_PROD  # active listening range for prod mode
    BOOTSTRAP_NODES      = BOOTSTRAP_PROD  # list of seed peers for prod mode
BOOTSTRAP_NODE           = BOOTSTRAP_NODES[0]  # preferred bootstrap peer entry

# ---- SOCKET DEFAULTS ----
BUFFER_SIZE              = 65536  # socket buffer size for P2P reads
HANDSHAKE_TIMEOUT        = 10  # seconds allowed to finish handshake
DISCOVERY_INTERVAL       = 5  # seconds between peer discovery scans
SYNC_INTERVAL            = 10  # seconds between standard sync pulls
FAST_SYNC_INTERVAL       = 2  # seconds between fast-sync loops
SYNC_TIMEOUT             = 10  # seconds before abandoning slow sync requests
CONNECT_TIMEOUT          = 1.5  # TCP dial timeout per peer attempt
BROADCAST_FAIL_THRESHOLD = 2  # consecutive failures before backing off broadcasting
BROADCAST_FAIL_BACKOFF_S = 120  # seconds to wait when broadcast keeps failing

# ---- ANTI-DOS LIMITS ----
MAX_ADDRS_PER_REQ            = 64  # max addresses accepted per addr message
MAX_HISTORY_LIMIT            = 200  # cap on stored addr history per peer
MAX_UTXO_ADDR_LEN            = 128  # sanity limit for UTXO address strings
NONCE_PER_SENDER_MAX         = 4096  # per-sender nonce cache bound
NONCE_GLOBAL_MAX             = 100_000  # global nonce cache bound across senders
HANDSHAKE_RL_PER_IP_BURST    = 50  # burst limit when rate-limiting handshakes
HANDSHAKE_RL_PER_IP_WINDOW_S = 10  # time window for handshake rate limit
TEMP_BAN_SECONDS             = 30  # duration for temporary ban entries

# ---- FULL SYNC GUARD ----
ENABLE_FULL_SYNC          = FULL_SYNC_DEV if IS_DEV else FULL_SYNC_PROD  # controls whether expensive full sync is allowed
FULL_SYNC_MAX_BLOCKS      = 75_000  # cap on blocks served per full-sync round
FULL_SYNC_MIN_INTERVAL    = 60  # seconds a peer must wait between full-sync requests
FULL_SYNC_BACKOFF_INITIAL = 120  # starting backoff between full sync retries
FULL_SYNC_BACKOFF_MAX     = 600  # maximum backoff delay between full sync retries
MAX_MSG                   = 75 * 1024 * 1024  # upper bound for inbound message payloads
MEMPOOL_SYNC_MIN_INTERVAL = 60  # seconds between mempool sync batches
MEMPOOL_INLINE_MAX_TX     = 600  # tx count allowed inline before streaming
MEMPOOL_FLUSH_INTERVAL    = 5.0  # seconds between mempool flush to disk

# ---- SYNC WINDOWS ----
HEADERS_BATCH_MAX         = 4096  # number of headers requested per batch
HEADERS_LOCATOR_DEPTH     = 64  # entries kept in locator list when syncing
HEADERS_FANOUT            = 32  # peers to fan out header requests to
HEADERS_SYNC_MIN_INTERVAL = 1  # seconds between header sync loops
BLOCK_DOWNLOAD_BATCH_MAX  = 4096  # concurrent block download cap
CHAIN_FLUSH_INTERVAL      = 1  # blocks between lightweight chain persistence
CHAIN_FORCE_FULL_FLUSH    = False  # force full persistence on every save when True
ADD_BLOCK_LOG_THRESHOLD   = 0.1  # log add_block timings slower than this (seconds)
UTXO_FLUSH_INTERVAL       = 1000  # block interval between UTXO set flushes

# ---- PEER QUOTAS ----
MAX_OUTBOUND_PEERS         = 14  # outbound connection ceiling
MAX_INBOUND_PEERS          = 16  # inbound connection ceiling
MAX_INBOUND_PER_IP         = 4  # inbound peers allowed per IP
PEER_SCORE_START           = 10  # initial trust score assigned to new peers
PEER_SCORE_FAILURE_PENALTY = 5  # decrements applied on failure events
PEER_SCORE_REWARD          = 1  # increments applied on good behavior
PEER_SCORE_MIN             = -40  # floor value before dropping the peer


# =============================================================================
# 8. SECURITY & CRYPTOGRAPHY
# =============================================================================
# ---- P2P ENCRYPTION ----
P2P_ENC_REQUIRED     = True  # enforce AEAD encryption for all node links
P2P_AEAD_KEY_BYTES   = 32  # key size used for AES-256-GCM sessions
P2P_AEAD_NONCE_BYTES = 12  # nonce size for GCM packets
P2P_AEAD_AAD_PREFIX  = b"TSAR|P2P|v1"  # additional data binding network id/version
P2P_SESSION_TTL_S    = 3600  # seconds before rekeying P2P session
P2P_SESSION_MAX_MSG  = 10000  # message count before forcing new keys

# ---- SYNC INFO CADENCE ----
SYNC_INFO_MIN_INTERVAL           = 60  # seconds between sync-info gossip messages
SYNC_INFO_MIN_INTERVAL_BOOTSTRAP = 300.0  # slower sync-info rate for bootstrap node

# ---- RPC ENVELOPE POLICY ----
ALLOW_RPC_PLAINTEXT = False  # disable plaintext wallet RPC envelopes unless explicitly allowed

# ---- REPLAY GUARDS ----
ENVELOPE_REQUIRED    = True  # require message envelopes for replay protection
ENFORCE_HELLO_PUBKEY = True  # reject peers that omit long-term pubkeys
REPLAY_WINDOW_SEC    = 60  # Acceptable skew window for anti-replay stamps


# =============================================================================
# 9. CHAT & PRESENCE
# =============================================================================
# ---- CHAT PAYLOAD LIMITS ----
CHAT_MAX_CT_BYTES     = 2 * 1024  # ciphertext size cap per chat message
CHAT_TS_DRIFT_S       = 120  # tolerated timestamp drift for chat payloads
CHAT_TTL_S            = 86400  # chat retention window (seconds)
CHAT_MAILBOX_MAX      = 250  # messages kept per recipient mailbox
CHAT_GLOBAL_QUEUE_MAX = 20_000  # max pending chat messages globally
CHAT_PULL_MAX_ITEMS   = 50  # entries returned per chat pull request

# ---- CHAT POLLING ----
CHAT_POLL_INTERVAL_MS       = 2000  # default polling interval for chat client
CHAT_POLL_INITIAL_MS        = 4000  # initial backoff before first poll
CHAT_PUBLISH_MIN_INTERVAL_S = 10  # throttle between chat publish attempts
CHAT_PUBLISH_SELF_CHECK     = False  # skip self-loopback validation by default

# ---- CHAT RATE LIMITS ----
CHAT_RL_ADDR_BURST   = 18  # per-address burst allowance for chat msgs
CHAT_RL_ADDR_WINDOWS = 10  # seconds over which per-address burst is evaluated
CHAT_RL_IP_BURST     = 37  # per-IP burst allowance for chat msgs
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
CHAT_SPK_ROTATE_INTERVAL_S = 7 * 24 * 3600  # seconds between signed pre-key rotations


# =============================================================================
# 10. RPC & CACHE
# =============================================================================
# ---- RPC TIMEOUTS ----
CONNECT_TIMEOUT_SCAN = 1.25  # timeout for quick port scanning during discovery
RPC_TIMEOUT          = 4.0  # wallet RPC request timeout in seconds

# ---- CLIENT THROTTLING ----
NODE_CACHE_TTL          = 60  # seconds cached node metadata stays valid
WALLET_RPC_MIN_INTERVAL = 0.35  # minimum spacing between wallet RPC calls


# =============================================================================
# 11. SCRIPT, GRAFFITI & STORAGE POLICY
# =============================================================================
# ---- MAGIC CONSTANTS ----
STORAGE_MAGIC  = b"TSAR_GRAF1|"  # domain separator for storage commitments
GRAFFITI_MAGIC = b"TSAR_GRAF1|"  # domain separator for graffiti commitments

# ---- OP_RETURN POLICY ----
OPRET_MAX_BYTES       = 352  # OP_RETURN payload ceiling (bytes)
MAX_GRAFFITI_OPRET    = min(OPRET_MAX_BYTES, 320)  # graffiti payload limit capped under script limit
OPRET_REQUIRE_LAST    = True  # enforce OP_RETURN as final output
OPRET_ONLY_ONE        = True  # restrict transactions to a single OP_RETURN
OPRET_ALLOW_PUSHDATA1 = True  # allow PUSHDATA1 opcodes inside OP_RETURN handler
OPRET_ALLOW_PUSHDATA2 = True  # allow PUSHDATA2 opcodes for >255B payloads

# ---- STORAGE POLICY ----
MAX_STORAGE_OPRET          = 180  # storage proof payload bound for OP_RETURN
STORAGE_MIN_SIZE           = 100 * 1024  # minimum bytes required for storage contracts
STORAGE_UPLOAD_CHUNK       = 100 * 1024  # chunk size used when slicing storage payloads
DOWNLOAD_WINDOW_BLOCKS     = 10  # number of blocks allowed for data retrieval window
ALLOW_UNREGISTERED_STORAGE = True  # toggle to accept storage downloads from unregistered nodes

# ---- STORAGE PATHS ----
STORAGE_DIR                        = "data/storage"  # folder holding uploaded storage blobs
STORAGE_MAX_BYTES                  = 10 * 1024 * 1024 * 1024  # cap on cumulative storage usage (10GB)
STORAGE_MIN_CONFIRM                = 2  # confirmations required before serving stored data
ALLOW_UNREGISTERED_STORAGE_UPLOADS = True  # permit uploads from nodes without registry entries


# =============================================================================
# 12. DATABASE & SNAPSHOTS
# =============================================================================
# ---- KV BACKEND ----
DB_DIR             = "data/DB"  # LMDB root folder
KV_BACKEND         = "lmdb"  # active key-value backend implementation
LMDB_MAP_SIZE_INIT = 64 * 1024 * 1024  # initial LMDB map size (64 MiB)
LMDB_MAP_SIZE_MAX  = 64 * 1024 * 1024 * 1024  # upper LMDB map cap (64 GiB)
LMDB_DATA_FILE     = os.path.join(DB_DIR, "data.mdb")  # main LMDB data file path
LMDB_LOCK_FILE     = os.path.join(DB_DIR, "lock.mdb")  # LMDB lock file path

# ---- SNAPSHOT SIGNING ----
SNAPSHOT_REQUIRE_SIGNATURE = False  # demand signed snapshot manifests when True
SNAPSHOT_MANIFEST_URL      = ""  # optional URL supplying snapshot manifest
SNAPSHOT_FILE_URL          = ""  # optional URL for snapshot binary
SNAPSHOT_PUBKEY_HEX        = ""  # hex-encoded pubkey used to verify snapshot signature

# ---- SNAPSHOT MODES ----
SNAPSHOT_BOOTSTRAP_ENABLED = False  # allow nodes to bootstrap via snapshot downloads
SNAPSHOT_BOOTSTRAP_FOR_GUI = False  # enable snapshot bootstrap path for GUI clients
SNAPSHOT_BOOTSTRAP_FOR_CLI = False  # enable snapshot bootstrap path for CLI clients

# ---- SNAPSHOT TRANSFER ----
SNAPSHOT_HTTP_TIMEOUT    = 90  # HTTP timeout applied to snapshot downloads
SNAPSHOT_CHUNK_BYTES     = 2 * 1024 * 1024  # chunk size when streaming snapshot data
SNAPSHOT_MIN_SIZE_BYTES  = 4 * 1024 * 1024  # ignore snapshot files smaller than this
SNAPSHOT_META_PATH       = os.path.join(DB_DIR, "snapshot.meta.json")  # cached metadata file for snapshots
SNAPSHOT_MAX_AGE_SECONDS = 12 * 3600  # maximum tolerated snapshot age (12h)
SNAPSHOT_USER_AGENT      = "TsarChainSnapshot/1.0"  # UA string used when fetching snapshots

# ---- SNAPSHOT BACKUP ----
SNAPSHOT_BACKUP_DIR   = os.path.join("data", "snapshot")  # folder storing backup snapshots
BACKUP_SNAPSHOT       = False  # toggle to keep automatic backup copies
BLOCK_BACKUP_SNAPSHOT = 50  # interval in blocks between snapshot backups


# =============================================================================
# 13. LOGGING
# =============================================================================
# ---- BASE OUTPUT ----
LOG_PATH             = "data/logging/tsarchain.log"  # canonical log file path before format-specific override
LOG_SHOW_PROCESS     = False  # include process metadata in log context when True
LOG_PROC_PLACEHOLDER = "-"  # value used when process info is hidden

# ---- MODE PROFILES ----
if IS_DEV:
    # ---- DEV PROFILE ----
    LOG_LEVEL                   = "TRACE"  # very verbose logging for development
    LOG_FORMAT                  = "plain"  # plain text logs ease local debugging
    LOG_TO_CONSOLE              = True  # mirror logs to stdout for dev loops
    LOG_RATE_LIMIT_SECONDS      = 0.0  # disable console throttling in dev
    LOG_FILE_RATE_LIMIT_SECONDS = 0.0  # disable file throttling in dev
    LOG_ROTATE_MAX_BYTES        = 5_000_000  # rollover log files after ~5MB in dev
    LOG_BACKUP_COUNT            = 3  # retain a few rotated dev log files
else:
    # ---- PROD PROFILE ----
    LOG_LEVEL                   = "INFO"  # balanced verbosity for production
    LOG_FORMAT                  = "json"  # JSON logs simplify ingestion in prod
    LOG_TO_CONSOLE              = False  # suppress console spam for daemons
    LOG_RATE_LIMIT_SECONDS      = 2.0  # throttle console spam in prod
    LOG_FILE_RATE_LIMIT_SECONDS = 1.0  # throttle file spam in prod
    LOG_ROTATE_MAX_BYTES        = 10_000_000  # rollover log files after ~10MB in prod
    LOG_BACKUP_COUNT            = 7  # keep more history on production nodes
    
# ---- LOG PATH NORMALIZATION ----
try:
    _LOG_BASE = "data/logging/tsarchain"  # base path used to pick extension
    _fmt      = str(LOG_FORMAT).lower().strip()  # normalized log format string
    
    if _fmt == "json":
        LOG_PATH = _LOG_BASE + ".jsonl"  # JSON lines extension to aid parsing
    else:
        LOG_PATH = _LOG_BASE + ".log"  # plain-text log extension fallback
except Exception:
    pass  # swallow errors so logging still works with existing path

