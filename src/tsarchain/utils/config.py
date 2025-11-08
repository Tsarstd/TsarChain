# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: NIST-800-38D-AES-GCM

'''
=============================================================================
 -------- ⚠ CONSENSUS-CRITICAL REMINDER — READ BEFORE EDITING ⚠ --------
-----------------------------------------------------------------------------

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
   (For now, this section is not critical, because it is still under development.)
   - OPRET_MAX_BYTES, OPRET_REQUIRE_LAST, OPRET_ONLY_ONE
   - OPRET_ALLOW_PUSHDATA1, OPRET_ALLOW_PUSHDATA2
   - MAX_STORAGE_OPRET, GRAFFITI_MAGIC
   
 6) FORK-CHOICE & REORG
   - ENABLE_CHAINWORK_RULE, ENABLE_REORG_LIMIT, REORG_LIMIT
   
 NOT CONSENSUS (safety differs between nodes):
   port/BOOTSTRAP, timeout, connection limit, anti-DoS, logging/path,
   toggle NATIVE, option UI/wallet.
   
 NETWORK ISOLATION (not a fork, but cannot connect to each other):
   - DEFAULT_NET_ID / NET_ID_DEV / NET_ID_PROD, NETWORK_MAGIC

=============================================================================
'''

import os
import appdirs

# ===== Native toggle (1=ON with Rust .pyd, 0=OFF pure-Python) =====
NATIVE = 1
MERKLE_NATIVE = True

# =============================================================================
# MODE & ENV (Dev/Prod Switch)
# =============================================================================

# ===== Dev & Prod toggle =====
MODE   = "dev"   # "dev" | "prod"
IS_DEV = (MODE.lower() == "dev")

# ===== Sync Data (Block, UTXO, etc) =====
FULL_SYNC_DEV      = False
FULL_SYNC_PROD     = False


# =============================================================================
# APP / METADATA
# =============================================================================
APP_NAME            = "Kremlin"
APP_AUTHOR          = "TsarStudio"
WALLET_DATA_DIR     = appdirs.user_data_dir(APP_NAME, APP_AUTHOR)


# =============================================================================
# MONETARY / SUPPLY
# =============================================================================
TSAR                   = 100_000_000     # SAT-like unit (8 decimals)
MAX_SUPPLY             = 252_500_000 * TSAR
INITIAL_REWARD         = 250 * TSAR
BLOCKS_PER_HALVING     = 235_000
COINBASE_MATURITY      = 10
MAX_COINBASE_EXTRADATA = 100

# --- Genesis reward override ---
GENESIS_REWARD         = True           # True: use special genesis rewards, False: follow standard policies
GENESIS_REWARD_AMOUNT  = 2_500_000 * TSAR


# =============================================================================
# CONSENSUS / DIFFICULTY
# =============================================================================
INITIAL_BITS       = 0x1E00FFFF
MAX_BITS           = 0x1F0FFFFF
TARGET_BLOCK_TIME  = 37             # 37 Sec
LWMA_WINDOW        = 75             # Block's
FUTURE_DRIFT       = 600            # 10 Minute
MTP_WINDOWS        = 11             # Block's

# === Consensus Hardening ===
# CONSENSUS LIMITS (Blocks & TX)
MAX_BLOCK_BYTES         = 1_200_000        # 1,2 MB
MAX_TXS_PER_BLOCK       = 5_000
MAX_SIGOPS_PER_BLOCK    = 40_000
MAX_SIGOPS_PER_TX       = 6_000

# FORK-CHOICE & REORG
ENABLE_CHAINWORK_RULE   = True
ENABLE_REORG_LIMIT      = True
REORG_LIMIT             = 1000

# DIFF CLAMP
ENABLE_DIFF_CLAMP       = True
DIFF_CLAMP_MAX_UP       = 1.8
DIFF_CLAMP_MAX_DOWN     = 0.5

# Emergency Difficulty Adjustment (EDA)
ENABLE_EDA              = True  # False for Prod
EDA_WINDOW              = 48
EDA_TRIGGER_RATIO       = 5.0
EDA_EASE_MULTIPLIER     = 2.5


# =============================================================================
# FEES / TX POLICY
# =============================================================================
DEFAULT_FEE_RATE_SATVB = 35
MIN_FEE_RATE_SATVB     = 1
MAX_FEE_RATE_SATVB     = 10_000

TX_BASE_VBYTES         = 10
SEGWIT_INPUT_VBYTES    = 68
SEGWIT_OUTPUT_VBYTES   = 31

DUST_THRESHOLD_SAT     = 294
MAX_DECIMALS           = 8

MEMPOOL_MAX_SIZE       = 1 * 1024 * 1024   # 1 Mb


# =============================================================================
# CHAIN / IDENTITY
# =============================================================================
NET_ID_DEV      = "gulag-net"
NET_ID_PROD     = "sputnik-net" 
ADDRESS_PREFIX  = "tsar"
DEFAULT_NET_ID  = NET_ID_DEV if IS_DEV else NET_ID_PROD
NETWORK_MAGIC   = b"TSARCHAIN"
ZERO_HASH       = b"\x00" * 32
CANONICAL_SEP   = (',', ':')

# === Genesis ===
ALLOW_AUTO_GENESIS       = 1
GENESIS_HASH_HEX         = ""
GENESIS_BLOCK_ID_DEFAULT = "Every person who is born free has the same rights and dignity. (Munir Said Thalib - 2004-09-07)"

# === Voice Sovereignty Figures (ASCII only) ===
# (name, year)
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
]


# =============================================================================
# NETWORK / P2P
# =============================================================================

# === Port & Bootstrap ===
PORT_RANGE_DEV     = (38169, 38178)
PORT_RANGE_PROD    = (40196, 40205)

BOOTSTRAP_DEV      = (
    ("31.97.51.207", 38169),
)

BOOTSTRAP_PROD     = (
    ("127.0.0.1", 40197),
)

if IS_DEV:
    PORT_START, PORT_END = PORT_RANGE_DEV
    BOOTSTRAP_NODES      = BOOTSTRAP_DEV
else:
    PORT_START, PORT_END = PORT_RANGE_PROD
    BOOTSTRAP_NODES      = BOOTSTRAP_PROD

BOOTSTRAP_NODE = BOOTSTRAP_NODES[0]

# === Buffers & Timeouts ===
BUFFER_SIZE                 = 65536
HANDSHAKE_TIMEOUT           = 10
DISCOVERY_INTERVAL          = 5
SYNC_INTERVAL               = 10
FAST_SYNC_INTERVAL          = 2
SYNC_TIMEOUT                = 10
CONNECT_TIMEOUT             = 1.5
BROADCAST_FAIL_THRESHOLD    = 2
BROADCAST_FAIL_BACKOFF_S    = 120

# === Anti-DoS ===
MAX_ADDRS_PER_REQ  = 64
MAX_HISTORY_LIMIT  = 200
MAX_UTXO_ADDR_LEN  = 128

NONCE_PER_SENDER_MAX         = 4096
NONCE_GLOBAL_MAX             = 100_000     # total nonce entries of all senders

HANDSHAKE_RL_PER_IP_BURST    = 50          # max 50 handshake
HANDSHAKE_RL_PER_IP_WINDOW_S = 10          # /10 second
TEMP_BAN_SECONDS             = 30          # temporary ban

# === Full Sync guard ===
ENABLE_FULL_SYNC            = FULL_SYNC_DEV if IS_DEV else FULL_SYNC_PROD
FULL_SYNC_MAX_BLOCKS        = 75_000
FULL_SYNC_MAX_BYTES         = 75 * 1024 * 1024   # 75 MB
FULL_SYNC_MIN_INTERVAL      = 60                 # seconds per peer
FULL_SYNC_BACKOFF_INITIAL   = 120
FULL_SYNC_BACKOFF_MAX       = 600
MAX_MSG                     = FULL_SYNC_MAX_BYTES
MEMPOOL_SYNC_MIN_INTERVAL   = 60
MEMPOOL_INLINE_MAX_TX       = 600                # if the network is high, increase it to 400 - 600
MEMPOOL_FLUSH_INTERVAL      = 5.0

HEADERS_BATCH_MAX           = 4096
HEADERS_LOCATOR_DEPTH       = 64
HEADERS_FANOUT              = 32
HEADERS_SYNC_MIN_INTERVAL   = 1
BLOCK_DOWNLOAD_BATCH_MAX    = 4096
CHAIN_FLUSH_INTERVAL        = 1                   # blocks between chain persistence when not forced
CHAIN_FORCE_FULL_FLUSH      = False               # set True to force full chain persistence each save
ADD_BLOCK_LOG_THRESHOLD     = 0.1                 # seconds; log add_block metrics when slower than this

UTXO_FLUSH_INTERVAL         = 1000

MAX_OUTBOUND_PEERS          = 14
MAX_INBOUND_PEERS           = 16
MAX_INBOUND_PER_IP          = 4
PEER_SCORE_START            = 10
PEER_SCORE_FAILURE_PENALTY  = 5
PEER_SCORE_REWARD           = 1
PEER_SCORE_MIN              = -40


# =============================================================================
# P2P TRANSPORT ENCRYPTION (Node <-> Node)
# =============================================================================
P2P_ENC_REQUIRED      = True           # DEV = False, PROD = True
P2P_AEAD_KEY_BYTES    = 32             # AES-256
P2P_AEAD_NONCE_BYTES  = 12             # GCM nonce 96-bit
P2P_AEAD_AAD_PREFIX   = b"TSAR|P2P|v1" # bound to the network/version
P2P_SESSION_TTL_S     = 3600           # rekey every 1 hours
P2P_SESSION_MAX_MSG   = 10000          # or every N messages (whichever comes first)

# Interval to clear old sessions
SYNC_INFO_MIN_INTERVAL           = 60
SYNC_INFO_MIN_INTERVAL_BOOTSTRAP = 300.0

# Wallet RPC policy (plaintext envelope)
ALLOW_RPC_PLAINTEXT = False


# =============================================================================
# SECURITY / REPLAY
# =============================================================================
ENVELOPE_REQUIRED    = True
ENFORCE_HELLO_PUBKEY = True

REPLAY_WINDOW_SEC  = 60


# =============================================================================
# CHAT SECURITY
# =============================================================================
CHAT_MAX_CT_BYTES           = 2 * 1024  # ciphertext
CHAT_TS_DRIFT_S             = 120       # sec
CHAT_TTL_S                  = 86400     # 24 hours
CHAT_MAILBOX_MAX            = 250
CHAT_GLOBAL_QUEUE_MAX       = 20_000
CHAT_PULL_MAX_ITEMS         = 50
CHAT_POLL_INTERVAL_MS       = 2000      # don't set it too low below 1500, so that nodes are not flooded with pull requests
CHAT_POLL_INITIAL_MS        = 4000
CHAT_PUBLISH_MIN_INTERVAL_S = 10
CHAT_PUBLISH_SELF_CHECK     = False      # no self check ,

# === Rate limiting ===
CHAT_RL_ADDR_BURST    = 18
CHAT_RL_ADDR_WINDOWS  = 10        # per 10 second
CHAT_RL_IP_BURST      = 37
CHAT_RL_IP_WINDOWS    = 10        # per 10 second
CHAT_BACKOFF_S        = 13        # limiter rate

# === Presence relay ===
PRESENCE_RL_ADDR_BURST     = 2
PRESENCE_RL_ADDR_WINDOWS   = 10
PRESENCE_MAX_HOPS          = 3
PRESENCE_TTL_S             = 3600

# === Chat onion-lite ===
CHAT_FORCE_RELAY = False       # multi-hop , set true if many peers/node , set false if only 1 peers/node
CHAT_NUM_HOPS    = 1          # can set 1 > ... if many peers/node

CHAT_SESSION_DIR            = os.path.join("data_user", "chat_sessions")
CHAT_KEY_TTL_SEC            = 15 * 60
CHAT_PWD_CACHE_TTL_SEC      = 180           # This configuration requires the user to enter the keystore password every time it is set.
CHAT_RATCHET_MAX_SKIP       = 200
CHAT_RATCHET_INDEX_MAX      = 1_000_000
CHAT_OPK_MIN_THRESHOLD      = 5
CHAT_OPK_REFILL_COUNT       = 20
CHAT_SPK_ROTATE_INTERVAL_S  = 7 * 24 * 3600


# =============================================================================
# RPC / TIMEOUTS / CACHE
# =============================================================================
CONNECT_TIMEOUT_SCAN = 1.25
RPC_TIMEOUT          = 4.0
NODE_CACHE_TTL       = 60
WALLET_RPC_MIN_INTERVAL = 0.35


# =============================================================================
# CONSENSUS — GRAFFITI
# =============================================================================
STORAGE_MAGIC = b"TSAR_GRAF1|"
GRAFFITI_MAGIC = b"TSAR_GRAF1|"

# === SCRIPT / OP_RETURN POLICY ===
OPRET_MAX_BYTES         = 352             # >= 270B (give margin)
MAX_GRAFFITI_OPRET      = min(OPRET_MAX_BYTES, 320)
OPRET_REQUIRE_LAST      = True            # OP_RETURN must be the last output
OPRET_ONLY_ONE          = True            # hanya 1 OP_RETURN per TX
OPRET_ALLOW_PUSHDATA1   = True
OPRET_ALLOW_PUSHDATA2   = True            # required for lengths >255B

# === OP_RETURN size guards ===
MAX_STORAGE_OPRET       = 180

# === Storage gas rules ===
STORAGE_MIN_SIZE        = 100 * 1024         # bytes (min 100KB)
STORAGE_CHUNK           = 100 * 1024         # bytes per chunk (100KB)

# === Download TTL window ===
DOWNLOAD_WINDOW_BLOCKS     = 10
ALLOW_UNREGISTERED_STORAGE = True

# STORAGE (for NODE_STORAGE)
STORAGE_DIR                 = "data/storage"
STORAGE_MAX_BYTES           = 10 * 1024 * 1024 * 1024  # 10GB
STORAGE_UPLOAD_CHUNK        = STORAGE_CHUNK
STORAGE_MIN_CONFIRM         = 2
ALLOW_UNREGISTERED_STORAGE_UPLOADS = True


# =============================================================================
# PATHS / STORAGE
# =============================================================================
STATE_FILE    = "data/State/state.json"
BLOCK_FILE    = "data/Block/blockchain.json"
UTXOS_FILE    = "data/UTXOS/utxos.json"
MEMPOOL_FILE  = "data/Mempools/txpools.json"


# =============================================================================
# USER & NODE (STORAGE PATH)
# =============================================================================
# -- User (wallet)
WALLETS_DIR    = "data_user"
USER_KEY_PATH  = "data_user/user_key.json"
REGISTRY_PATH  = "data_user/wallet_registry.json"
CHAT_STATE     = "data_user/chat_config.json"

# -- Node
NODE_DATA_DIR          = "data_node"
NODE_KEY_PATH          = os.path.join(NODE_DATA_DIR, "node_key.json")
PEER_KEYS_PATH         = os.path.join(NODE_DATA_DIR, "peer_keys.json")
LEGACY_NODE_KEY_PATH   = "data_user/node_key.json"
LEGACY_PEER_KEYS_PATH  = "data_user/peer_keys.json"


# =============================================================================
# GRAFFITI / STORAGE PATHS
# =============================================================================
CONTRACTS_DIR       = "data/Contracts"
GRAFFITI_FILE       = os.path.join(CONTRACTS_DIR, "graffiti.json")
STORAGE_NODES_FILE  = os.path.join(CONTRACTS_DIR, "storage_nodes.json")


# =============================================================================
# DB / KV BACKEND
# =============================================================================
DB_DIR             = "data/DB"
KV_BACKEND         = "lmdb"   # lmdb | json
LMDB_MAP_SIZE_INIT = 64 * 1024 * 1024  # 64 MiB
LMDB_MAP_SIZE_MAX  = 64 * 1024 * 1024 * 1024  # 64 GiB
LMDB_DATA_FILE     = os.path.join(DB_DIR, "data.mdb")
LMDB_LOCK_FILE     = os.path.join(DB_DIR, "lock.mdb")

# Snapshot bootstrap (data.mdb fast-sync)
SNAPSHOT_REQUIRE_SIGNATURE   = False
SNAPSHOT_MANIFEST_URL        = ""
SNAPSHOT_FILE_URL            = ""
SNAPSHOT_PUBKEY_HEX          = ""

SNAPSHOT_BOOTSTRAP_ENABLED   = False
SNAPSHOT_BOOTSTRAP_FOR_GUI   = False
SNAPSHOT_BOOTSTRAP_FOR_CLI   = False
SNAPSHOT_HTTP_TIMEOUT        = 90
SNAPSHOT_CHUNK_BYTES         = 2 * 1024 * 1024
SNAPSHOT_MIN_SIZE_BYTES      = 4 * 1024 * 1024
SNAPSHOT_META_PATH           = os.path.join(DB_DIR, "snapshot.meta.json")
SNAPSHOT_MAX_AGE_SECONDS     = 12 * 3600
SNAPSHOT_USER_AGENT          = "TsarChainSnapshot/1.0"

# Backup
SNAPSHOT_BACKUP_DIR          = os.path.join("data", "snapshot")
BACKUP_SNAPSHOT              = True
BLOCK_BACKUP_SNAPSHOT        = 50


# =============================================================================
# LOGGING SETTINGS
# =============================================================================
LOG_PATH             = "data/logging/tsarchain.log"
LOG_SHOW_PROCESS     = False
LOG_PROC_PLACEHOLDER = "-"

# === MODE based profile ===
if IS_DEV:
    # === DEV PROFILE ===
    LOG_LEVEL = "TRACE"                # lot of details
    LOG_FORMAT = "plain"               # easy to read while developing
    LOG_TO_CONSOLE = True              # display to the console
    LOG_RATE_LIMIT_SECONDS = 0.0       # don't throttle in console while debugging
    LOG_FILE_RATE_LIMIT_SECONDS = 0.0
    LOG_ROTATE_MAX_BYTES = 5_000_000   # 5 MB
    LOG_BACKUP_COUNT     = 3
else:
    # === PROD PROFILE ===
    LOG_LEVEL = "INFO"                 # quite informative
    LOG_FORMAT = "json"                # suitable for parsing/tooling
    LOG_TO_CONSOLE = False             # daemons don't need console
    LOG_RATE_LIMIT_SECONDS = 2.0       # throttle spam console
    LOG_FILE_RATE_LIMIT_SECONDS = 1.0  # throttle spam into file
    LOG_ROTATE_MAX_BYTES = 10_000_000  # 10 MB
    LOG_BACKUP_COUNT     = 7

try:
    _LOG_BASE = "data/logging/tsarchain"
    _fmt = str(LOG_FORMAT).lower().strip()
    if _fmt == "json":
        LOG_PATH = _LOG_BASE + ".jsonl"   # JSON Lines: easier for parsers
    else:
        LOG_PATH = _LOG_BASE + ".log"
except Exception:
    # If anything goes wrong, stick to whatever LOG_PATH was before.
    pass
