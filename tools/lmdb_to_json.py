#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio

"""
Export LMDB sub-databases to JSON with FULL STREAMING (memory-safe).
Supports multi-domain exports with native binary decoding:
- Keys: node_secrets -> data/keys/json_output/node_secrets.json
- Node: chain, state, utxo, mempool, graffiti -> data/node/json_output/
- Archivist: index_db, payout_guard -> data/archivist/storage/json_output/
- Web: web_cache, web_media, web_blocks -> data/web/json_output/
"""

import os
import sys
import json
import lmdb
import base64
import struct

reconfig = getattr(sys.stdout, 'reconfigure', None)
if callable(reconfig):
    reconfig(encoding='utf-8', errors='replace')

from tqdm import tqdm
from typing import Any, Dict, List, Union, Optional, Tuple

# Add src to sys.path for native models
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

try:
    from tsarchain.core.block import Block
    from tsarchain.core.tx import Tx
    from tsarchain.mempool.scripts import script_to_address
    from tsarchain.contracts.graffiti_registry import (
        deserialize_post_binary,
        deserialize_comment_binary,
        deserialize_payout_binary,
        deserialize_proof_binary,
    )
    from tsarchain.network.rpc_helper.chat import decode_prekey_bundle
except ImportError:
    Block = None
    Tx = None
    script_to_address = None
    deserialize_post_binary = None
    deserialize_comment_binary = None
    deserialize_payout_binary = None
    deserialize_proof_binary = None
    decode_prekey_bundle = None

# ============================
# USER SETTINGS
# ============================
NODE_SUBDBS = ['chain', 'state', 'utxo', 'mempool', 'graffiti', 'chat_prekeys']
NODE_SUBDB_PATHS = {
    'chain': 'data/node/chain',
    'state': 'data/node/state',
    'utxo': 'data/node/utxo',
    'mempool': 'data/node/mempool',
    'graffiti': 'data/node/graffiti',
    'chat_prekeys': 'data/node/chat_prekeys',
}
KEYS_SUBDBS = ['node_secrets', 'secure_wallet', 'wallet_peer_keys', 'stor_peer_keys']
KEYS_ENV_PATH = "data/keys"
LEGACY_NODE_PATH = "data/node"

KEYS_OUTPUT_DIR = "data/keys/json_output"
NODE_OUTPUT_DIR = "data/node/json_output"
ARCHIVIST_OUTPUT_DIR = "data/archivist/storage/json_output"
WEB_OUTPUT_DIR = "data/web/json_output"

INDENT = 2                        # 'None' for smaller size but less readable.
SORT_UTXO = True

# Registry of databases operating on Pure Binary storage
BINARY_STORAGE_REGISTRY = {
    'utxo': {
        'model': 'Compact Binary Header (<Q?qH) + Raw ScriptPubkey',
        'benefit': '~80% disk reduction, instant O(log N) prefix lookups',
    },
    'chain': {
        'model': 'Binary Block (80B Header + 24B Meta + Serialized Witness Txs)',
        'benefit': '~70% disk reduction, zero-copy native parsing for IBD',
    },
    'graffiti': {
        'model': 'Granular Binary Structs (p: Posts, c: Comments, y: Payouts, r: Proofs)',
        'benefit': 'O(1) isolated record updates, prevents monolithic rewrite lag',
    },
    'mempool': {
        'model': 'Compact Binary Header (<dIII) + Binary Tx Bytes',
        'benefit': 'Microsecond memory-mapped queue persistence',
    },
    'chat_prekeys': {
        'model': 'Binary Prekey Bundle (<QB Header + IK + SPK + Sig + OPK Pool)',
        'benefit': '~60% storage reduction, zero-deserialization overhead for offline bundles',
    },
}
# ============================


def decode_key(key_bytes: bytes) -> str:
    try:
        return key_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return key_bytes.hex()


def decode_value(value_bytes: bytes) -> Union[str, Dict, List, Any]:
    try:
        text = value_bytes.decode('utf-8')
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    except UnicodeDecodeError:
        return {
            "_binary": True,
            "hex": value_bytes.hex(),
            "base64": base64.b64encode(value_bytes).decode('ascii'),
            "size": len(value_bytes)
        }


def decode_db_value(db_name: str, key_bytes: bytes, value_bytes: bytes) -> Union[str, Dict, List, Any]:
    key_str = decode_key(key_bytes)
    if key_str == '__meta__':
        try:
            return json.loads(value_bytes.decode('utf-8'))
        except Exception:
            return value_bytes.decode('utf-8', errors='replace')

    # 1. UTXO binary decoding
    if db_name == 'utxo' and len(value_bytes) >= 19 and not value_bytes.startswith(b'{'):
        try:
            amt, is_cb, height, spk_len = struct.unpack_from("<Q?qH", value_bytes, 0)
            spk_bytes = value_bytes[19:19 + spk_len]
            spk_hex = spk_bytes.hex()
            addr = script_to_address(spk_bytes) if script_to_address else None
            return {
                "amount": amt,
                "is_coinbase": bool(is_cb),
                "block_height": height,
                "script_pubkey": spk_hex,
                "address": addr,
            }
        except Exception:
            pass

    # 2. Chain binary decoding
    if db_name == 'chain' and key_str.startswith('h:'):
        if Block:
            try:
                blk = Block.from_storage_bytes(value_bytes)
                return blk.to_dict()
            except Exception:
                pass

    # 3. Mempool binary decoding
    if db_name == 'mempool' and len(value_bytes) >= 20 and not value_bytes.startswith(b'{'):
        if Tx:
            try:
                recv_at, fee, vsize, weight = struct.unpack_from("<dIII", value_bytes, 0)
                raw_tx = value_bytes[20:]
                tx_obj = Tx.from_storage_bytes(raw_tx)
                tx_dict = tx_obj.to_dict(include_txid=True)
                tx_dict["_meta"] = {
                    "received_at": recv_at,
                    "fee": fee,
                    "vbytes": vsize,
                    "weight": weight,
                }
                return tx_dict
            except Exception:
                pass

    # 4. Chat Prekeys binary decoding
    if db_name == 'chat_prekeys' and len(value_bytes) >= 9 and not value_bytes.startswith(b'{'):
        try:
            if decode_prekey_bundle:
                return decode_prekey_bundle(value_bytes)
        except Exception:
            pass

    # Fallback to standard text / json decoding
    return decode_value(value_bytes)


def stream_write_json(filepath: str, cursor, db_name: str = "") -> int:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    count = 0
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('{\n')
        first = True

        for key_bytes, value_bytes in tqdm(cursor, desc=f"Writing {os.path.basename(filepath)}", unit=" entries"):
            key_str = decode_key(key_bytes)
            val = decode_db_value(db_name, key_bytes, value_bytes)

            if not first:
                f.write(',\n')
            first = False

            key_json = json.dumps(key_str, ensure_ascii=False)
            val_json = json.dumps(val, ensure_ascii=False, default=str, indent=INDENT)
            f.write(f'  {key_json}: {val_json}')
            count += 1

            if count % 1000 == 0:
                f.flush()

        f.write('\n}\n')

    return count


def open_lmdb_env_dbi(env_path: str, db_name: Optional[str] = None) -> Tuple[Optional[lmdb.Environment], Any]:
    if not os.path.exists(env_path):
        return None, None
    try:
        env = lmdb.open(env_path, readonly=True, max_dbs=32, lock=False, subdir=os.path.isdir(env_path))
    except Exception as e:
        print(f"❌ Failed to open LMDB environment at {env_path}: {e}")
        return None, None

    dbi = None
    if db_name:
        try:
            dbi = env.open_db(db_name.encode('utf-8'), create=False)
        except lmdb.Error:
            try:
                dbi = env.open_db(None, create=False)
            except lmdb.Error:
                env.close()
                return None, None
    else:
        try:
            dbi = env.open_db(None, create=False)
        except lmdb.Error:
            env.close()
            return None, None

    return env, dbi


# ============================================================
# EXPORT MODULES
# ============================================================

def export_keys_data() -> int:
    """Exports key sub-databases (node_secrets, secure_wallet, wallet_peer_keys, stor_peer_keys) from data/keys to data/keys/json_output/."""
    print("\n🔑 --- Exporting Keys Data ---")
    os.makedirs(KEYS_OUTPUT_DIR, exist_ok=True)

    env_path = KEYS_ENV_PATH if os.path.exists(KEYS_ENV_PATH) else LEGACY_NODE_PATH
    if not os.path.exists(env_path):
        print(f"⚠️  Keys LMDB environment directory not found at '{env_path}', skipping...")
        return 0

    total_entries = 0
    for subdb in KEYS_SUBDBS:
        env, dbi = open_lmdb_env_dbi(env_path, subdb)
        if not env or dbi is None:
            continue

        output_file = os.path.join(KEYS_OUTPUT_DIR, f"{subdb}.json")
        print(f"📁 Reading '{subdb}' from {env_path}")
        with env.begin(db=dbi, write=False) as txn:
            with txn.cursor() as cursor:
                count = stream_write_json(output_file, cursor, db_name=subdb)
                print(f"   ✅ {count} entries written to {output_file}")
                total_entries += count
        env.close()

    if total_entries == 0:
        print(f"ℹ️  No populated key sub-databases found in '{env_path}'.")

    return total_entries


def sort_utxo_items(items):
    """Sort UTXO items by block_height, with __meta__ placed first."""
    meta = None
    others = []
    for k, v in items:
        if k == '__meta__':
            meta = (k, v)
        else:
            others.append((k, v))
    others.sort(key=lambda x: (x[1].get('block_height', 0) if isinstance(x[1], dict) else 0))
    if meta:
        return [meta] + others
    return others


def export_node_data() -> int:
    """Exports Node sub-databases (chain, state, utxo, mempool, graffiti) to data/node/json_output/."""
    print("\n📦 --- Exporting Node Data ---")
    os.makedirs(NODE_OUTPUT_DIR, exist_ok=True)
    total_entries = 0

    for db_name in NODE_SUBDBS:
        dedicated_path = NODE_SUBDB_PATHS.get(db_name)
        env_path = dedicated_path if (dedicated_path and os.path.exists(dedicated_path)) else LEGACY_NODE_PATH
        if not os.path.exists(env_path):
            print(f"⚠️  Environment directory for '{db_name}' not found at '{env_path}', skipping...")
            continue

        env, dbi = open_lmdb_env_dbi(env_path, db_name)
        if not env or dbi is None:
            print(f"⚠️  Sub-database '{db_name}' not found in {env_path}, skipping...")
            continue

        is_binary = db_name in BINARY_STORAGE_REGISTRY
        badge = " [BINARY ENGINE]" if is_binary else " [JSON/KV]"
        print(f"📁 Reading '{db_name}'{badge} from: {env_path}")

        # ---------- GRAFFITI (Granular Binary / Legacy Parser) ----------
        if db_name == 'graffiti':
            posts = {}
            comments = {}
            payouts = {}
            proofs = {}
            count = 0

            with env.begin(db=dbi, write=False) as txn:
                with txn.cursor() as cursor:
                    for k_bytes, v_bytes in cursor:
                        count += 1
                        try:
                            if k_bytes.startswith(b"p:") and deserialize_post_binary:
                                art_id = k_bytes[2:].decode("utf-8", errors="replace")
                                posts[art_id] = deserialize_post_binary(v_bytes, art_id)
                            elif k_bytes.startswith(b"c:") and deserialize_comment_binary:
                                parts = k_bytes[2:].decode("utf-8", errors="replace").split(":")
                                if len(parts) >= 2:
                                    comments.setdefault(parts[0], []).append(deserialize_comment_binary(v_bytes))
                            elif k_bytes.startswith(b"y:") and deserialize_payout_binary:
                                parts = k_bytes[2:].decode("utf-8", errors="replace").split(":")
                                if len(parts) >= 2:
                                    payouts.setdefault(parts[0], []).append(deserialize_payout_binary(v_bytes))
                            elif k_bytes.startswith(b"r:") and deserialize_proof_binary:
                                parts = k_bytes[2:].decode("utf-8", errors="replace").split(":")
                                if len(parts) >= 2:
                                    proofs.setdefault(parts[0], []).append(deserialize_proof_binary(v_bytes))
                        except Exception as e:
                            print(f"   ⚠️  Error decoding graffiti key {k_bytes}: {e}")

            graffiti_dir = os.path.join(NODE_OUTPUT_DIR, 'graffiti')
            os.makedirs(graffiti_dir, exist_ok=True)

            for subkey, sdata in [('posts', posts), ('comments', comments), ('payouts', payouts), ('proofs', proofs)]:
                out_file = os.path.join(graffiti_dir, f"{subkey}.json")
                with open(out_file, 'w', encoding='utf-8') as f:
                    json.dump(sdata, f, indent=INDENT, ensure_ascii=False, default=str)
                print(f"   ✅ {subkey}.json written ({len(sdata)} entries)")

            total_entries += count
            env.close()
            continue

        # ---------- STREAMING ALL OTHER NODE DBS ----------
        output_file = os.path.join(NODE_OUTPUT_DIR, f"{db_name}.json")
        with env.begin(db=dbi, write=False) as txn:
            with txn.cursor() as cursor:
                count = stream_write_json(output_file, cursor, db_name=db_name)
                print(f"   ✅ {count} entries streamed to {output_file}")
                total_entries += count

        env.close()

    # POST-PROCESS: SORT UTXO (if enabled)
    if SORT_UTXO:
        utxo_file = os.path.join(NODE_OUTPUT_DIR, "utxo.json")
        if os.path.exists(utxo_file):
            print("\n🔄 Post-processing UTXO: sorting by block_height...")
            try:
                with open(utxo_file, 'r', encoding='utf-8') as f:
                    utxo_data = json.load(f)

                if isinstance(utxo_data, dict):
                    items = list(utxo_data.items())
                    print(f"   📊 Sorting {len(items)} UTXO items...")
                    sorted_items = sort_utxo_items(items)
                    sorted_data = dict(sorted_items)
                    with open(utxo_file, 'w', encoding='utf-8') as f:
                        json.dump(sorted_data, f, indent=INDENT, ensure_ascii=False, default=str)
                    print(f"   ✅ UTXO sorted and saved back to {utxo_file}")
                    del utxo_data, items, sorted_data
                else:
                    print("   ⚠️  UTXO file is not a dict, skipping sort.")
            except Exception as e:
                print(f"   ❌ Error during UTXO sorting: {e}")

    return total_entries


def export_archivist_data() -> int:
    """Exports Archivist sub-databases (index_db, payout_guard) to data/archivist/storage/json_output/."""
    print("\n📚 --- Exporting Archivist Storage Data ---")
    os.makedirs(ARCHIVIST_OUTPUT_DIR, exist_ok=True)
    total_entries = 0

    targets = [
        ("index_db", "data/archivist/storage/index_db", "idx", "index.json"),
        ("payout_guard", "data/archivist/storage/payout_guard", "guard", "payout_guard.json"),
    ]

    for label, env_path, db_name, out_filename in targets:
        if not os.path.exists(env_path):
            print(f"⚠️  Archivist '{label}' environment directory not found at '{env_path}', skipping...")
            continue

        env, dbi = open_lmdb_env_dbi(env_path, db_name)
        if not env or dbi is None:
            print(f"⚠️  Sub-database '{db_name}' not found in {env_path}, skipping...")
            continue

        output_file = os.path.join(ARCHIVIST_OUTPUT_DIR, out_filename)
        print(f"📁 Reading '{label}' ({db_name}) from {env_path}")
        with env.begin(db=dbi, write=False) as txn:
            with txn.cursor() as cursor:
                count = stream_write_json(output_file, cursor, db_name=db_name)
                print(f"   ✅ {count} entries written to {output_file}")
                total_entries += count

        env.close()

    return total_entries


def export_web_data() -> int:
    """Exports Web LMDB data (web_cache, web_media, web_blocks) to data/web/json_output/."""
    print("\n🌐 --- Exporting Web Data ---")
    os.makedirs(WEB_OUTPUT_DIR, exist_ok=True)

    env_path = "data/web"
    if not os.path.exists(env_path):
        print(f"⚠️  Web LMDB environment directory not found at '{env_path}', skipping...")
        return 0

    web_subdbs = ['web_cache', 'web_media', 'web_blocks']
    total_entries = 0

    try:
        env = lmdb.open(env_path, readonly=True, max_dbs=32, lock=False, subdir=os.path.isdir(env_path))
    except Exception as e:
        print(f"❌ Failed to open Web LMDB at {env_path}: {e}")
        return 0

    found_any = False
    for subdb in web_subdbs:
        try:
            dbi = env.open_db(subdb.encode('utf-8'), create=False)
            output_file = os.path.join(WEB_OUTPUT_DIR, f"{subdb}.json")
            with env.begin(db=dbi, write=False) as txn:
                with txn.cursor() as cursor:
                    count = stream_write_json(output_file, cursor, db_name=subdb)
                    print(f"   ✅ {count} entries written to {output_file}")
                    total_entries += count
                    found_any = True
        except lmdb.Error:
            continue

    if not found_any:
        try:
            dbi = env.open_db(None, create=False)
            output_file = os.path.join(WEB_OUTPUT_DIR, "web.json")
            with env.begin(db=dbi, write=False) as txn:
                with txn.cursor() as cursor:
                    count = stream_write_json(output_file, cursor, db_name="web")
                    print(f"   ✅ {count} entries written to {output_file} (fallback)")
                    total_entries += count
        except lmdb.Error:
            print(f"⚠️  No readable sub-databases found in {env_path}")
            env.close()
            return 0

    env.close()
    return total_entries


# ============================================================
# MAIN ORCHESTRATION
# ============================================================

def export_lmdb():
    print("=" * 72)
    print("🚀 TSARCHAIN MULTI-DOMAIN LMDB EXPORTER & SMART BINARY DECODER")
    print("=" * 72)
    print("🛡️  ACTIVE BINARY STORAGE ENGINE REGISTER:")
    for db_name, info in BINARY_STORAGE_REGISTRY.items():
        print(f"   ⚡ [{db_name.upper():<8}] Model   : {info['model']}")
        print(f"                 Benefit : {info['benefit']}")
    print("=" * 72)

    keys_count = export_keys_data()
    node_count = export_node_data()
    archivist_count = export_archivist_data()
    web_count = export_web_data()

    total = keys_count + node_count + archivist_count + web_count
    print("\n" + "=" * 72)
    print("🔒 ALL LMDB EXPORTS & BINARY DECODING COMPLETED SUCCESSFULLY.")
    print("📊 SUMMARY OF EXPORTED ENTRIES:")
    print(f"   - Keys (secrets/wallets) : {keys_count}")
    print(f"   - Node (chain,utxo,etc)  : {node_count}")
    print(f"   - Archivist (storage)    : {archivist_count}")
    print(f"   - Web (explorer cache)   : {web_count}")
    print(f"   - Total Decoded Entries  : {total}")
    print("=" * 72)


if __name__ == '__main__':
    export_lmdb()