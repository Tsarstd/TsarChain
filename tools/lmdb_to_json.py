#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio

"""
Export LMDB sub-databases to JSON with FULL STREAMING (memory-safe).
- All sub-databases (chain, state, utxo, mempool, graffiti) exported with streaming, without loading entire DB into memory.
"""

import os
import sys
import json
import lmdb
import base64

from tqdm import tqdm
from typing import Any, Dict, List, Union

# ============================
# USER SETTINGS
# ============================
SUBDBS = ['chain', 'state', 'utxo', 'mempool', 'graffiti']
PATH = "data/node"
OUTPUT_DIR = "data/node/json_output"
INDENT = 2                        # 'None' for smaller size but less readable.

# Set to True ONLY if you had enough RAM to load the entire UTXO into memory (2GB+ for 1M+ UTXOs)
# and you really need the order by block_height.
SORT_UTXO = True
# ============================

os.makedirs(OUTPUT_DIR, exist_ok=True)

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


def sort_utxo_items(items):
    """Sort UTXO items by block_height, with __meta__ placed first."""
    meta = None
    others = []
    for k, v in items:
        if k == '__meta__':
            meta = (k, v)
        else:
            others.append((k, v))
    others.sort(key=lambda x: x[1].get('block_height', 0))
    if meta:
        return [meta] + others
    return others


def stream_write_json(filepath, cursor, show_progress=True):
    count = 0
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('{\n')
        first = True

        for key_bytes, value_bytes in tqdm(cursor, desc=f"Writing {os.path.basename(filepath)}", unit=" entries"):
            key_str = decode_key(key_bytes)
            val = decode_value(value_bytes)

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


def export_lmdb():
    print(f"📁 Reading LMDB from: {PATH}")
    if not os.path.isdir(PATH):
        print(f"❌ LMDB directory not found: {PATH}")
        sys.exit(1)

    env = lmdb.open(PATH, readonly=True, max_dbs=32, lock=False, subdir=True)
    total_entries = 0

    for db_name in SUBDBS:
        try:
            dbi = env.open_db(db_name.encode('utf-8'), create=False)
        except lmdb.BadRslotError:
            print(f"⚠️  Sub-database '{db_name}' not found, skip...")
            continue

        print(f"\n📖 Reading sub-database: {db_name}")

        # ---------- GRAFFITI ----------
        if db_name == 'graffiti':
            with env.begin(db=dbi, write=False) as txn:
                with txn.cursor() as cursor:
                    db_data = {}
                    for key_bytes, value_bytes in cursor:
                        key_str = decode_key(key_bytes)
                        val = decode_value(value_bytes)
                        db_data[key_str] = val

            graffiti_content = db_data.get('data:data')
            if graffiti_content is None and len(db_data) == 1:
                graffiti_content = next(iter(db_data.values()))

            if graffiti_content is not None and isinstance(graffiti_content, dict):
                sub_keys = ['posts', 'comments', 'payouts', 'proofs']
                if any(k in graffiti_content for k in sub_keys):
                    graffiti_dir = os.path.join(OUTPUT_DIR, 'graffiti')
                    os.makedirs(graffiti_dir, exist_ok=True)

                    for subkey in sub_keys:
                        data = graffiti_content.get(subkey, {})
                        out_file = os.path.join(graffiti_dir, f"{subkey}.json")
                        with open(out_file, 'w', encoding='utf-8') as f:
                            json.dump(data, f, indent=INDENT, ensure_ascii=False, default=str)
                        entry_count = len(data) if isinstance(data, dict) else 0
                        print(f"   ✅ {subkey}.json written ({entry_count} entries)")
                    total_entries += 1
                    continue
                else:
                    print("   ⚠️  Graffiti data doesn't contain expected keys, fallback to single file")
            else:
                print("   ⚠️  Graffiti 'data:data' key not found, fallback to single file")

            # Fallback: if no graffiti activities in database
            output_file = os.path.join(OUTPUT_DIR, f"{db_name}.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(db_data, f, indent=INDENT, ensure_ascii=False, default=str)
            print(f"   ✅ {len(db_data)} entries written to {output_file} (fallback)")
            total_entries += len(db_data)
            continue

        # ---------- STREAMING ALL (chain, state, utxo, mempool) ----------
        output_file = os.path.join(OUTPUT_DIR, f"{db_name}.json")
        with env.begin(db=dbi, write=False) as txn:
            with txn.cursor() as cursor:
                count = stream_write_json(output_file, cursor, show_progress=True)
                print(f"   ✅ {count} entries streamed to {output_file}")
                total_entries += count

    env.close()
    print(f"\n🔒 LMDB closed. Total entries streamed: {total_entries}")

    # ============================================================
    # POST-PROCESS: SORT UTXO (if enabled)
    # ============================================================
    if SORT_UTXO:
        utxo_file = os.path.join(OUTPUT_DIR, "utxo.json")
        if os.path.exists(utxo_file):
            print("\n🔄 Post-processing UTXO: sorting by block_height...")
            try:
                with open(utxo_file, 'r', encoding='utf-8') as f:
                    utxo_data = json.load(f)

                if not isinstance(utxo_data, dict):
                    print("   ⚠️  UTXO file is not a dict, skipping sort.")
                else:
                    items = list(utxo_data.items())
                    print(f"   📊 Sorting {len(items)} UTXO items...")
                    sorted_items = sort_utxo_items(items)

                    # Rewrite utxo with sorted items
                    sorted_data = dict(sorted_items)
                    with open(utxo_file, 'w', encoding='utf-8') as f:
                        json.dump(sorted_data, f, indent=INDENT, ensure_ascii=False, default=str)

                    print(f"   ✅ UTXO sorted and saved back to {utxo_file}")

                    # Memory cleanup
                    del utxo_data
                    del items
                    del sorted_data

            except json.JSONDecodeError as e:
                print(f"   ❌ Error reading UTXO JSON: {e}. Sorting skipped.")
            except MemoryError:
                print("   ❌ MemoryError: UTXO file too large to sort in memory. Consider using external sort or increasing RAM.")
            except Exception as e:
                print(f"   ❌ Unexpected error during UTXO sorting: {e}")
        else:
            print("\n⚠️  UTXO file not found, skipping post-processing sort.")
    else:
        print("\n⏩ UTXO sorting is disabled.")

    print(f"\n💾 All done. Output directory: {OUTPUT_DIR}")


if __name__ == '__main__':
    export_lmdb()