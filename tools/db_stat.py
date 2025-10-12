#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import os
import sys
import argparse
import json
from bech32 import bech32_encode, convertbits
from tsarchain.utils.config import DB_DIR, ADDRESS_PREFIX

try:
    import lmdb  # type: ignore
except Exception as e:
    print("lmdb module not available. Install with: pip install lmdb")
    sys.exit(1)


def _default_db_dir() -> str:
    try:
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.append(os.path.join(here, 'src'))


        return DB_DIR
    except Exception:
        return os.path.join('data', 'DB')


SUBDBS = [
    'chain', 'state', 'utxo', 'mempool',
    'peer_keys', 'autosettle', 'stor_nodes',
    'wallet_peer_keys', 'stor_peer_keys',
]


def _count(env, name: str) -> int:
    try:
        dbi = env.open_db(name.encode('utf-8'), create=False)
    except Exception:
        return 0
    n = 0
    with env.begin(db=dbi, write=False) as txn:
        with txn.cursor() as cur:
            if cur.first():
                n = 1
                while cur.next():
                    n += 1
    return n


def _peek_keys(env, name: str, limit: int = 5):
    out = []
    try:
        dbi = env.open_db(name.encode('utf-8'), create=False)
    except Exception:
        return out
    with env.begin(db=dbi, write=False) as txn:
        with txn.cursor() as cur:
            if not cur.first():
                return out
            out.append(cur.key())
            while len(out) < limit and cur.next():
                out.append(cur.key())
    return out


def main():
    ap = argparse.ArgumentParser(description='LMDB quick stats for TsarChain.')
    ap.add_argument('--db', dest='db_dir', default=_default_db_dir(), help='LMDB directory (default: from config or data/DB)')
    ap.add_argument('--peek', dest='peek', type=int, default=3, help='Number of keys to peek per subdb')
    ap.add_argument('--detail', dest='detail', choices=['utxo','mempool','chain','state'], help='Show detailed items for a subdb')
    args = ap.parse_args()

    db_dir = args.db_dir
    if not os.path.isdir(db_dir):
        print(f"DB dir not found: {db_dir}")
        sys.exit(1)

    env = lmdb.open(db_dir, readonly=True, max_dbs=32, lock=False, subdir=True)
    print(f"DB: {db_dir}")

    # chain height via count
    n_chain = _count(env, 'chain')
    print(f"chain blocks: {n_chain}")

    # state snapshot
    try:
        state_db = env.open_db(b'state', create=False)
        with env.begin(db=state_db, write=False) as txn:
            tb = txn.get(b'k:total_blocks')
            ts = txn.get(b'k:total_supply')
            if tb or ts:
                print(f"state total_blocks: {int(tb.decode('utf-8')) if tb else 0}")
                print(f"state total_supply: {int(ts.decode('utf-8')) if ts else 0}")
    except Exception:
        pass

    # UTXO/Mempool
    n_utxo = _count(env, 'utxo')
    n_mempool = _count(env, 'mempool')
    print(f"utxo entries: {n_utxo}")
    print(f"mempool txs: {n_mempool}")

    # Optional peeks
    for name in SUBDBS:
        keys = _peek_keys(env, name, args.peek)
        if not keys:
            continue
        try:
            show = [k.decode('utf-8', 'ignore') for k in keys]
        except Exception:
            show = [str(k) for k in keys]
        print(f"{name} peek: {show}")

    # Optional detail dump
    if args.detail == 'utxo':
        try:
            dbi = env.open_db(b'utxo', create=False)
        except Exception:
            print('No utxo subdb found')
            return
        print('\n[detail:utxo]')
        cnt = 0
        with env.begin(db=dbi, write=False) as txn:
            with txn.cursor() as cur:
                if not cur.first():
                    print('empty')
                    return
                while True and cnt < max(1, int(args.peek)):
                    k = cur.key(); v = cur.value();
                    try:
                        key = k.decode('utf-8')
                        obj = json.loads(v.decode('utf-8'))
                        txo = obj.get('tx_out') or obj
                        amt = int(txo.get('amount', 0))
                        spk_hex = txo.get('script_pubkey','')
                        addr = None
                        try:
                            spk = bytes.fromhex(spk_hex)
                            if len(spk) >= 22 and spk[0] == 0x00 and spk[1] == 0x14:
                                prog = spk[2:22]
                                data = [0] + list(convertbits(prog, 8, 5, True))
                                addr = bech32_encode(ADDRESS_PREFIX, data)
                        except Exception:
                            addr = None
                        print(f"- {key} | amount: {amt} | address: {addr or 'n/a'}")
                    except Exception as e:
                        print(f"- decode error for key {k!r}: {e}")
                    cnt += 1
                    if not cur.next():
                        break


if __name__ == '__main__':
    main()
