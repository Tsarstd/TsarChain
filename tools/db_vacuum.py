#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md
"""
Vacuum/compact TsarChain LMDB environment by creating a compacted copy.

Usage examples:
  - Copy-compact to a new folder:
      python tools/db_vacuum.py --src data/DB --dst data/DB_vacuum

  - Compact in place (backup old dir, replace with compact copy):
      python tools/db_vacuum.py --apply

Notes:
  - Stop node/wallet processes that use the DB before applying replacement.
  - Copying (without --apply) is safe with node running, but in-place
    replacement requires DB not in use.
"""
import os
import sys
import time
import argparse

try:
    import lmdb  # type: ignore
except Exception:
    print("lmdb module not available. Install with: pip install lmdb")
    sys.exit(1)


def _sum_dir_bytes(path: str) -> int:
    total = 0
    try:
        for name in os.listdir(path):
            p = os.path.join(path, name)
            if os.path.isfile(p):
                try:
                    total += os.path.getsize(p)
                except Exception:
                    pass
    except Exception:
        pass
    return total


def _default_src() -> str:
    # Try read from config
    try:
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.append(os.path.join(here, 'src'))
        from tsarchain.utils.config import DB_DIR  # type: ignore
        return DB_DIR
    except Exception:
        return os.path.join('data', 'DB')


def compact_copy(src: str, dst: str, overwrite: bool = False) -> None:
    if not os.path.isdir(src):
        raise FileNotFoundError(f"src dir not found: {src}")
    if os.path.exists(dst):
        if not overwrite:
            raise FileExistsError(f"dst exists: {dst} (use --force to overwrite)")
        # ensure empty
        for f in os.listdir(dst):
            p = os.path.join(dst, f)
            try:
                if os.path.isdir(p):
                    continue
                os.remove(p)
            except Exception:
                pass
    else:
        os.makedirs(dst, exist_ok=True)

    # Open source env read-only and perform compact copy
    env = lmdb.open(src, readonly=True, max_dbs=64, lock=False, subdir=True)
    env.copy(dst, compact=True)


def apply_inplace(src: str, tmp_dst: str) -> str:
    """Rename dst over src; backup original dir.
    Returns backup path.
    """
    ts = time.strftime('%Y%m%d-%H%M%S')
    backup = src.rstrip('/\\') + f".bak-{ts}"

    # Rename src -> backup, then dst -> src
    os.replace(src, backup)
    os.replace(tmp_dst, src)
    return backup


def main():
    ap = argparse.ArgumentParser(description='Compact (vacuum) TsarChain LMDB environment.')
    ap.add_argument('--src', default=_default_src(), help='Source LMDB dir (default from config)')
    ap.add_argument('--dst', help='Destination LMDB dir for compacted copy (default: <src>_vacuum)')
    ap.add_argument('--force', action='store_true', help='Overwrite destination if exists')
    ap.add_argument('--apply', action='store_true', help='Replace src with compact copy (stops requiring idle DB)')
    args = ap.parse_args()

    src = os.path.abspath(args.src)
    dst = os.path.abspath(args.dst or (src.rstrip('/\\') + '_vacuum'))

    before = _sum_dir_bytes(src)
    print(f"[vacuum] src: {src}")
    print(f"[vacuum] dst: {dst}")
    print(f"[vacuum] src size: {before/1024/1024:.2f} MiB")

    try:
        compact_copy(src, dst, overwrite=args.force)
    except Exception as e:
        print(f"[vacuum] copy error: {e}")
        sys.exit(2)

    after = _sum_dir_bytes(dst)
    print(f"[vacuum] dst size: {after/1024/1024:.2f} MiB")

    if args.apply:
        print("[vacuum] Applying compact copy in place...")
        try:
            backup = apply_inplace(src, dst)
            print(f"[vacuum] Done. Backup at: {backup}")
        except Exception as e:
            print(f"[vacuum] apply error: {e}")
            sys.exit(3)
    else:
        print("[vacuum] Copy-only complete. Review dst and optionally rerun with --apply to replace.")


if __name__ == '__main__':
    main()

