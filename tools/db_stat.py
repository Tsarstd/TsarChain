#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: BIP173

import os
import sys

reconfig = getattr(sys.stdout, 'reconfigure', None)
if callable(reconfig):
    reconfig(encoding='utf-8', errors='replace')

import lmdb
import struct
import argparse
import json
import math
import shutil
import colorama
import tempfile
from typing import Any
from datetime import datetime
from bech32 import bech32_encode, convertbits

# Add src to sys.path if not present
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_HERE, 'src')
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from tsarchain.utils import config as CFG
try:
    from tsarchain.contracts.graffiti_registry import (
        deserialize_post_binary,
        deserialize_comment_binary,
        deserialize_payout_binary,
        deserialize_proof_binary,
    )
except ImportError:
    deserialize_post_binary = None
    deserialize_comment_binary = None
    deserialize_payout_binary = None
    deserialize_proof_binary = None


colorama.init()
RESET  = "\033[0m"
BLUE   = "\033[34m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"
RED    = "\033[31m"
CYAN   = "\033[36m"
DIM    = "\033[2m"

def clog(message: str, color: str | None = GREEN):
    if color:
        print(f"{color}{message}{RESET}")
    else:
        print(message)

def color_text(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def _default_db_dir() -> str:
    try:
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.append(os.path.join(here, 'src'))
        return CFG.NODE_DATA_DIR
    except Exception:
        return os.path.join('data', 'node')


SUBDBS = [
    'chain', 'state', 'utxo', 'mempool', 'graffiti',
]


def _bytes_to_human(size_bytes: int) -> str:
    if size_bytes == 0:
        return "0B"
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {units[i]}"


def check_storage_health(env) -> dict:
    try:
        info = env.info()
        stats = env.stat()

        current_size = info.get('map_size', 0)
        max_size = CFG.LMDB_MAP_SIZE_MAX
        page_size = stats.get('psize', 4096)
        leaf_pages = stats.get('leaf_pages', 0)
        used_pages = page_size * leaf_pages

        usage_ratio = current_size / max_size if max_size > 0 else 0
        actual_usage_ratio = used_pages / current_size if current_size > 0 else 0

        health_status = "HEALTHY"
        warnings = []

        if usage_ratio > 0.9:
            health_status = "CRITICAL"
            warnings.append(f"Storage near maximum capacity: {usage_ratio:.1%}")
        elif usage_ratio > 0.8:
            health_status = "WARNING"
            warnings.append(f"Storage usage high: {usage_ratio:.1%}")
        elif usage_ratio > 0.7:
            health_status = "HEALTHY"
            warnings.append(f"Storage usage moderate: {usage_ratio:.1%}")

        # Check if auto-growth is still possible
        can_grow = current_size < max_size

        # Check transaction count (potential performance issue)
        txn_count = info.get('last_txnid', 0)
        if txn_count > 1000000:  # Arbitrary threshold
            warnings.append(f"High transaction count: {txn_count:,} - consider compaction")

        # Check for overflow pages (fragmentation indicator)
        overflow_pages = stats.get('overflow_pages', 0)
        if overflow_pages > 1000:
            warnings.append(f"High overflow pages: {overflow_pages:,} - database fragmentation detected")

        return {
            "status": health_status,
            "current_size_bytes": current_size,
            "current_size_human": _bytes_to_human(current_size),
            "max_size_bytes": max_size,
            "max_size_human": _bytes_to_human(max_size),
            "usage_percent": usage_ratio * 100,
            "actual_usage_percent": actual_usage_ratio * 100,
            "used_pages_bytes": used_pages,
            "used_pages_human": _bytes_to_human(used_pages),
            "can_grow": can_grow,
            "last_txn_id": txn_count,
            "page_size": page_size,
            "leaf_pages": leaf_pages,
            "branch_pages": stats.get('branch_pages', 0),
            "overflow_pages": overflow_pages,
            "warnings": warnings,
            "recommendations": _generate_recommendations(
                usage_ratio,
                can_grow,
                current_size,
                max_size,
                overflow_pages
            ),
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "error": str(e),
            "warnings": ["Health check failed"],
            "recommendations": ["Check LMDB directory permissions and integrity"],
        }


def _generate_recommendations(
    usage_ratio: float,
    can_grow: bool,
    current: int,
    max_size: int,
    overflow_pages: int,
) -> list:
    
    recommendations = []
    if usage_ratio > 0.9:
        recommendations.extend([
            "🚨 IMMEDIATE ACTION REQUIRED: Storage near maximum",
            f"Current: {_bytes_to_human(current)}, Max: {_bytes_to_human(max_size)}",
            "Options:",
            "  1. Increase LMDB_MAP_SIZE_MAX in config.py",
            "  2. Run database compaction (--compact flag)",
            "  3. Prune old data if applicable",
        ])
    elif usage_ratio > 0.8:
        recommendations.extend([
            "⚠️  Storage usage high - monitor closely",
            f"Consider increasing LMDB_MAP_SIZE_MAX from {_bytes_to_human(max_size)}",
            "Run with --compact to reclaim space",
        ])
    elif not can_grow:
        recommendations.extend([
            "📏 Storage at maximum configured size",
            "Cannot auto-grow further without config change",
        ])

    if overflow_pages > 1000:
        recommendations.append("🔧 Run compaction to reduce fragmentation from overflow pages")

    if usage_ratio < 0.3:
        recommendations.append("💚 Storage utilization is healthy")

    # Always suggest monitoring
    recommendations.append("📈 Run regularly with --health to monitor storage trends")

    return recommendations


def compact_database(db_dir: str, backup: bool = True) -> bool:
    try:
        clog(f"Starting database compaction for: {db_dir}")

        if backup:
            backup_dir = f"{db_dir}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            clog(f"Creating backup: {backup_dir}")
            shutil.copytree(db_dir, backup_dir)

        # LMDB compaction requires copy to new environment
        temp_dir = tempfile.mkdtemp(prefix="lmdb_compact_")

        try:
            # Open source environment
            src_env = lmdb.open(db_dir, readonly=True, max_dbs=32, lock=False)
            src_info = src_env.info()

            # Create destination environment with same map size
            dst_env = lmdb.open(temp_dir, map_size=src_info['map_size'], max_dbs=32)

            clog("Copying databases...")

            # Copy all databases
            for db_name in SUBDBS:
                try:
                    src_db = src_env.open_db(db_name.encode('utf-8'), create=False)

                    # Get count for progress indication
                    with src_env.begin(db=src_db, write=False) as txn:
                        stat = txn.stat()
                        count = stat['entries'] if stat else 0

                    if count > 0:
                        dst_db = dst_env.open_db(db_name.encode('utf-8'), create=True)

                        with src_env.begin(db=src_db, write=False) as src_txn:
                            with dst_env.begin(db=dst_db, write=True) as dst_txn:
                                with src_txn.cursor() as cursor:
                                    copied = 0
                                    for key, value in cursor:
                                        dst_txn.put(key, value)
                                        copied += 1
                                        if copied % 10000 == 0:  # Progress indicator
                                            clog(f"  {db_name}: {copied}/{count}")

                        clog(f"  ✅ Compacted: {db_name} ({count} entries)")
                    else:
                        clog(f"  ⏭️  Skipped: {db_name} (empty)")

                except Exception as e:
                    clog(f"  ❌ Failed: {db_name} - {e}")
                    continue

            src_env.close()
            dst_env.close()

            # Get size before and after for comparison
            original_size = sum(
                f.stat().st_size for f in os.scandir(db_dir) if f.is_file()
            )
            new_size = sum(
                f.stat().st_size for f in os.scandir(temp_dir) if f.is_file()
            )

            # Replace original with compacted version
            shutil.rmtree(db_dir)
            shutil.move(temp_dir, db_dir)

            clog("✅ Database compaction completed successfully")
            clog(
                f"📊 Size change: {_bytes_to_human(original_size)} → "
                f"{_bytes_to_human(new_size)} "
                f"({((original_size - new_size) / original_size * 100):.1f}% reduction)"
            )

            return True

        except Exception as e:
            clog(f"❌ Compaction failed: {e}")
            # Cleanup temp directory
            shutil.rmtree(temp_dir, ignore_errors=True)
            return False

    except Exception as e:
        clog(f"❌ Compaction error: {e}")
        return False


def open_subdb_env(base_dir: str, db_name: str | None = None) -> tuple[lmdb.Environment | None, Any]:
    if db_name:
        dedicated = os.path.join(base_dir, db_name)
        if os.path.isdir(dedicated) and (os.path.exists(os.path.join(dedicated, "data.mdb")) or os.path.exists(os.path.join(dedicated, "lock.mdb"))):
            try:
                env = lmdb.open(dedicated, readonly=True, max_dbs=32, lock=False, subdir=True)
                try:
                    dbi = env.open_db(db_name.encode('utf-8'), create=False)
                except lmdb.Error:
                    dbi = env.open_db(None, create=False)
                return env, dbi
            except Exception:
                pass
    try:
        env = lmdb.open(base_dir, readonly=True, max_dbs=32, lock=False, subdir=os.path.isdir(base_dir))
        if db_name:
            try:
                dbi = env.open_db(db_name.encode('utf-8'), create=False)
            except lmdb.Error:
                dbi = env.open_db(None, create=False)
        else:
            dbi = env.open_db(None, create=False)
        return env, dbi
    except Exception:
        return None, None


def _count(base_dir: str, name: str) -> int:
    env, dbi = open_subdb_env(base_dir, name)
    if not env or dbi is None:
        return 0
    n = 0
    try:
        with env.begin(db=dbi, write=False) as txn:
            with txn.cursor() as cur:
                for k, _ in cur:
                    if k != b'__meta__':
                        n += 1
    finally:
        env.close()
    return n


def _peek_keys(base_dir: str, name: str, limit: int = 5):
    out = []
    env, dbi = open_subdb_env(base_dir, name)
    if not env or dbi is None:
        return out
    try:
        with env.begin(db=dbi, write=False) as txn:
            with txn.cursor() as cur:
                for k, _ in cur:
                    out.append(k)
                    if len(out) >= limit:
                        break
    finally:
        env.close()
    return out


def _graffiti_summary(base_dir: str) -> dict | None:
    env, dbi = open_subdb_env(base_dir, "graffiti")
    if not env or dbi is None:
        return None
    try:
        posts = 0
        comments = 0
        payouts = 0
        proofs = 0
        with env.begin(db=dbi, write=False) as txn:
            with txn.cursor() as cur:
                for k, _ in cur:
                    if k.startswith(b"p:"):
                        posts += 1
                    elif k.startswith(b"c:"):
                        comments += 1
                    elif k.startswith(b"y:"):
                        payouts += 1
                    elif k.startswith(b"r:"):
                        proofs += 1
        return {"posts": posts, "comments": comments, "payouts": payouts, "proofs": proofs}
    except Exception:
        return None
    finally:
        env.close()


def _load_graffiti_registry(base_dir: str) -> dict | None:
    env, dbi = open_subdb_env(base_dir, "graffiti")
    if not env or dbi is None:
        return None
    try:
        posts = {}
        comments = {}
        payouts = {}
        proofs = {}
        with env.begin(db=dbi, write=False) as txn:
            with txn.cursor() as cur:
                for k, v in cur:
                    try:
                        if k.startswith(b"p:") and deserialize_post_binary:
                            art_id = k[2:].decode("utf-8", errors="replace")
                            posts[art_id] = deserialize_post_binary(v, art_id)
                        elif k.startswith(b"c:") and deserialize_comment_binary:
                            parts = k[2:].decode("utf-8", errors="replace").split(":")
                            if len(parts) >= 2:
                                comments.setdefault(parts[0], []).append(deserialize_comment_binary(v))
                        elif k.startswith(b"y:") and deserialize_payout_binary:
                            parts = k[2:].decode("utf-8", errors="replace").split(":")
                            if len(parts) >= 2:
                                payouts.setdefault(parts[0], []).append(deserialize_payout_binary(v))
                        elif k.startswith(b"r:") and deserialize_proof_binary:
                            parts = k[2:].decode("utf-8", errors="replace").split(":")
                            if len(parts) >= 2:
                                proofs.setdefault(parts[0], []).append(deserialize_proof_binary(v))
                    except Exception:
                        pass
        return {"posts": posts, "comments": comments, "payouts": payouts, "proofs": proofs}
    except Exception:
        return None
    finally:
        env.close()


def _render_payouts(reg: dict, limit: int = 10) -> None:
    payouts = reg.get("payouts") or {}
    total_entries = sum(len(v or []) for v in payouts.values())
    total_arts = len(payouts)
    total_amount = 0
    rows = []
    for art_id, items in payouts.items():
        for entry in items or []:
            try:
                amt = int(entry.get("amount", 0))
            except Exception:
                amt = 0
            total_amount += amt
            rows.append({
                "art_id": art_id,
                "txid": entry.get("txid"),
                "height": int(entry.get("block_height", 0) or 0),
                "amount": amt,
                "epoch": entry.get("epoch"),
            })
    rows.sort(key=lambda r: (r.get("height", 0), r.get("epoch") or -1), reverse=True)

    clog(f"payouts   : {total_entries}")
    clog(f"arts paid : {total_arts}")
    clog(f"amount sum: {total_amount}")
    if not rows:
        return
    show = rows[:max(1, limit)]
    clog("\nTop payouts (by height):")
    for r in show:
        art = (r.get("art_id") or "")[:16]
        amt = r.get("amount", 0)
        h = r.get("height", 0)
        ep = r.get("epoch")
        txid = (r.get("txid") or "")[:16]
        clog(f"- h={h} ep={ep} amt={amt} art={art} txid={txid}")


# ---- CLI core ----

def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description='LMDB quick stats and health check for TsarChain.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --health                    # Comprehensive health check
  %(prog)s --size-only                 # Quick size summary  
  %(prog)s --compact                   # Compact database (with backup)
  %(prog)s --compact --no-backup       # Compact without backup
  %(prog)s --health --detail utxo      # Health check + UTXO details
  %(prog)s --peek 5                    # Show 5 keys from each DB
        """,
    )

    ap.add_argument(
        '--db',
        dest='db_dir',
        default=_default_db_dir(),
        help='LMDB directory (default: from config or data/node)',
    )
    ap.add_argument(
        '--peek',
        dest='peek',
        type=int,
        default=3,
        help='Number of keys to peek per subdb',
    )
    ap.add_argument(
        '--detail',
        dest='detail',
        choices=['utxo', 'mempool', 'chain', 'state', 'graffiti', 'payout'],
        help='Show detailed items for a subdb',
    )

    # Health and maintenance arguments
    health_group = ap.add_argument_group('Health & Maintenance')
    health_group.add_argument(
        '--health',
        dest='health',
        action='store_true',
        help='Run comprehensive health check',
    )
    health_group.add_argument(
        '--compact',
        dest='compact',
        action='store_true',
        help='Compact database to reclaim space',
    )
    health_group.add_argument(
        '--no-backup',
        dest='no_backup',
        action='store_true',
        help='Skip backup during compaction (not recommended)',
    )
    health_group.add_argument(
        '--size-only',
        dest='size_only',
        action='store_true',
        help='Show only size information',
    )

    return ap


def run_tool(args) -> int:
    db_dir = args.db_dir

    if not os.path.isdir(db_dir):
        clog(f"DB dir not found: {db_dir}")
        return 1

    # Compact database if requested
    if getattr(args, "compact", False):
        success = compact_database(db_dir, backup=not getattr(args, "no_backup", False))
        return 0 if success else 1

    # Health check mode
    if getattr(args, "health", False):
        clog("🔍 LMDB Storage Health Check")
        clog("=" * 50)
        # Check health for main sub-databases
        for sub in SUBDBS:
            env, _ = open_subdb_env(db_dir, sub)
            if not env:
                continue
            try:
                health = check_storage_health(env)
                status_icons = {"HEALTHY": "✅", "WARNING": "⚠️", "CRITICAL": "🚨", "ERROR": "❌"}
                icon = status_icons.get(health['status'], "🔍")
                clog(f"[{sub.upper()}] {icon} Status: {health['status']} | Size: {health['current_size_human']} ({health['usage_percent']:.1f}%)")
            finally:
                env.close()
        return 0

    # Size-only mode
    if getattr(args, "size_only", False):
        total_sz = sum(f.stat().st_size for f in os.scandir(db_dir) if f.is_file())
        for sub in SUBDBS:
            subp = os.path.join(db_dir, sub)
            if os.path.isdir(subp):
                total_sz += sum(f.stat().st_size for f in os.scandir(subp) if f.is_file())
        clog(f"Total Storage: {_bytes_to_human(total_sz)}")
        return 0

    clog(f"📁 DB: {db_dir}", GREEN)
    clog("\n---------------------", RED)

    # chain height via count
    n_chain = _count(db_dir, 'chain')
    clog(f"⛓️  {color_text('chain blocks : ', CYAN)}{n_chain}")

    # state snapshot
    env_state, dbi_state = open_subdb_env(db_dir, 'state')
    if env_state and dbi_state is not None:
        try:
            with env_state.begin(db=dbi_state, write=False) as txn:
                tb = txn.get(b'k:total_blocks')
                ts = txn.get(b'k:total_supply')
                if tb or ts:
                    clog(f"📊 {color_text('total_blocks : ', CYAN)}{int(tb.decode('utf-8')) if tb else 0}")
                    clog(f"💰 {color_text('total_supply : ', CYAN)}{int(ts.decode('utf-8')) if ts else 0}")
        finally:
            env_state.close()

    # UTXO/Mempool
    n_utxo = _count(db_dir, 'utxo')
    n_mempool = _count(db_dir, 'mempool')
    clog(f"📦 {color_text('utxo entries : ', CYAN)}{n_utxo}")
    clog(f"📝 {color_text('mempool txs  : ', CYAN)}{n_mempool}")
    
    gstats = _graffiti_summary(db_dir)
    if gstats:
        clog(f"{color_text('graffiti     : ', CYAN)}{gstats.get('posts', 0)}")
        clog(f"{color_text('comments     : ', CYAN)}{gstats.get('comments', 0)}")
        clog(f"{color_text('payouts      : ', CYAN)}{gstats.get('payouts', 0)}")
        clog(f"{color_text('proofs       : ', CYAN)}{gstats.get('proofs', 0)}")

    # Optional peeks
    if getattr(args, "peek", 0) > 0:
        clog(f"\n🔍 Peeking {args.peek} keys per database:")
        for name in SUBDBS:
            keys = _peek_keys(db_dir, name, args.peek)
            if not keys:
                continue
            try:
                show = [k.decode('utf-8', 'ignore') for k in keys]
            except Exception:
                show = [str(k) for k in keys]
            clog(f"  {name}: {show}")

    # Optional detail dump
    if getattr(args, "detail", None) == 'utxo':
        env_utxo, dbi_utxo = open_subdb_env(db_dir, 'utxo')
        if not env_utxo or dbi_utxo is None:
            clog('No utxo subdb found')
            return 0
        clog(f"{color_text('\n[detail:utxo]', CYAN)}")
        cnt = 0
        try:
            with env_utxo.begin(db=dbi_utxo, write=False) as txn:
                with txn.cursor() as cur:
                    limit = max(1, int(getattr(args, "peek", 3)))
                    for k, v in cur:
                        if k == b'__meta__':
                            continue
                        try:
                            key = k.decode('utf-8')
                            if len(v) >= 19:
                                amt, is_cb, height, spk_len = struct.unpack_from("<Q?qH", v, 0)
                                spk = v[19:19 + spk_len]
                                addr = None
                                try:
                                    if len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14:
                                        prog = spk[2:22]
                                        data = [0] + list(convertbits(prog, 8, 5, True))
                                        addr = bech32_encode(CFG.ADDRESS_PREFIX, data)
                                    elif len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20:
                                        prog = spk[2:34]
                                        data = [0] + list(convertbits(prog, 8, 5, True))
                                        addr = bech32_encode(CFG.ADDRESS_PREFIX, data)
                                except Exception:
                                    addr = None
                                clog(f"- {key} | amount: {amt} | height: {height} | cb: {is_cb} | address: {addr or 'n/a'}")
                            else:
                                clog(f"- {key} | raw size: {len(v)} bytes")
                        except Exception as e:
                            clog(f"- decode error for key {k!r}: {e}")
                        cnt += 1
                        if cnt >= limit:
                            break
        finally:
            env_utxo.close()
    elif getattr(args, "detail", None) == 'graffiti':
        reg = _load_graffiti_registry(db_dir)
        if not reg:
            clog('No graffiti records found')
            return 0
        clog(f"{color_text('\n[detail:graffiti]', CYAN)}")
        posts = reg.get("posts") or {}
        comments = reg.get("comments") or {}
        payouts = reg.get("payouts") or {}
        proofs = reg.get("proofs") or {}
        clog(f"posts   : {len(posts)}")
        clog(f"comments: {sum(len(v or []) for v in comments.values())}")
        clog(f"payouts : {sum(len(v or []) for v in payouts.values())}")
        clog(f"proofs  : {sum(len(v or []) for v in proofs.values())}")
    elif getattr(args, "detail", None) == 'payout':
        reg = _load_graffiti_registry(db_dir)
        if reg is None:
            clog("No graffiti registry found")
            return 0
        clog(f"{color_text('\n[detail:payout]', CYAN)}")
        _render_payouts(reg, limit=max(1, int(getattr(args, "peek", 3) or 3)))

    return 0


def main(argv=None) -> int:
    """Entry point for non-interaktif (argparse)."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return run_tool(args)


def cli_menu() -> None:
    """Interactive CLI menu"""
    default_db = _default_db_dir()
    db_dir = default_db

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        clog("==============================================", color=CYAN)
        clog("         TsarChain LMDB Dev Toolbox   ", color=YELLOW)
        clog("==============================================", color=CYAN)
        clog(f"Current DB dir: {db_dir}", color=BLUE)
        clog("----------------------------------------------", color=RED)
        clog("1) Quick summary (height, state, utxo, mempool)")
        clog("2) Size-only")
        clog("3) Health check (detailed)")
        clog("4) Peek keys")
        clog("5) UTXO detail sample")
        clog("6) Compact database")
        clog("7) Change DB directory")
        clog("0) Exit")
        clog("----------------------------------------------", color=RED)

        choice = input("Select option: ").strip()

        # Exit
        if choice == '0':
            clog("Bye.")
            return

        # Change DB dir
        if choice == '7':
            new_dir = input(f"New DB dir [{db_dir}]: ").strip()
            if new_dir:
                db_dir = new_dir
            continue

        # Build argv based on selection
        argv = None

        if choice == '1':
            argv = ['--db', db_dir]
        elif choice == '2':
            argv = ['--db', db_dir, '--size-only']
        elif choice == '3':
            argv = ['--db', db_dir, '--health']
        elif choice == '4':
            peek = input("Peek how many keys per DB? [3]: ").strip() or "3"
            argv = ['--db', db_dir, '--peek', peek]
        elif choice == '5':
            peek = input("How many UTXOs to show? [5]: ").strip() or "5"
            argv = ['--db', db_dir, '--detail', 'utxo', '--peek', peek]
        elif choice == '6':
            clog("\nWARNING: Compaction will rewrite the DB directory.")
            yn = input("Proceed with backup before compaction? [y/N]: ").strip().lower()
            if yn.startswith('y'):
                argv = ['--db', db_dir, '--compact']
            else:
                yn2 = input("Compact WITHOUT backup (NOT recommended)? [y/N]: ").strip().lower()
                if yn2.startswith('y'):
                    argv = ['--db', db_dir, '--compact', '--no-backup']
                else:
                    clog("Compaction cancelled.")
        else:
            clog("Invalid choice.")
            input("\nPress Enter to continue...")
            continue

        if argv is not None:
            clog("\n--- Informations ---\n", color=YELLOW)
            try:
                exit_code = main(argv)
                if exit_code != 0:
                    clog(f"\nCommand finished with exit code {exit_code}")
            except KeyboardInterrupt:
                clog("\nInterrupted by user.")

        input("\nPress Enter to return to menu...")


if __name__ == '__main__':
    if len(sys.argv) == 1 or '--menu' in sys.argv:
        try:
            cli_menu()
        except KeyboardInterrupt:
            clog("\nExit.")
    else:
        raise SystemExit(main())
