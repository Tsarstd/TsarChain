#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP173

import os
import sys
import lmdb
import argparse
import json
import math
import shutil
import colorama
import tempfile
from datetime import datetime
from bech32 import bech32_encode, convertbits

from tsarchain.utils import config as CFG


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
        return CFG.DB_DIR
    except Exception:
        return os.path.join('data', 'DB')


SUBDBS = [
    'chain', 'state', 'utxo', 'mempool',
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
        help='LMDB directory (default: from config or data/DB)',
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
        choices=['utxo', 'mempool', 'chain', 'state'],
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

    env = lmdb.open(db_dir, readonly=True, max_dbs=32, lock=False, subdir=True)

    try:
        # Health check mode
        if getattr(args, "health", False):
            clog("🔍 LMDB Storage Health Check")
            clog("=" * 50)
            health = check_storage_health(env)

            status_icons = {
                "HEALTHY": "✅",
                "WARNING": "⚠️",
                "CRITICAL": "🚨",
                "ERROR": "❌",
            }
            icon = status_icons.get(health['status'], "🔍")
            clog(f"{icon} Status: {health['status']}")

            clog(f"📊 Current Size: {health['current_size_human']}")
            clog(f"📈 Max Size: {health['max_size_human']}")
            clog(f"📐 Usage: {health['usage_percent']:.1f}%")
            clog(
                f"💾 Actual Data Usage: {health['actual_usage_percent']:.1f}% "
                f"({health['used_pages_human']})"
            )
            clog(f"🔄 Can Auto-Grow: {'✅ Yes' if health['can_grow'] else '❌ No'}")

            if health['warnings']:
                clog("\n⚠️  Warnings:")
                for warning in health['warnings']:
                    clog(f"  • {warning}")

            if health['recommendations']:
                clog("\n💡 Recommendations:")
                for rec in health['recommendations']:
                    clog(f"  {rec}")

            clog("\n🔧 Technical Details:")
            clog(f"  Page Size: {health['page_size']} bytes")
            clog(f"  Leaf Pages: {health['leaf_pages']:,}")
            clog(f"  Branch Pages: {health['branch_pages']:,}")
            clog(f"  Overflow Pages: {health['overflow_pages']:,}")
            clog(f"  Last Transaction ID: {health['last_txn_id']:,}")
            return 0

        # Size-only mode
        if getattr(args, "size_only", False):
            health = check_storage_health(env)
            clog(
                f"{health['current_size_human']} / "
                f"{health['max_size_human']} "
                f"({health['usage_percent']:.1f}%)"
            )
            return 0

        # Original functionality with health indicator
        clog(f"📁 DB: {db_dir}", GREEN)

        # Quick health indicator
        health = check_storage_health(env)
        if health['status'] == 'HEALTHY':
            status_icon = "✅"
        elif health['status'] == 'WARNING':
            status_icon = "⚠️"
        else:
            status_icon = "🚨"
        clog(
            f"{status_icon} "
            f"{color_text('Storage Health ', CYAN)}: "
            f"{health['status']} "
            f"({health['usage_percent']:.1f}% used)",
            color=None,
        )
        clog(f"\n---------------------", RED)

        # chain height via count
        n_chain = _count(env, 'chain')
        clog(f"⛓️  "
             f"{color_text('chain blocks : ', CYAN)}"
             f"{n_chain}"
        )

        # state snapshot
        try:
            state_db = env.open_db(b'state', create=False)
            with env.begin(db=state_db, write=False) as txn:
                tb = txn.get(b'k:total_blocks')
                ts = txn.get(b'k:total_supply')
                if tb or ts:
                    clog(
                        f"📊 "
                        f"{color_text('total_blocks : ', CYAN)}"
                        f"{int(tb.decode('utf-8')) if tb else 0}"
                    )
                    clog(
                        f"💰 "
                        f"{color_text('total_supply : ', CYAN)}"
                        f"{int(ts.decode('utf-8')) if ts else 0}"
                    )
        except Exception:
            pass

        # UTXO/Mempool
        n_utxo = _count(env, 'utxo')
        n_mempool = _count(env, 'mempool')
        clog(f"📦 "
             f"{color_text('utxo entries : ', CYAN)}"
             f"{n_utxo}"
             
        )
        clog(f"📝 "
             f"{color_text('mempool txs  : ', CYAN)}"
             f"{n_mempool}"
        )

        # Optional peeks
        if getattr(args, "peek", 0) > 0:
            clog(f"\n🔍 Peeking {args.peek} keys per database:")
            for name in SUBDBS:
                keys = _peek_keys(env, name, args.peek)
                if not keys:
                    continue
                try:
                    show = [k.decode('utf-8', 'ignore') for k in keys]
                except Exception:
                    show = [str(k) for k in keys]
                clog(f"  {name}: {show}")

        # Optional detail dump (UTXO-focused for now)
        if getattr(args, "detail", None) == 'utxo':
            try:
                dbi = env.open_db(b'utxo', create=False)
            except Exception:
                clog('No utxo subdb found')
                return 0
            clog(f"{color_text('\n[detail:utxo]', CYAN)}")
            cnt = 0
            with env.begin(db=dbi, write=False) as txn:
                with txn.cursor() as cur:
                    if not cur.first():
                        clog('empty')
                        return 0
                    limit = max(1, int(getattr(args, "peek", 3)))
                    while True and cnt < limit:
                        k = cur.key()
                        v = cur.value()
                        try:
                            key = k.decode('utf-8')
                            obj = json.loads(v.decode('utf-8'))
                            txo = obj.get('tx_out') or obj
                            amt = int(txo.get('amount', 0))
                            spk_hex = txo.get('script_pubkey', '')
                            addr = None
                            try:
                                spk = bytes.fromhex(spk_hex)
                                if len(spk) >= 22 and spk[0] == 0x00 and spk[1] == 0x14:
                                    prog = spk[2:22]
                                    data = [0] + list(convertbits(prog, 8, 5, True))
                                    addr = bech32_encode(CFG.ADDRESS_PREFIX, data)
                            except Exception:
                                addr = None
                            clog(f"- {key} | amount: {amt} | address: {addr or 'n/a'}")
                        except Exception as e:
                            clog(f"- decode error for key {k!r}: {e}")
                        cnt += 1
                        if not cur.next():
                            break

        return 0

    finally:
        env.close()


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
