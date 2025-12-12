# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain ƒ?" see LICENSE and TRADEMARKS.md
# Refs: BIP141; BIP173

from __future__ import annotations

import argparse
import json
import secrets
import socket
import sys
import threading
import time
import multiprocessing as mp
from typing import Any, Dict, Optional

from tsarchain.contracts.storage_node.server import StorageServer
from tsarchain.contracts.storage_node.connect import RPC, NodeDirectory
from tsarchain.network.protocol import send_message, recv_message
from tsarchain.utils import config as CFG
from tsarchain.contracts import graffiti as GRAFFITI

from tsarchain.utils.tsar_logging import setup_logging, get_ctx_logger

log = get_ctx_logger("apps.cli_archivist")

HEARTBEAT_SEC = 10
REFRESH_SEC = 6
STORAGE_PORT_OFFSET = 100


def _fmt_bytes(n: Any) -> str:
    size = float(n)
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    for u in units:
        if size < 1024.0 or u == units[-1]:
            return f"{size:.2f} {u}" if u != "B" else f"{int(size)} {u}"
        size /= 1024.0


class ArchivistCLI:
    def __init__(
        self,
        *,
        address: str,
        target_node: tuple[str, int],
        refresh_sec: int = REFRESH_SEC,
    ):
        self.rpc = RPC()
        self.directory = NodeDirectory()
        try:
            self.rpc.set_address_override(address)
        except Exception as exc:
            raise RuntimeError(f"Invalid payout address: {exc}") from exc
        self.rpc.set_trusted(True)

        self._target_node = target_node
        self._refresh_sec = max(3, int(refresh_sec))

        self._server: Optional[StorageServer] = None
        self._storage_port: Optional[int] = None
        self.connected = False

        self._stop = threading.Event()
        self._refresh_lock = threading.Lock()
        self._print_lock = threading.Lock()
        self.last_info: Dict[str, Any] | None = None
        self.last_index: Dict[str, Any] | None = None
        self._pending_paid: set[str] = set()
        self._pool_data: dict[str, Dict[str, Any]] = {}
        self._last_dashboard: str = ""

    def _normalize_network_info(self, info_obj: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(info_obj, dict) or info_obj.get("error"):
            return None
        data = info_obj.get("data") if info_obj.get("type") == "NETWORK_INFO" else info_obj
        chain = data.get("chain") if isinstance(data, dict) else {}
        peers = data.get("peers") if isinstance(data, dict) else {}

        def _as_int(val: Any) -> Optional[int]:
            return int(val)

        height = _as_int(chain.get("tip_height") if isinstance(chain, dict) else None)
        if isinstance(data, dict) and height is None:
            height = _as_int(data.get("height"))
        peers_cnt = _as_int(peers.get("count") if isinstance(peers, dict) else None)
        if isinstance(data, dict) and peers_cnt is None:
            peers_cnt = _as_int(data.get("peers"))

        if height is None and peers_cnt is None:
            return None
        normalized = dict(info_obj)
        normalized["height"] = height
        normalized["peers"] = peers_cnt
        return normalized

    # ---------- bootstrap ----------
    def _launch_storage_server(self, fallback_start: Optional[int] = None) -> int:
        cand_ports: list[int] = []
        cfg_start = CFG.STORAGE_PORT_START
        cfg_end = CFG.STORAGE_PORT_END
        if cfg_start > 0 and cfg_end >= cfg_start:
            cand_ports.extend(range(cfg_start, cfg_end + 1))
        if fallback_start:
            base = max(1024, fallback_start)
            cand_ports.extend(range(base, base + 64))
        if not cand_ports:
            cand_ports.extend(range(39000, 39064))
        tried = set()
        for port in cand_ports:
            if port <= 0 or port in tried:
                continue
            tried.add(port)
            self._server = StorageServer("0.0.0.0", port, CFG.STORAGE_DIR)
            self._log(f"[storage] server listening on 0.0.0.0:{port}")
            return port
        raise RuntimeError("No free port for storage server")

    def _call_storage_local(self, payload: Dict[str, Any], timeout: float = 5.0) -> Optional[Dict[str, Any]]:
        port = self._storage_port
        if port is None:
            return None
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(("127.0.0.1", int(port)))
            send_message(s, json.dumps(payload).encode("utf-8"))
            raw = recv_message(s, timeout)
            if not raw:
                return None
            obj = json.loads(raw.decode("utf-8"))
            return obj if isinstance(obj, dict) else None

    def connect(self) -> bool:
        host, miner_port = self._target_node
        storage_port = self._storage_port
        if self._server is None or storage_port is None:
            fallback = miner_port + STORAGE_PORT_OFFSET
            storage_port = self._launch_storage_server(fallback)
            self._storage_port = storage_port

        ok = self.rpc.connect(host, miner_port, my_listen_port=storage_port)
        if not ok:
            peers = self.directory.get_nodes() or []
            for ip, p in peers:
                if self.rpc.connect(ip, p, my_listen_port=storage_port):
                    self.directory.mark_good((ip, p))
                    self._target_node = (ip, p)
                    ok = True
                    break

        if ok:
            self.directory.mark_good((host, miner_port))
            self.connected = True
            self._log(f"[connect] Connected to node {self._target_node[0]}:{self._target_node[1]}")
            return True
        self._log("[connect] Failed to connect to any node", error=True)
        return False

    # ---------- logging ----------
    def _log(self, msg: str, *, error: bool = False) -> None:
        with self._print_lock:
            prefix = "[err]" if error else "[info]"
            print(f"{prefix} {msg}")
            sys.stdout.flush()

    # ---------- rendering ----------
    def _print_dashboard(self, force: bool = False) -> None:
        info = self.last_info or {}
        idx = self.last_index or {}
        files = idx.get("files") if isinstance(idx, dict) else None
        files = files if isinstance(files, dict) else {}

        used = _fmt_bytes(idx.get("bytes_used", 0))
        file_count = len(files) if isinstance(files, dict) else 0
        peers = info.get("peers", "-") if isinstance(info, dict) else "-"
        tip = info.get("height") if isinstance(info, dict) else "-"

        header = f"Archivist CLI | tip={tip} peers={peers} files={file_count} used={used}"

        lines = [header, "-" * len(header)]
        lines.append("Files (latest 10):")
        lines.append(self._format_files_table(files))
        lines.append("Pool entries:")
        lines.append(self._format_pool_table(self._pool_data))

        buf = "\n".join(lines)
        if not force and buf == self._last_dashboard:
            return
        self._last_dashboard = buf
        with self._print_lock:
            print(buf)
            sys.stdout.flush()

    def _format_files_table(self, files: Dict[str, Any]) -> str:
        headers = ["graffiti_id", "size", "paid", "expire", "state"]
        widths = [64, 12, 6, 10, 10]
        rows: list[list[str]] = []
        for gid, meta in list(files.items())[:10]:
            art_id = str(meta.get("art_id") or gid)
            display_id = art_id[:64] if len(art_id) > 64 else art_id
            rows.append([
                display_id,
                f"{int(meta.get('size_bytes', 0)):,}",
                "yes" if meta.get("paid") else "no",
                str(meta.get("expire_at_height", "-")),
                str(meta.get("state", "-")),
            ])
        if not rows:
            return "(no file yet)"
        table = [" ".join(h.ljust(w) for h, w in zip(headers, widths))]
        for r in rows:
            table.append(" ".join(val.ljust(w) for val, w in zip(r, widths)))
        return "\n".join(table)

    def _format_pool_table(self, pool_data: Dict[str, Any]) -> str:
        if not pool_data:
            return "(pool not available)"
        headers = ["art_id", "pool", "size", "creator", "comments"]
        widths = [64, 16, 12, 64, 10]
        table = [" ".join(h.ljust(w) for h, w in zip(headers, widths))]
        for aid, entry in list(pool_data.items())[:64]:
            stats = entry.get("stats") or {}
            file_meta = entry.get("file") or {}
            creator = (entry.get("post", {}).get("creator") or "")[:64]
            pool_bal = float(stats.get("pool_balance", 0)) / float(CFG.TSAR)
            size_bytes = int(file_meta.get("size_bytes", 0))
            table.append(" ".join([
                (aid[:64]).ljust(widths[0]),
                f"{pool_bal:.8f}".ljust(widths[1]),
                f"{size_bytes:,}".ljust(widths[2]),
                creator.ljust(widths[3]),
                str(stats.get("comments", 0)).ljust(widths[4]),
            ]))
        return "\n".join(table)

    # ---------- refresh loops ----------
    def _refresh_loop(self) -> None:
        while not self._stop.is_set():
            if not self.connected:
                time.sleep(self._refresh_sec)
                continue
            try:
                self._refresh_once()
            except Exception as exc:
                self._log(f"[refresh] error: {exc}", error=True)
            time.sleep(self._refresh_sec)

    def _refresh_once(self) -> None:
        if self._refresh_lock.locked():
            return
        with self._refresh_lock:
            info = None
            idx = None
            info_ok = idx_ok = False
            try:
                raw_info = self.rpc.call({"type": "GET_NETWORK_INFO"}, timeout=4.0) or {}
                info = self._normalize_network_info(raw_info)
                info_ok = isinstance(info, dict)
            except Exception as exc:
                self._log(f"[refresh] GET_NETWORK_INFO error: {exc}", error=True)
            try:
                idx = self._call_storage_local({"type": "STOR_INDEX"}, timeout=6.0)
                idx_ok = isinstance(idx, dict)
            except Exception as exc:
                self._log(f"[refresh] STOR_INDEX error: {exc}", error=True)

            if info_ok:
                self.last_info = info
            else:
                self._handle_rpc_drop("refresh_info")
            if idx_ok:
                self.last_index = idx
                self._render_index(idx)
            else:
                self._handle_rpc_drop("refresh_index")
            if info_ok and idx_ok:
                self._print_dashboard()

    def _render_index(self, idx: Dict[str, Any]) -> None:
        files = idx.get("files", {}) if isinstance(idx, dict) else {}
        art_map_idx = idx.get("art_map") if isinstance(idx, dict) else None
        if not isinstance(files, dict):
            files = {}
        self._mark_pending_payouts(idx)
        self._refresh_pool_listing(files, art_map_idx)

    def _refresh_pool_listing(self, files: Dict[str, Any], art_map_idx: Optional[Dict[str, Any]] = None) -> None:
        rpc = getattr(self, "rpc", None)
        if not rpc:
            return
        resp = rpc.call({"type": "GRAFFITI_GET_POSTS", "limit": 500}, timeout=6.0) or {}
        posts = resp.get("posts") or []
        self._pool_data = {}
        files_by_sha: dict[str, dict] = {}
        files_by_art: dict[str, dict] = {}
        art_map = art_map_idx or {}
        for gid, meta in (files or {}).items():
            sha = str(meta.get("sha256") or "").lower()
            if sha:
                files_by_sha[sha] = {"id": gid, "meta": meta}
            art_id = str(meta.get("art_id") or "").lower()
            if art_id:
                files_by_art[art_id] = {"id": gid, "meta": meta}
        if isinstance(art_map, dict):
            for art_id, gid in art_map.items():
                if art_id in files_by_art:
                    continue
                meta = files.get(gid) if isinstance(files, dict) else None
                if isinstance(meta, dict):
                    files_by_art[str(art_id).lower()] = {"id": gid, "meta": meta}

        for art in posts:
            aid = art.get("art_id")
            sha = str(art.get("sha256") or "").lower()
            file_meta = files_by_art.get(str(aid).lower()) or files_by_sha.get(sha)
            if not (aid and file_meta):
                continue
            
            stats = art.get("stats") or {}
            self._pool_data[aid] = {"post": art, "stats": stats, "file": file_meta["meta"]}
        self._auto_mark_paid(posts, files_by_art)

    def _auto_mark_paid(self, posts: list[dict], files_by_art: dict[str, dict]) -> None:
        if not posts or not files_by_art:
            return
        marked = False
        for art in posts:
            aid = str(art.get("art_id") or "").lower()
            if not aid:
                continue
            file_entry = files_by_art.get(aid)
            if not file_entry:
                continue
            meta = file_entry.get("meta") or {}
            if meta.get("paid"):
                continue
            bh = int(art.get("block_height", 0) or 0)
            if bh <= 0:
                continue
            gid = file_entry.get("id") or aid
            txid = (art.get("txid") or "").strip()
            resp = self._call_storage_local(
                {"type": "STOR_PAID", "graffiti_id": gid, "txid": txid, "block_height": bh},
                timeout=4.0,
            )
            if isinstance(resp, dict) and resp.get("status") in ("ok", None):
                marked = True
                self._log(f"[auto-paid] {gid} (h={bh})")
        if marked:
            threading.Thread(target=self._refresh_once, name="ArchivistRefreshAuto", daemon=True).start()

    # ---------- retention / heartbeat ----------
    def _retention_loop(self) -> None:
        while not self._stop.is_set():
            if not self.connected:
                self._stop.wait(CFG.RETENTION_GC_SEC)
                continue
            
            tip = int((self.last_info or {}).get("height") or 0)
            try:
                gc_resp = self._call_storage_local({"type": "STOR_GC", "tip_height": tip}, timeout=6.0)
                idx = self._call_storage_local({"type": "STOR_INDEX"}, timeout=6.0)
                if isinstance(gc_resp, dict) and gc_resp.get("expired"):
                    self._log(f"[retention] GC removed {gc_resp.get('expired')} expired item(s)")
                if isinstance(idx, dict):
                    self.last_index = idx
                    self._run_retention_proofs(idx, tip)
                    self._mark_pending_payouts(idx)
                self._print_dashboard()
                
            except Exception as exc:
                self._log(f"[retention] error: {exc}", error=True)
            self._stop.wait(CFG.RETENTION_GC_SEC)

    def _run_retention_proofs(self, idx: Dict[str, Any], tip_height: int) -> None:
        files = idx.get("files", {}) if isinstance(idx, dict) else {}
        if not files:
            return
        epoch_target = GRAFFITI.compute_proof_epoch(tip_height)
        for gid, meta in files.items():
            if not isinstance(meta, dict):
                continue
            if not meta.get("paid") or meta.get("state") != "stored":
                continue
            last_epoch = int(meta.get("last_proof_epoch", -1))
            if last_epoch >= epoch_target:
                continue
            art_id = str(meta.get("art_id") or "").strip().lower()
            if not art_id:
                self._log(f"[proof] skip {gid[:10]} (missing art_id)")
                continue
            payload = {
                "type": "STOR_PROOF_RUN",
                "graffiti_id": gid,
                "art_id": art_id,
                "tip_height": tip_height,
            }
            resp = self._call_storage_local(payload, timeout=10.0)
            if resp is None:
                resp = self.rpc.call(payload, timeout=10.0)
            if not isinstance(resp, dict) or resp.get("status") != "ok":
                reason = (resp or {}).get("reason") if isinstance(resp, dict) else "rpc_error"
                self._log(f"[proof] {gid[:10]} failed ({reason})")
                continue
            proof_epoch = int(resp.get("epoch", epoch_target))
            offset = int(resp.get("offset", 0))
            length = int(resp.get("length", 0))
            phash = str(resp.get("hash") or "")
            seed = str(resp.get("seed") or "")
            self._log(f"[proof] {gid[:10]} epoch {proof_epoch} offset {offset} len {length}")
            if not self.connected:
                continue
            submit = {
                "type": "GRAFFITI_PROOF_SUBMIT",
                "art_id": art_id,
                "epoch": proof_epoch,
                "offset": offset,
                "length": length,
                "hash": phash,
                "height": tip_height,
                "seed": seed,
                "storer": (getattr(self.rpc, "address", "") or "").strip().lower(),
                "ts": int(time.time()),
                "nonce": secrets.token_hex(16),
            }
            ack = self.rpc.call(submit, timeout=8.0)
            if isinstance(ack, dict) and ack.get("status") == "ok":
                self._log(f"[proof] submitted epoch {proof_epoch} for {art_id[:12]}...")
            else:
                self._log(f"[proof] submit failed: {ack}")

    def _heartbeat_loop(self) -> None:
        while not self._stop.is_set():
            if not self.connected:
                self._stop.wait(HEARTBEAT_SEC)
                continue
            pong = self.rpc.call({"type": "PING"}, timeout=2.0)
            ok = isinstance(pong, dict) and pong.get("type") == "PONG"
            if ok:
                self._refresh_once()
            else:
                self._handle_rpc_drop("heartbeat")
            self._stop.wait(HEARTBEAT_SEC)

    # ---------- state helpers ----------
    def _handle_rpc_drop(self, reason: str = "") -> None:
        if not self.connected:
            return
        note = "[rpc] connection lost"
        if reason:
            note += f" ({reason})"
        self._log(note)
        self.connected = False
        if self._attempt_reconnect():
            self._log("[rpc] reconnected automatically.")
        else:
            self._log("Reconnection failed. Use 'reconnect' command.")

    def _attempt_reconnect(self) -> bool:
        target = getattr(self, "_target_node", None)
        storage_port = self._storage_port
        if not target or storage_port is None:
            return False
        
        host, miner_port = target
        ok = self.rpc.connect(host, miner_port, my_listen_port=storage_port)
        
        if ok:
            self.connected = True
            return True
        
        return False

    def _mark_pending_payouts(self, idx: Dict[str, Any]) -> None:
        files = idx.get("files", {}) if isinstance(idx, dict) else {}
        current: set[str] = set()
        for aid, meta in (files.items() if isinstance(files, dict) else []):
            if not isinstance(meta, dict):
                continue
            
            if meta.get("state") == "stored" and not meta.get("paid"):
                current.add(aid)
                if aid not in self._pending_paid:
                    size = int(meta.get("size_bytes", 0))
                    self._log(f"[payout] Pending for {aid} ({size} bytes)")
                    
            elif aid in self._pending_paid:
                self._log(f"[payout] Cleared for {aid}")
                
        self._pending_paid = current

    # ---------- commands ----------
    def _handle_claim(self, art_id: Optional[str] = None) -> None:
        if not self.connected:
            self._log("Not connected to node.", error=True)
            return
        
        if not self._pool_data:
            self._log("Pool empty.")
            return
        
        chosen_id = art_id
        if not chosen_id:
            self._print_pool_table()
            chosen_id = input("Input art_id for claim: ").strip()
            
        entry = self._pool_data.get(chosen_id)
        if not entry:
            self._log("art_id not found in pool.", error=True)
            return
        
        stats = entry.get("stats") or {}
        pool_balance = int(stats.get("pool_balance", 0))
        if pool_balance <= 0:
            return
        
        default_amt = pool_balance / CFG.TSAR
        try:
            amt_str = input(f"The number of TSAR you wish to claim (default {default_amt:.8f}): ").strip()
        except EOFError:
            amt_str = ""
        amount = default_amt if not amt_str else float(amt_str.replace(",", "."))
        amount_sats = int(amount * CFG.TSAR)
        if amount_sats <= 0 or amount_sats > pool_balance:
            self._log("Amount is invalid or exceeds balance.", error=True)
            return
        
        recipient = (getattr(self.rpc, "address", "") or "").strip().lower()
        payload = {
            "type": "GRAFFITI_BUILD_PAYOUT",
            "art_id": chosen_id,
            "recipients": [{"addr": recipient, "amount": amount_sats}],
            "epoch": stats.get("last_paid_epoch", -1) + 1,
            "broadcast": True,
            "ts": int(time.time()),
            "nonce": secrets.token_hex(16),
        }
        self._log(f"[pool] build payout art={chosen_id[:64]} amt={amount_sats} sats -> {recipient}")
        resp = self.rpc.call(payload, timeout=8.0)
        
        if isinstance(resp, dict) and resp.get("status") == "ok":
            tx = resp.get("tx") or {}
            txid = tx.get("txid") or "?"
            self._log(f"[pool] Broadcast payout tx {txid[:64]}... for {chosen_id[:64]}...")
            self._print_dashboard(force=True)
        else:
            self._log(f"Failde to claim: {resp}", error=True)

    def _print_pool_table(self) -> None:
        lines = self._format_pool_table(self._pool_data)
        with self._print_lock:
            print(lines if isinstance(lines, str) else "")
            sys.stdout.flush()

    def command_loop(self) -> None:
        self._log("Command: status | claim | pool | reconnect | quit")
        while not self._stop.is_set():
            try:
                cmd = input("archivist> ").strip()
            except (KeyboardInterrupt, EOFError):
                self._log("Closing...")
                self._stop.set()
                break
            
            if not cmd:
                continue
            
            if cmd in ("quit", "exit", "q"):
                self._stop.set()
                break
            
            if cmd in ("status", "stats"):
                self._print_dashboard(force=True)
                continue
            
            if cmd.startswith("claim"):
                parts = cmd.split()
                art = parts[1] if len(parts) > 1 else None
                self._handle_claim(art)
                continue
            
            if cmd in ("pool", "list"):
                self._print_pool_table()
                continue
            
            if cmd in ("reconnect", "retry"):
                if self._attempt_reconnect():
                    self._log("Reconnected.")
                    self.connected = True
                    self._refresh_once()
                else:
                    self._log("Reconnection failed.", error=True)
                continue
            
            self._log("Unknown command. Use: status | claim | pool | reconnect | quit")

    # ---------- lifecycle ----------
    def start(self) -> None:
        if not self.connect():
            return
        # start loops
        threading.Thread(target=self._refresh_loop, name="ArchivistRefresh", daemon=True).start()
        threading.Thread(target=self._retention_loop, name="ArchivistRetention", daemon=True).start()
        threading.Thread(target=self._heartbeat_loop, name="ArchivistHeartbeat", daemon=True).start()
        self._print_dashboard(force=True)
        self.command_loop()

    def stop(self) -> None:
        self._stop.set()
        self.connected = False
        self.rpc.node = None
        self._pending_paid.clear()
        self._pool_data.clear()
        self._log("Shutdown complete.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TsarChain Archivist CLI (headless)")
    parser.add_argument("--address", help="Payout storage Address(tsar1...)")
    parser.add_argument("--host", help="Target node host", default=None)
    parser.add_argument("--port", type=int, help="Target node port", default=None)
    parser.add_argument("--refresh", type=int, help="Interval refresh status (second)", default=REFRESH_SEC)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    address = (args.address or "").strip()
    if not address:
        try:
            address = input("Input payout address (tsar1...): ").strip()
        except EOFError:
            address = ""
    if not address or not address.lower().startswith(CFG.ADDRESS_PREFIX):
        print("Payout address must be filled in and start with the correct prefix. (tsar1...).")
        sys.exit(2)

    host = args.host or CFG.BOOTSTRAP_NODE[0]
    port = args.port or CFG.BOOTSTRAP_NODE[1]

    cli = ArchivistCLI(address=address, target_node=(host, int(port)), refresh_sec=args.refresh)
    try:
        cli.start()
    finally:
        cli.stop()


if __name__ == "__main__":
    mp.freeze_support()
    setup_logging(force=True)
    main()
