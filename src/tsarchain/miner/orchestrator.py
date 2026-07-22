import re
import time
import errno
import signal
import threading
import multiprocessing as mp
from datetime import datetime

# ---------------- Local Project ----------------
from ..utils import config as CFG
from ..network.node import Network
from ..consensus.blockchain import Blockchain
from ..utils.bootstrap import maybe_bootstrap_snapshot

from .cosmetic import interface as COL
from .cosmetic.thread_check import get_thread_monitor, register_thread_monitoring_signal

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.miner.orchestrator")

INTERRUPTED_ERRNOS = {
    code
    for code in (
        getattr(errno, "EINTR", None),
        getattr(errno, "WSAEINTR", None),
    )
    if code is not None
}

ADDRESS_PATTERN = re.compile(r"^tsar1[0-9a-z]{20,120}$")

def _stamp() -> str:
    now = datetime.now()
    d = f"{now.year:04d}.{now.month:02d}.{now.day:02d}"
    t = f"{now.hour:02d}.{now.minute:02d}.{now.second:02d}"
    return f"{COL.BOLD}{COL.GREY} {d} {COL.RESET}{COL.BOLD}{COL.GREY} {t} {COL.RESET}"

_clog_func = None

def set_clog_func(func):
    global _clog_func
    _clog_func = func

def clog(message: str, color: str = COL.GREY):
    if _clog_func:
        _clog_func(message, color)
    else:
        print(f"{_stamp()} : {color}{message}{COL.RESET}")

def _enable_siginterrupt():
    for sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if sig is None:
            continue
        try:
            signal.siginterrupt(sig, False)
        except Exception:
            pass

def _register_bootstrap_peers(network: Network) -> int:
    fallback_nodes = tuple(CFG.BOOTSTRAP_NODES or (CFG.BOOTSTRAP_NODE,))
    count = 0
    is_self = getattr(network, "_is_self_bootstrap", None)

    for peer in fallback_nodes:
        if not peer or len(peer) != 2:
            continue
        host, port = peer
        host_s, port_i = str(host), int(port)
        if callable(is_self) and is_self(host_s, port_i):
            continue
        
        peer_tuple = (host_s, port_i)
        network.persistent_peers.add(peer_tuple)
        network.peers.add(peer_tuple)
        count += 1

    return count

def _run_snapshot_bootstrap(enabled: bool):
    if not enabled:
        return None

    def _printer(message: str):
        clog(f"[Bootstrap] {message}")

    result = maybe_bootstrap_snapshot(progress_cb=_printer)
    if result.status == "failed":
        clog(f"[Bootstrap] Snapshot bootstrap Failed: {result.reason}. Continuing with normal sync.")
    elif result.status == "skipped":
        clog(f"[Bootstrap] Snapshot bootstrap Skipped: {result.reason}")
    elif result.status == "installed":
        clog("[Bootstrap] Finished Instaling Snapshot")
    else:
        reason = result.reason
        clog(f"[Bootstrap] : {reason}")
    return result

class SimpleMiner:
    def __init__(
        self,
        address: str,
        cores: int,
        bootstrap_snapshot: bool = True,
        *,
        progress_queue: "mp.Queue | None" = None,
    ):
        self.address = address
        self.cores = cores
        self.bootstrap_snapshot = bootstrap_snapshot
        self.mining_alive = True
        self.cancel_mining = mp.Event()
        self.blockchain = None
        self.network = None
        self._progress_q: mp.Queue = progress_queue or mp.Queue()
        self.tui = None
        self._pending_blocks: list = []
        self._pending_block_hashes: set[str] = set()
        self._trusted_height_cache: int = -1
        self._last_trusted_probe: float = 0.0
        self._bootstrap_self_only: bool | None = None
        self._last_trusted_hash: str | None = None
        
        self.thread_monitor = get_thread_monitor()
        register_thread_monitoring_signal()

        signal.signal(signal.SIGTERM, self.signal_handler)
        
        def _sigint_with_report(signum, frame):
            try:
                self.signal_handler(signum, frame)
            finally:
                self.thread_monitor.print_thread_report(detailed=True)

        signal.signal(signal.SIGINT, _sigint_with_report)
        
        _enable_siginterrupt()

    def signal_handler(self, signum, _frame):
        clog(f"Received signal {signum}, shutting down...")
        self.mining_alive = False
        if self.cancel_mining:
            self.cancel_mining.set()

    def validate_address(self):
        if not self.address:
            clog("Error: Address is required (tsar1...).")
            return False
        addr = self.address.strip().lower()
        if not ADDRESS_PATTERN.match(addr):
            clog("Error: Address must start with 'tsar1' and contain only lowercase base32 chars (length 24-124).")
            return False
        self.address = addr
        return True

    def _queue_block_for_broadcast(self, block) -> None:
        hx = block.hash().hex()
        if hx and hx in self._pending_block_hashes:
            return
        self._pending_blocks.append(block)
        if hx:
            self._pending_block_hashes.add(hx)
        while len(self._pending_blocks) > 5:
            old = self._pending_blocks.pop(0)
            try:
                self._pending_block_hashes.discard(old.hash().hex())
            except Exception:
                log.exception("error_6")

    def _flush_pending_blocks(self) -> None:
        if not self.network or not self._pending_blocks:
            return
        remaining = []
        for blk in self._pending_blocks:
            try:
                sent = self.network.publish_block(blk, exclude=None, force=True)
                if sent and sent > 0:
                    try:
                        self._pending_block_hashes.discard(blk.hash().hex())
                    except Exception:
                        log.exception("error_7")
                    continue
            except Exception as exc:
                clog(f"[broadcast] retry failed: {exc}")
            remaining.append(blk)
        self._pending_blocks = remaining

    def _has_active_peers(self) -> bool:
        if not self.network:
            return False
        inbound = getattr(self.network, "inbound_peers", None) or set()
        outbound = getattr(self.network, "outbound_peers", None) or set()
        return bool(inbound or outbound)

    def _bootstrap_seeds(self) -> list[tuple[str, int]]:
        seeds = []
        raw = tuple(CFG.BOOTSTRAP_NODES or (CFG.BOOTSTRAP_NODE,))
        for peer in raw:
            if not peer or len(peer) != 2:
                continue
            host, port = peer
            seeds.append((str(host), int(port)))
        return seeds

    def _bootstrap_is_self_only(self) -> bool:
        if self._bootstrap_self_only is not None:
            return self._bootstrap_self_only
        seeds = self._bootstrap_seeds()
        if not seeds or not self.network:
            self._bootstrap_self_only = False
            return False
        self._bootstrap_self_only = all(
            getattr(self.network, "_is_self_bootstrap", lambda h, p: False)(h, p) for h, p in seeds
        )
        return bool(self._bootstrap_self_only)

    def _get_local_tip(self) -> tuple[int, str | None]:
        h = int(getattr(self.blockchain, "height", -1))
        hx = None
        tip = self.blockchain.get_last_block() if self.blockchain else None
        if tip:
            hx = tip.hash().hex()
        return h, hx

    def _mine_block_runner(self, result: dict):
        """
        Run a single mine_block call in a worker thread so the main loop
        stays responsive to Ctrl+C and can flip cancel_mining immediately.
        """
        blk = self.blockchain.mine_block(
            miner_address=self.address,
            use_cores=self.cores,
            cancel_event=self.cancel_mining,
            pow_backend="randomx",
            progress_queue=self._progress_q,
        )
        result["block"] = blk

    def _trusted_best_height(self, force_refresh: bool = False) -> int:
        """
        Return best height seen from bootstrap peers (trusted seeds).
        Falls back to cached value unless forced or cache is stale.
        """
        if not self.network:
            return -1
        now = time.time()
        if (not force_refresh) and (now - self._last_trusted_probe < 5.0):
            return self._trusted_height_cache
        seeds = self._bootstrap_seeds()
        peers = list(getattr(self.network, "persistent_peers", ())) or []
        if seeds:
            peers = seeds
        heights: list[int] = []

        # Use recorded best heights first
        best_map = getattr(self.network, "_peer_best_height", {}) or {}
        for peer in peers:
            h = int(best_map.get(peer, -1))
            if h >= 0:
                heights.append(h)

        # Self-bootstrap fallback: trust local height if all seeds are self
        if self._bootstrap_is_self_only():
            local_h = int(getattr(self.blockchain, "height", -1))
            if local_h >= 0:
                best = local_h
                self._trusted_height_cache = best
                self._last_trusted_probe = now
                # cache local tip hash
                tip = self.blockchain.get_last_block()
                self._last_trusted_hash = tip.hash().hex() if tip else None
                return best

        # If nothing recorded, query seeds directly
        if not heights:
            for peer in peers:
                info = self.network.rpc_request(peer, {"type": "GET_INFO"}, timeout=max(8.0, CFG.SYNC_TIMEOUT))
                if not info:
                    continue
                h = int(info.get("height", -1))
                if h >= 0:
                    best_map[peer] = h  # keep network state aware of trusted height
                    self.network._peer_best_height[peer] = h
                    heights.append(h)

        best = max(heights) if heights else -1
        self._trusted_height_cache = best
        self._last_trusted_probe = now
        return best

    def _trusted_tip_hash(self, height: int) -> str | None:
        if height < 0 or not self.network:
            return None
        if self._bootstrap_is_self_only():
            return self._get_local_tip()[1]
        seeds = self._bootstrap_seeds()
        if not seeds:
            return None
        peer = seeds[0]
        resp = self.network.rpc_request(
            peer, {"type": "GET_BLOCK_HASH", "height": int(height)}, timeout=max(8.0, CFG.SYNC_TIMEOUT)
        )
        if resp and resp.get("type") == "BLOCK":
            hx = resp.get("hash")
            if isinstance(hx, str) and hx:
                return hx.lower()
        return None

    def start_node(self):
        try:
            _run_snapshot_bootstrap(self.bootstrap_snapshot)
            self.blockchain = Blockchain(
                use_cores=self.cores,
                miner_address=self.address,
            )
            self.network = Network(blockchain=self.blockchain)
            peer_count = _register_bootstrap_peers(self.network)
            clog(f"Node started with {peer_count} bootstrap peers")
            return True
        except Exception as exc:
            log.exception("error")
            clog(f"Failed to start node: {exc}")
            return False

    def wait_for_sync(self, timeout=560):
        clog("Waiting for blockchain sync...")
        start_time = time.time()
        last_progress = (-1, -1, -1)

        while self.mining_alive and (time.time() - start_time) < timeout:
            try:
                height = int(getattr(self.blockchain, "height", -1))

                trusted_height = self._trusted_best_height(force_refresh=True)
                trusted_hash = self._trusted_tip_hash(trusted_height) if trusted_height >= 0 else None
                best_height = -1
                if hasattr(self.network, "get_best_peer_height"):
                    best_height = int(self.network.get_best_peer_height())

                active_peers = self._has_active_peers()
                if not active_peers and not self._bootstrap_is_self_only():
                    clog("[Sync] Waiting for peer connection...")
                    time.sleep(3)
                    continue

                if self.network.peers:
                    self.network.request_sync(fast=True)

                best_known = trusted_height if trusted_height >= 0 else best_height
                local_h, local_hash = self._get_local_tip()
                if (
                    best_known >= 0
                    and local_h >= best_known
                    and (trusted_hash is None or (local_hash and local_hash.lower() == trusted_hash))
                ):
                    clog(f"Chain synced to height {local_h} (trusted tip {best_known})")
                    return True
                if trusted_hash and local_hash and local_hash.lower() != trusted_hash:
                    clog("[Sync] Local tip hash differs from trusted; requesting resync...")
                    if self.network:
                        seeds = self._bootstrap_seeds()
                        peer = seeds[0] if seeds else None
                        if peer:
                            self.network.request_full_sync(peer, force=True)
                        self.network.request_sync(fast=True)
                    time.sleep(2)
                    continue

                progress = (height, best_known, trusted_height)
                if best_known >= 0 and progress != last_progress:
                    tip_label = trusted_height if trusted_height >= 0 else best_known
                    clog(f"Sync progress - local {height}, trusted best {tip_label}")
                    last_progress = progress
                time.sleep(2)
            except Exception as exc:
                clog(f"Sync error: {exc}")
                time.sleep(2)

        clog("Sync timeout or interrupted")
        return False

    def start_mining(self, timeout=560):
        if not self.validate_address():
            return False
        
        self.thread_monitor.start_monitoring()
        clog("Thread monitoring started")
        
        if not self.start_node():
            return False
        if not self.wait_for_sync(timeout=timeout):
            return False
        
        clog(f"{COL.BOLD}{COL.BG_WHITE} Press {COL.RESET}{COL.BOLD}{COL.BG_RED} Ctrl+C {COL.RESET}{COL.BG_WHITE}{COL.BOLD}{COL.ORANGE} to stop mining {COL.RESET}")

        if getattr(self.blockchain, "height", -1) < 0:
            created = self.blockchain.ensure_genesis(self.address, use_cores=self.cores)
            if created:
                clog("Genesis block created")
            else:
                clog("Failed to create genesis block")
                return False

        # Mulai loop mining
        last_gap_log = None
        while self.mining_alive:
            try:
                if not self._has_active_peers() and not self._bootstrap_is_self_only():
                    if last_gap_log != "no_peers":
                        clog("[mining] No active peers; pausing mining until peers are back.")
                        last_gap_log = "no_peers"
                    time.sleep(2)
                    continue

                local_height = int(getattr(self.blockchain, "height", -1))

                trusted_height = self._trusted_best_height(force_refresh=True)
                trusted_hash = self._trusted_tip_hash(trusted_height) if trusted_height >= 0 else None
                _, local_hash = self._get_local_tip()
                if trusted_height < 0:
                    if last_gap_log != "no_trusted":
                        clog("[mining] Waiting for trusted bootstrap height before mining...")
                        last_gap_log = "no_trusted"
                    if self.network:
                        self.network.request_sync(fast=True)
                    time.sleep(2)
                    continue

                gap = trusted_height - local_height
                if gap > 0:
                    if last_gap_log != gap:
                        clog(f"[mining] Local height {local_height} behind trusted {trusted_height} (gap {gap}); syncing before mining...")
                        last_gap_log = gap
                    if self.network:
                        self.network.request_sync(fast=True)
                    time.sleep(2)
                    continue
                if trusted_hash and local_hash and local_hash.lower() != trusted_hash:
                    if last_gap_log != "hash_mismatch":
                        clog("[mining] Local tip hash differs from trusted; syncing before mining...")
                        last_gap_log = "hash_mismatch"
                    if self.network:
                        seeds = self._bootstrap_seeds()
                        peer = seeds[0] if seeds else None
                        if peer:
                            self.network.request_full_sync(peer, force=True)
                        self.network.request_sync(fast=True)
                    time.sleep(2)
                    continue

                last_gap_log = None
                self._flush_pending_blocks()
                if self.network.peers:
                    self.network.request_sync(fast=True)

                result_holder: dict = {}
                mine_thread = threading.Thread(
                    target=self._mine_block_runner,
                    args=(result_holder,),
                    name="MineBlockWorker",
                    daemon=True,
                )
                mine_thread.start()

                cancel_logged = False
                while mine_thread.is_alive() and self.mining_alive:
                    mine_thread.join(timeout=0.5)
                    if self.cancel_mining.is_set() and not cancel_logged:
                        clog("[mining] Cancellation requested; waiting for miner thread to stop...")
                        cancel_logged = True

                if mine_thread.is_alive():
                    mine_thread.join(timeout=2.0)

                block = result_holder.get("block")
                exc = result_holder.get("exc")
                if exc:
                    raise exc

                if not self.mining_alive or self.cancel_mining.is_set():
                    break

                if block:
                    if self.tui is not None:
                        self.tui.note_block_mined(getattr(block, "height", None))

                    h = getattr(block, "height", "?")
                    txs = getattr(block, "transactions", None) or []
                    confirmed = max(len(txs) - 1, 0)
                    clog(
                        f"Block mined at height {h}: {block.hash().hex()[:64]} ({confirmed} tx{'' if confirmed == 1 else 's'})"
                    )
                    try:
                        sent = self.network.publish_block(block, exclude=None, force=True)
                        if sent <= 0:
                            self.network.request_sync(fast=True)
                            self._queue_block_for_broadcast(block)
                    except Exception as exc:
                        clog(f"Broadcast error: {exc}")
                        self._queue_block_for_broadcast(block)
            except KeyboardInterrupt:
                self.mining_alive = False
                if self.cancel_mining:
                    self.cancel_mining.set()
                clog("[signal] Mining interrupted by user")
                break
            except Exception as exc:
                if isinstance(exc, OSError) and getattr(exc, "errno", None) in INTERRUPTED_ERRNOS:
                    clog("[mining] Interrupted system call; stopping miners...")
                    self.mining_alive = False
                    self.cancel_mining.set()
                    break
                clog(f"Mining error: {exc}")
                time.sleep(1)

        return True

    def stop(self):
        self.mining_alive = False
        if self.cancel_mining:
            self.cancel_mining.set()
            
        
        if self.network:
            self.network.shutdown()
        clog("Miner stopped")
        self.thread_monitor.stop_monitoring()

class NodeRunner:
    def __init__(self, bootstrap_snapshot: bool = True):
        self.blockchain = None
        self.network = None
        self.running = True
        self._last_chain_height = -1
        self._sync_ready = False
        self.bootstrap_snapshot = bootstrap_snapshot
        self._threads: list[threading.Thread] = []
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        _enable_siginterrupt()

    def _handle_signal(self, *_args):
        clog("Stopping node...")
        log.info("Ctrl+C received - stopping node-only runner.")
        self.running = False

    def _has_active_peers(self) -> bool:
        if not self.network:
            return False
        peers = getattr(self.network, "peers", set()) or set()
        inbound = getattr(self.network, "inbound_peers", set()) or set()
        outbound = getattr(self.network, "outbound_peers", set()) or set()
        return bool(peers or inbound or outbound)

    def start(self):
        clog("Starting TsarChain node (no mining)...")
        try:
            _run_snapshot_bootstrap(self.bootstrap_snapshot)
            self.blockchain = Blockchain(
                use_cores=None,
                miner_address=None,
            )
            
            self._last_chain_height = int(getattr(self.blockchain, "height", -1))
            clog(f"Local chain height: {self._last_chain_height}")
            
            self.network = Network(blockchain=self.blockchain)
            peer_count = _register_bootstrap_peers(self.network)
            clog(f"Node online on port {self.network.port}, bootstrap peers: {peer_count}")

            # == Early fast-sync ==
            def _early_sync():
                for _ in range(5):
                    try:
                        self.network.request_sync(fast=True)
                    except Exception:
                        log.exception("asuuuu")
                    time.sleep(1.0)
            t_early = threading.Thread(target=_early_sync, daemon=True)
            t_early.start()
            self._threads.append(t_early)

            # == Background sync daemon ==
            t_sync = threading.Thread(target=self._sync_daemon, daemon=True)
            t_sync.start()
            self._threads.append(t_sync)

            while self.running:
                time.sleep(2)
                
        except Exception as exc:
            clog(f"Node error: {exc}")
            
        finally:
            self.shutdown()

    def _sync_daemon(self):
        last_status = ""
        while self.running and self.blockchain and self.network:
            try:
                # No peers yet
                if not self._has_active_peers():
                    msg = "[Sync] Waiting for peer connection..."
                    if msg != last_status:
                        clog(msg)
                        last_status = msg
                    self._sync_ready = False
                    time.sleep(5)
                    continue

                # Have peers — request fast sync
                self.network.request_sync(fast=True)
                # Heights
                height = int(getattr(self.blockchain, "height", -1))
                # Progress print (only when changed)
                if height != self._last_chain_height:
                    if height >= 0:
                        clog(f"[Sync] Chain height now {height}")
                    self._last_chain_height = height

                peer_sync_map = getattr(self.network, "_peer_last_sync", {}) or {}
                latest_sync = max(peer_sync_map.values()) if peer_sync_map else 0.0
                synced_recently = latest_sync and (time.time() - latest_sync) < 10
                if not self._sync_ready and height >= 0 and synced_recently:
                    self._sync_ready = True
                    clog("Chain has been confirmed. Node is live (no mining).")

            except Exception as e:
                clog(f"[node-only] sync error: {e}")
            time.sleep(5)

    def shutdown(self):
        self.running = False
        if self.network:
            self.network.shutdown()
            self.network = None
        for t in self._threads:
            if t and t.is_alive():
                t.join(timeout=2.5)
        self._threads.clear()
        clog("Node stopped.")
        log.info("Node-only runner stopped (cleanup complete).")