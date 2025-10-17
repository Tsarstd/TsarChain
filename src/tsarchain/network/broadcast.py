# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

import socket, json, threading, time
from typing import Set, Tuple, Optional, Dict, Any, TYPE_CHECKING

# ---------------- Local Project ----------------
from .protocol import send_message, recv_message, verify_and_unwrap, is_envelope, SecureChannel
from ..consensus.blockchain import Blockchain
from ..core.block import Block
from ..core.tx import Tx
from ..mempool.pool import TxPoolDB
from ..storage.utxo import UTXODB
from ..utils import config as CFG

if TYPE_CHECKING:
    from .node import Network

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network(broadcast)")


class Broadcast:
    def __init__(self, blockchain=None, utxodb=None):
        self.lock = threading.RLock()
        self.blockchain = blockchain or Blockchain()
        self.utxodb = utxodb or UTXODB()
        self.mempool = TxPoolDB()
        self.state = {}
        self.seen_blocks: Set[str] = set()
        self.seen_txs: Set[str] = set()
        self._processing_blocks: Set[str] = set()
        self.last_sync_time = 0
        self.port: Optional[int] = None
        self._encode = lambda m: m
        self.node_id = None
        self.pubkey = None
        self.privkey = None
        self.peer_pubkeys = {}
        self.network: Optional["Network"] = None
        self._failmap: Dict[Tuple[str, int], Dict[str, float | int]] = {}  # {peer: {"fails": int, "last": ts}}

    # ----------------------------- I/O helpers -----------------------------

    def _send(self, peer: Tuple[str, int], message: Dict[str, Any]) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                connect_timeout = float(CFG.CONNECT_TIMEOUT)
                if connect_timeout <= 0:
                    connect_timeout = float(CFG.SYNC_TIMEOUT)
                    
                s.settimeout(connect_timeout)
                s.connect(peer)
                s.settimeout(CFG.SYNC_TIMEOUT)
                payload = json.dumps(self._encode(message)).encode("utf-8")
                if CFG.P2P_ENC_REQUIRED:
                    chan = SecureChannel(
                        s, role="client",
                        node_id=self.node_id, node_pub=self.pubkey, node_priv=self.privkey,
                        get_pinned=lambda nid: self.peer_pubkeys.get(nid),
                        set_pinned=lambda nid, pk: self.peer_pubkeys.__setitem__(nid, pk)
                    )
                    
                    chan.handshake()
                    chan.send(payload)
                else:
                    send_message(s, payload)
                try:
                    fm = self._failmap.get(peer)
                    if fm:
                        self._failmap.pop(peer, None)
                        
                except Exception:
                    pass
                log.debug("[_send] delivered to %s", peer)
                return True
            
        except TimeoutError:
            log.info("[_send] Connect to %s timed out", peer)
            
        except ConnectionRefusedError:
            log.info("[_send] Connect to %s refused", peer)
            
        except OSError as e:
            log.warning("[_send] OSError sending to %s: %s", peer, getattr(e, "strerror", e))
            
        except Exception:
            log.warning("[_send] Send to %s failed (unexpected)", peer, exc_info=True)

        try:
            fm = self._failmap.get(peer) or {"fails": 0, "last": 0.0}
            fm["fails"] = int(fm["fails"]) + 1
            fm["last"]  = time.time()
            self._failmap[peer] = fm
            
        except Exception:
            pass
        return False

    def _request_full_sync(self, peer: Tuple[str, int]) -> bool:
        if not CFG.ENABLE_FULL_SYNC:
            return False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(CFG.SYNC_TIMEOUT)
                s.connect(peer)
                # Secure transport
                if CFG.P2P_ENC_REQUIRED:
                    chan = SecureChannel(
                        s, role="client",
                        node_id=self.node_id, node_pub=self.pubkey, node_priv=self.privkey,
                        get_pinned=lambda nid: self.peer_pubkeys.get(nid),
                        set_pinned=lambda nid, pk: self.peer_pubkeys.__setitem__(nid, pk)
                    )
                    
                    chan.handshake()
                    send_fn = lambda b: chan.send(b)
                    recv_fn = lambda t: chan.recv(t)
                else:
                    send_fn = lambda b: send_message(s, b)
                    recv_fn = lambda t: recv_message(s, t)

                msg = {"type": "GET_FULL_SYNC", "port": getattr(self, "port", 0), "height": self.blockchain.height}
                payload = json.dumps(self._encode(msg)).encode("utf-8")
                send_fn(payload)
                resp = recv_fn(CFG.SYNC_TIMEOUT)
                if not resp:
                    return False
                outer = json.loads(resp.decode("utf-8"))
                if not is_envelope(outer):
                    return False
                try:
                    inner = verify_and_unwrap(outer, lambda nid: None)  # will use the 'pubkey' from the envelope
                except Exception:
                    log.warning("[_request_full_sync] Invalid envelope from peer")
                    return False
                if isinstance(inner, dict) and inner.get("type") == "FULL_SYNC":
                    self.receive_full_sync(inner.get("data", inner))
                    return True
                return False
        except Exception as e:
            log.exception(f"[_request_full_sync] Full sync request to {peer} failed: {e}")
            return False

    # ----------------------------- FULL SYNC -------------------------------

    def send_full_sync(self, peer: Tuple[str, int]):
        try:
            with self.lock:
                if not self.blockchain.in_memory:
                    self.blockchain.load_chain()
                chain_data = [blk.to_dict() for blk in self.blockchain.chain]
                try:
                    utxo_dict = self.utxodb.to_dict()
                except Exception:
                    utxo_dict = {}
                txs = [tx.to_dict() for tx in self.mempool.get_all_txs()]
                full = {
                    "type": "FULL_SYNC",
                    "data": {
                        "chain": chain_data,
                        "utxos": utxo_dict,
                        "state": self.state,
                        "mempool": txs
                    }
                }
                self._send(peer, full)
        except Exception as e:
            log.exception(f"[send_full_sync] Error sending full sync to {peer}: {e}")

    def receive_full_sync(self, payload: dict):
        if not CFG.ENABLE_FULL_SYNC:
            return False
        try:
            incoming = payload.get("chain") or []
            if not isinstance(incoming, list) or not incoming:
                return False

            if not self._validate_incoming_chain({"data": incoming}):
                return False

            current_list = [b.to_dict() for b in self.blockchain.chain]
            cw_local  = self._calc_chainwork_from_list(current_list)
            cw_remote = self._calc_chainwork_from_list(incoming)
            h_local   = self.blockchain.height
            h_remote  = incoming[-1].get("height", len(incoming)-1)
            tip_local = current_list[-1]["hash"]  if current_list else ""
            tip_remote= incoming[-1].get("hash", "")

            def is_better():
                if h_remote > h_local: return True
                if h_remote < h_local: return False
                if cw_remote > cw_local: return True
                if cw_remote < cw_local: return False
                return tip_remote < tip_local

            if not is_better() and self.blockchain.chain:
                return False

            new_chain = Blockchain.from_dict(incoming)

            with self.lock:
                self.blockchain.replace_with(new_chain)
                if not self.blockchain.in_memory:
                    self.blockchain.save_chain()
                    self.blockchain.save_state()

                self._rebuild_utxo_from_chain_locked()

                pool = payload.get("mempool") or []
                if isinstance(pool, list) and pool:
                    added = 0
                    for tx_data in pool:
                        try:
                            tx = Tx.from_dict(tx_data) if isinstance(tx_data, dict) else tx_data
                            if self.mempool.add_valid_tx(tx):
                                added += 1
                        except Exception:
                            log.exception("[receive_full_sync] Error adding tx from mempool during full sync")
                    if added:
                        log.info("[receive_full_sync] Mempool updated: %s new transactions", added)
                        
                self.last_sync_time = time.time()
            return True

        except Exception:
            log.exception("[receive_full_sync] Error receiving full sync")
            return False

    # ----------------------------- Broadcast ------------------------------

    def _broadcast(self, peers: Set[Tuple[str, int]], message: Dict[str, Any], exclude: Optional[Tuple[str, int]] = None):
        success_count = 0
        now = time.time()
        backoff_s = CFG.BROADCAST_FAIL_BACKOFF_S
        thr = CFG.BROADCAST_FAIL_THRESHOLD
        for peer in peers:
            if exclude and peer == exclude:
                continue
            
            fm = self._failmap.get(peer)
            if fm and int(fm.get("fails", 0)) >= thr and (now - float(fm.get("last", 0.0)) < backoff_s):
                log.debug("[_broadcast] Skipping %s due to backoff (fails=%s)", peer, fm.get("fails"))
                continue
            
            if self._send(peer, message):
                success_count += 1
        return success_count

    def broadcast_block(self, block: Block, peers: Set[Tuple[str, int]], exclude: Optional[Tuple[str, int]] = None, force: bool = False):
        block_id = block.hash().hex()
        with self.lock:
            if not force and block_id in self.seen_blocks:
                return 0
            self.seen_blocks.add(block_id)

        success = self._broadcast(peers, {
            "type": "NEW_BLOCK",
            "data": block.to_dict(),
            "port": getattr(self, "port", 0)
        }, exclude)
        
        return success

    def broadcast_tx(self, tx: Tx, peers: Set[Tuple[str, int]]):
        tx_id = tx.txid.hex()
        with self.lock:
            if tx_id in self.seen_txs:
                return 0
            self.seen_txs.add(tx_id)

        success = self._broadcast(peers, {
            "type": "NEW_TX",
            "data": tx.to_dict()
        })
        return success

    # ---------------------- Chainwork / validation utils ------------------

    def _compact_to_target(self, bits):
        if isinstance(bits, str):
            bits = int(bits, 16) if bits.startswith("0x") else int(bits)
        exp = (bits >> 24) & 0xff
        mant = bits & 0xffffff
        if exp <= 3:
            target = mant >> (8 * (3 - exp))
        else:
            target = mant << (8 * (exp - 3))
        return max(1, target)

    @staticmethod
    def _parse_bits(bits):
        if bits is None:
            return None
        if isinstance(bits, float):
            if bits.is_integer():
                return int(bits)
            raise TypeError(f"bits float non-integer: {bits}")
        if isinstance(bits, int):
            return bits & 0xFFFFFFFF
        if isinstance(bits, str):
            s = bits.strip().lower()
            return int(s, 16) if s.startswith("0x") else int(s)
        raise TypeError(f"bits must be int/hexstr, got {type(bits)}")

    def _work_from_bits(self, bits):
        bits = self._parse_bits(bits)
        exp = (bits >> 24) & 0xFF
        mant = bits & 0x007FFFFF
        if exp <= 3:
            target = mant >> (8 * (3 - exp))
        else:
            target = mant << (8 * (exp - 3))
        if target <= 0:
            return 0
        return (1 << 256) // (target + 1)

    def _calc_chainwork_from_list(self, chain_list) -> int:
        total = 0
        last_bits = None
        for i, b in enumerate(chain_list):
            raw  = b.get("bits") if isinstance(b, dict) else getattr(b, "bits", None)
            bits = self._parse_bits(raw)
            if bits is None:
                bits = CFG.INITIAL_BITS if i == 0 or last_bits is None else last_bits
            if bits > CFG.MAX_BITS:
                bits = CFG.MAX_BITS
            total += self._work_from_bits(bits)
            last_bits = bits
        return total

    # ------------------------------ Receive -------------------------------

    def receive_chain(self, message: Dict[str, Any]) -> bool:
        try:
            if not self._validate_incoming_chain(message):
                return False

            incoming_chain_data = message["data"]
            incoming_chain = Blockchain.from_dict(incoming_chain_data)

            with self.lock:
                current_height = self.blockchain.height
                incoming_height = incoming_chain.height

                current_list = [blk.to_dict() for blk in self.blockchain.chain]
                incoming_list = incoming_chain_data
                cw_local = self._calc_chainwork_from_list(current_list)
                cw_remote = self._calc_chainwork_from_list(incoming_list)
                tip_local = current_list[-1]["hash"] if current_list else ""
                tip_remote = incoming_list[-1]["hash"] if incoming_list else ""

                def is_better():
                    if incoming_height > current_height: return True
                    if incoming_height < current_height: return False
                    if cw_remote > cw_local: return True
                    if cw_remote < cw_local: return False
                    return tip_remote < tip_local

                if is_better():
                    self.blockchain.replace_with(incoming_chain)
                    if not self.blockchain.in_memory:
                        self.blockchain.save_chain()
                        self.blockchain.save_state()
                    self._rebuild_utxo_from_chain_locked()
                    return True

                return False

        except Exception:
            log.exception("[receive_chain] Error receiving chain")
            return False

    def receive_block(self, message: Dict[str, Any], addr, peers: Set[Tuple[str, int]]):
        block_id = None
        inflight = False
        accepted = False
        try:
            block_data = message.get("data")
            if not block_data:
                return

            block = Block.deserialize_block(block_data)
            block_id = block.hash().hex()

            origin_port = message.get("port")
            origin = (addr[0], origin_port) if origin_port else None

            with self.lock:
                if block_id in self.seen_blocks or block_id in self._processing_blocks:
                    return
                self._processing_blocks.add(block_id)
                inflight = True

            last = self.blockchain.get_last_block()
            potential_fork = False
            if last:
                tip_h = last.hash()
                if block.height > last.height + 1:
                    handled = False
                    if self.network:
                        try:
                            self.network.handle_block_gap(block, origin)
                            handled = True
                        except Exception:
                            log.exception("[receive_block] Network handle_block_gap failed")
                    if not handled and CFG.ENABLE_FULL_SYNC:
                        targets = [origin] if origin else list(peers)
                        for p in targets:
                            try:
                                self._request_full_sync(p)
                            except Exception:
                                log.exception("[receive_block] Full sync request to %s failed", p)
                    return
                if block.prev_block_hash != tip_h:
                    potential_fork = True

            if not potential_fork:
                if not self.blockchain.validate_block(block):
                    log.warning("[receive_block] Invalid block received ... block=%s peer=%s", block_id[:12], f"{addr[0]}:{origin_port or 0}")
                    return

            old_tip = None
            try:
                ok = self.blockchain.add_block(block)
            except ValueError:
                if potential_fork:
                    old_tip = self.blockchain.swap_tip_if_better(block)
                    ok = old_tip is not None
                else:
                    ok = False
            if not ok:
                log.warning("[receive_block] Block at height %s rejected by add_block", block.height)
                if potential_fork:
                    targets = [origin] if origin else list(peers)
                    for p in targets:
                        try:
                            prev_flag = CFG.ENABLE_FULL_SYNC
                            CFG.ENABLE_FULL_SYNC = True
                            self._request_full_sync(p)
                        except Exception:
                            log.exception("[receive_block] Fallback full sync request to %s failed", p)
                        finally:
                            CFG.ENABLE_FULL_SYNC = prev_flag
                return

            accepted = True

            try:
                fail_rm = 0
                for tx in (block.transactions[1:] or []):
                    try:
                        self.mempool.remove_tx(tx.txid.hex())
                    except Exception:
                        fail_rm += 1
                if fail_rm:
                    log.warning("[receive_block] %s tx failed to remove from mempool after block addition", fail_rm)
                try:
                    self.mempool.save_pool(self.mempool.load_pool())
                except Exception:
                    log.exception("[receive_block] Error cleaning mempool")

                if old_tip:
                    try:
                        for tx in (old_tip.transactions[1:] or []):
                            try:
                                self.mempool.add_valid_tx(tx)
                            except Exception:
                                pass
                    except Exception:
                        log.exception("[receive_block] Error requeueing transactions from orphaned tip")
            except Exception:
                log.exception("[receive_block] Error updating mempool after block acceptance")

            try:
                if self.blockchain.in_memory:
                    try:
                        self.utxodb.update(block.transactions, block.height)
                    except Exception:
                        log.exception("[receive_block] Error updating UTXO after block acceptance")
                else:
                    try:
                        self.utxodb._load()
                    except Exception:
                        log.exception("[receive_block] Error loading UTXO DB from disk")
            except Exception:
                log.exception("[receive_block] Error updating UTXO DB after block acceptance")

            with self.lock:
                self.seen_blocks.add(block_id)

            try:
                self.broadcast_block(block, peers, exclude=origin, force=True)
            except Exception:
                log.exception("[receive_block] Error broadcasting new block to peers")

        except Exception:
            log.exception("[receive_block] Error processing incoming block")
        finally:
            if inflight and block_id:
                with self.lock:
                    self._processing_blocks.discard(block_id)
                    if not accepted:
                        self.seen_blocks.discard(block_id)

    def receive_tx(self, message: Dict[str, Any], addr, peers: Set[Tuple[str, int]]) -> bool:
        try:
            tx_data = message["data"]
            tx = Tx.from_dict(tx_data) if isinstance(tx_data, dict) else tx_data
            tx_id = tx.txid.hex()

            with self.lock:
                if tx_id in self.seen_txs:
                    return False
                self.seen_txs.add(tx_id)

            try:
                is_valid = self.mempool.add_valid_tx(tx)
            except Exception:
                log.exception("[receive_tx] Error validating/adding incoming TX")
                return False

            if is_valid:
                self.broadcast_tx(tx, peers)
                return True
            else:
                # Keep last_error_reason for caller to inspect via process_message
                return False
        except Exception:
            log.exception("[receive_tx] Error processing incoming TX")
            return False

    def receive_utxos(self, message: Dict[str, Any]):
        try:
            utxo_data = message.get("data", {})
            if utxo_data and not self.blockchain.chain:
                self.utxodb = UTXODB.from_dict(utxo_data)
                if not self.blockchain.in_memory:
                    self.utxodb._save()
            else:
                if utxo_data:
                    log.warning("[receive_utxos] Ignoring UTXO snapshot since we have a non-empty chain")
        except Exception:
            log.exception("[receive_utxos] Error updating UTXO DB")

    def receive_state(self, message: Dict[str, Any]):
        try:
            self.state = message.get("data", {})
        except Exception:
            log.exception("[receive_state] Error updating state")

    def receive_mempool(self, message: Dict[str, Any]):
        try:
            txs_data = message.get("data", [])
            added_count = 0
            for tx_data in txs_data:
                try:
                    tx = Tx.from_dict(tx_data) if isinstance(tx_data, dict) else tx_data
                    if self.mempool.add_valid_tx(tx):
                        added_count += 1
                except Exception:
                    log.exception("[receive_mempool] Error adding tx from mempool snapshot")
            if added_count:
                log.info("[receive_mempool] Mempool updated: %s new transactions", added_count)
        except Exception:
            log.exception("[receive_mempool] Error updating mempool")

    def _validate_incoming_chain(self, message: Dict[str, Any]) -> bool:
        try:
            chain_data = message.get("data", [])
            if not chain_data:
                return False

            if chain_data[0].get("height") != 0:
                return False

            for i in range(1, len(chain_data)):
                if chain_data[i].get("height") != chain_data[i - 1].get("height") + 1:
                    return False
                if chain_data[i].get("prev_block_hash") != chain_data[i - 1].get("hash"):
                    return False
            return True
        except Exception:
            log.exception("[_validate_incoming_chain] Error validating incoming chain")
            return False

    def _rebuild_utxo_from_chain_locked(self):
        try:
            self.utxodb.rebuild_from_chain(self.blockchain.chain)
            self._clean_mempool_after_chain_replace()
        except Exception:
            log.exception("[_rebuild_utxo_from_chain_locked] Error rebuilding UTXO from chain")


    # ------------------------------ Mempool Snapshoot Gossip -------------------------------
    
    def _mempool_chunks(self, max_bytes: int) -> list[list[dict]]:
        try:
            txs = self.mempool.get_all_txs() or []
        except Exception:
            txs = []
        chunks, cur = [], []
        base = {"type": "MEMPOOL", "data": []}
        for tx in txs:
            try:
                d = tx.to_dict() if hasattr(tx, "to_dict") else tx
            except Exception:
                continue
            
            test = dict(base)
            test["data"] = cur + [d]
            try:
                enc = json.dumps(self._encode(test), separators=(',', ':')).encode("utf-8")
            except Exception:
                continue
            
            hard_cap = max(1024, CFG.MAX_MSG) - len(CFG.NETWORK_MAGIC)
            if len(enc) > hard_cap and cur:
                chunks.append(cur)
                cur = [d]
            else:
                cur.append(d)
        if cur:
            chunks.append(cur)
        return chunks

    def send_mempool_to_peer(self, peer: tuple[str, int], *, min_interval_s: float | None = None) -> int:
        if not hasattr(self, "_last_mempool_push"):
            self._last_mempool_push = {}
        ttl = float(min_interval_s or CFG.MEMPOOL_SYNC_MIN_INTERVAL)
        now = time.time()
        last = float(self._last_mempool_push.get(peer, 0.0))
        if now - last < ttl:
            return 0

        sent = 0
        hard_cap = max(1024, CFG.MAX_MSG) - len(CFG.NETWORK_MAGIC)
        for chunk in self._mempool_chunks(hard_cap):
            if not chunk:
                continue
            ok = self._send(peer, {
                "type": "MEMPOOL",
                "data": chunk,
                "port": getattr(self, "port", 0),
            })
            if ok:
                sent += len(chunk)
        self._last_mempool_push[peer] = now
        return sent

    def _clean_mempool_after_chain_replace(self):
        try:
            current_mempool = self.mempool.get_all_txs()
            new_mempool = []
            in_chain = set()
            for block in self.blockchain.chain:
                for block_tx in block.transactions:
                    in_chain.add(block_tx.txid.hex() if getattr(block_tx, "txid", None) else "")

            for tx in current_mempool:
                if not (tx.txid.hex() in in_chain):
                    new_mempool.append(tx)

            self.mempool.save_pool([tx.to_dict() for tx in new_mempool])
        except Exception:
            log.exception("[_clean_mempool_after_chain_replace] Error cleaning mempool after chain replace")

    # ------------------------------ Shutdown ------------------------------

    def shutdown(self):
        with self.lock:
            self.seen_blocks.clear()
            self.seen_txs.clear()
        log.info("[shutdown] Shutdown complete")
