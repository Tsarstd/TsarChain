# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: BIP141; BIP173; Merkle; Signal-X3DH

import json
import time
import socket
import threading
import collections

# ---------------- Local Project ----------------
from ...utils import config as CFG
from .base import NetworkHandlerProxy
from ..protocol import send_message, recv_message,build_envelope, SecureChannel

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc_helper.chat")


# ------------------------------ P2P Chat ------------------------------

class ChatHandler(NetworkHandlerProxy):
    def send_to_peer(self, peer: tuple[str,int], payload: dict) -> None:
        if not isinstance(peer, tuple) or len(peer) != 2:
            raise ValueError("bad peer")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            s.connect(peer)
            env = build_envelope(payload, self.node_ctx, extra={"pubkey": self.pubkey})
            env["pubkey"] = self.pubkey
            raw = json.dumps(env).encode("utf-8")
            chan = SecureChannel(
                s, role="client",
                node_id=self.node_id, node_pub=self.pubkey, node_priv=self.privkey,
                get_pinned=self.get_pinned, set_pinned=self.set_pinned,
            )
            chan.handshake()
            chan.send(raw)
            _ = chan.recv(1)


    def relay_presence_async(self, pres: dict, exclude=None) -> None:
        threading.Thread(target=self._relay_presence, args=(pres, exclude), daemon=True).start()


    def mailbox_put(self, addr, item, ttl_s, per_addr_max, global_max):
        now = time.time()
        exp = now + ttl_s
        with self.chat_lock:
            dq = self.chat_mailbox.get(addr)
            if dq is None:
                dq = collections.deque()
                self.chat_mailbox[addr] = dq
            # lazy GC per addr
            while dq and dq[0][0] <= now:
                dq.popleft(); self.chat_global_count -= 1
            if len(dq) >= per_addr_max or self.chat_global_count >= global_max:
                return False  # mailbox full
            dq.append((exp, item))
            self.chat_global_count += 1
            return True


    def mailbox_pull(self, addr, nmax):
        now = time.time()
        out = []
        with self.chat_lock:
            dq = self.chat_mailbox.get(addr)
            if not dq:
                return out
            # prune expired entries first
            while dq and dq[0][0] <= now:
                dq.popleft(); self.chat_global_count -= 1
            while dq and len(out) < nmax:
                exp, it = dq.popleft()
                self.chat_global_count -= 1
                if exp > now:
                    out.append(it)
        return out


    def enqueue_rcpt(self, to_addr, kind, mid, frm, to, ts):
        item = {
            "type": "CHAT_RCPT",
            "rcpt": kind,
            "msg_id": mid,
            "from": frm,
            "to": to,
            "ts": int(ts),
        }
        self.mailbox_put(to_addr, item, CFG.CHAT_TTL_S, CFG.CHAT_MAILBOX_MAX, CFG.CHAT_GLOBAL_QUEUE_MAX)


    def record_presence_seen(self, pid: str) -> None:
        if not pid:
            return
        with self.chat_lock:
            if not hasattr(self, "chat_presence_seen_order"):
                self.chat_presence_seen_order = collections.deque(maxlen=10000)
            if pid in self.chat_presence_seen:
                return
            if len(self.chat_presence_seen_order) == self.chat_presence_seen_order.maxlen:
                oldest = self.chat_presence_seen_order.popleft()
                self.chat_presence_seen.discard(oldest)
            self.chat_presence_seen_order.append(pid)
            self.chat_presence_seen.add(pid)


    def dedup_pull(self, addr: str, pull_sig: str) -> bool:
        if not pull_sig or not addr:
            return False
        with self.chat_lock:
            if not hasattr(self, "chat_pull_seen"):
                self.chat_pull_seen = {}
            if len(self.chat_pull_seen) > 2000 and addr not in self.chat_pull_seen:
                oldest_addr = next(iter(self.chat_pull_seen))
                self.chat_pull_seen.pop(oldest_addr, None)
            rec = self.chat_pull_seen.get(addr)
            if rec is None:
                dq = collections.deque(maxlen=128)
                st = set()
                self.chat_pull_seen[addr] = (dq, st)
            else:
                dq, st = rec
            if pull_sig in st:
                return True
            if len(dq) == dq.maxlen:
                old = dq.popleft()
                st.discard(old)
            dq.append(pull_sig)
            st.add(pull_sig)
            return False


    def gc_mailboxes(self):
        now = time.time()
        if now - self.chat_gc_last < 30:
            return
        with self.chat_lock:
            empty_mailboxes = []
            for addr, dq in self.chat_mailbox.items():
                changed = False
                while dq and dq[0][0] <= now:
                    dq.popleft(); self.chat_global_count -= 1; changed = True
                if not dq and changed:
                    empty_mailboxes.append(addr)
            for addr in empty_mailboxes:
                self.chat_mailbox.pop(addr, None)

            # Clean expired backoffs
            expired_backoffs = [k for k, until in self.backoff_until.items() if until <= now]
            for k in expired_backoffs:
                self.backoff_until.pop(k, None)

            # Clean oversized seen structures if needed
            if hasattr(self, "chat_pull_seen") and len(self.chat_pull_seen) > 2000:
                self.chat_pull_seen.clear()
            if len(self.chat_seen_mid) > 2000:
                # prune half of oldest address keys
                keys_to_remove = list(self.chat_seen_mid.keys())[:1000]
                for k in keys_to_remove:
                    self.chat_seen_mid.pop(k, None)
        self.chat_gc_last = now


    def dedup_mid(self, from_addr, msg_id):
        if msg_id is None: 
            return False
        with self.chat_lock:
            if len(self.chat_seen_mid) > 2000 and from_addr not in self.chat_seen_mid:
                try:
                    oldest_addr = next(iter(self.chat_seen_mid))
                    self.chat_seen_mid.pop(oldest_addr, None)
                except StopIteration:
                    pass
            rec = self.chat_seen_mid.get(from_addr)
            if rec is None:
                dq = collections.deque(maxlen=self.chat_seen_max)
                st = set()
                self.chat_seen_mid[from_addr] = (dq, st)
            else:
                dq, st = rec
            if msg_id in st:
                return True
            # tambah
            if len(dq) == dq.maxlen:
                old = dq.popleft(); st.discard(old)
            dq.append(msg_id); st.add(msg_id)
            return False


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _relay_presence(self, pres: dict, exclude=None) -> None:
        hops = int(pres.get("hops", 0))
        if hops >= 2:
            return
        pres2 = dict(pres); pres2["hops"] = hops + 1
        msg = {"type": "CHAT_PRESENCE", **pres2}
        self.broadcast.send_gossip(self.peers, msg, exclude=exclude)