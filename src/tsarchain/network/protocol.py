# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: RFC7748-X25519; RFC5869-HKDF; NIST-800-38D-AES-GCM

import socket, struct, time, os, json, secrets, hashlib, errno
import threading
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

# ---------------- Local Project ----------------
from ..utils import config as CFG

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network(protocol)")


def _ensure_dir(path = str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


# -----------------------------
# DISCONECT SPAM FILTER LOGGING
# -----------------------------
WIN_DISCONNECT = {10053, 10054, 10058, 10060}  # WSAECONNABORTED, WSAECONNRESET, WSAESHUTDOWN, WSAETIMEDOUT
POSIX_DISCONNECT = {errno.ECONNRESET, errno.EPIPE, errno.ECONNABORTED, errno.ETIMEDOUT}

def _is_disconnect_exc(e: BaseException) -> bool:
    if isinstance(e, (ConnectionError, ConnectionResetError, ConnectionAbortedError, TimeoutError, socket.timeout, BrokenPipeError)):
        return True
    if isinstance(e, OSError):
        code = getattr(e, "errno", None)
        w    = getattr(e, "winerror", None)
        return (code in POSIX_DISCONNECT) or (w in WIN_DISCONNECT)
    return False


# ----------------------------------
# NONCE CACHE for ANTI-REPLAY GUARD
# ----------------------------------
_nonce_lock = threading.RLock()
_nonce_cache: dict[str, dict[str, int]] = {}

def _nonce_total_entries() -> int:
    return sum(len(rec) for rec in _nonce_cache.values())

def _nonce_prune_expired_locked(now_ts: int):
    ttl = CFG.REPLAY_WINDOW_SEC
    for sender, rec in list(_nonce_cache.items()):
        try:
            for k, t in list(rec.items()):
                if now_ts - int(t or 0) > ttl:
                    rec.pop(k, None)
        except Exception:
            log.warning("[_nonce_prune_expired_locked] prune error", exc_info=True)
        if not rec:
            _nonce_cache.pop(sender, None)

def _nonce_prune_global_if_needed_locked():
    total = _nonce_total_entries()
    if total <= CFG.NONCE_GLOBAL_MAX:
        return
    # Oldest evict globally until <= CFG.NONCE_GLOBAL_MAX
    # Collect the head (oldest nonce) from each sender
    heads = []
    for sender, rec in _nonce_cache.items():
        if rec:
            try:
                oldest_nonce, oldest_ts = min(rec.items(), key=lambda it: it[1])
                heads.append((oldest_ts, sender, oldest_nonce))
            except Exception:
                pass
    heads.sort()  # oldest first
    to_evict = total - CFG.NONCE_GLOBAL_MAX
    i = 0
    while to_evict > 0 and i < len(heads):
        _, s, n = heads[i]
        rec = _nonce_cache.get(s)
        if rec and n in rec:
            rec.pop(n, None)
            if not rec:
                _nonce_cache.pop(s, None)
            to_evict -= 1
        i += 1


def _nonce_register(sender: str, nonce: str, ts_val: int) -> None:
    if not sender or not nonce:
        raise ValueError("missing sender/nonce")
    now = int(time.time())
    with _nonce_lock:
        # 1) Prune global yang expired
        _nonce_prune_expired_locked(now)

        # 2) Ambil map per-sender
        rec = _nonce_cache.get(sender)
        if rec is None:
            rec = {}
            _nonce_cache[sender] = rec

        # 3) Tolak jika nonce sudah pernah dipakai
        if nonce in rec:
            raise ValueError("replayed nonce")

        # 4) Tambah nonce baru
        rec[nonce] = now

        # 5) Bound per-sender size (evict tertua)
        if len(rec) > CFG.NONCE_PER_SENDER_MAX:
            try:
                extra = len(rec) - CFG.NONCE_PER_SENDER_MAX
                for k, _t in sorted(rec.items(), key=lambda it: it[1])[:extra]:
                    rec.pop(k, None)
            except Exception:
                log.exception("[_nonce_register] nonce prune error")

        # 6) Enforce global cap
        _nonce_prune_global_if_needed_locked()



# -----------------------------
# SEND & RECEIVE MESSAGE
# -----------------------------
def send_message(sock: socket.socket, payload: bytes):
    if len(payload) + len(CFG.NETWORK_MAGIC) > CFG.MAX_MSG:
        raise ValueError("Message too large")
    
    body = CFG.NETWORK_MAGIC + payload
    n = len(body)
    hdr = struct.pack(">I", n)
    
    try:
        sock.sendall(hdr + body)
    except Exception as e:
        if _is_disconnect_exc(e):
            log.debug("[send_message] peer closed during send (%s)", getattr(e, "winerror", getattr(e, "errno", e)))
            return
        raise
    
    if log.isEnabledFor(5):  # TRACE
        log.trace("sent %s bytes", n)

def recv_message(sock, timeout: float | None = None):
    if timeout is not None:
        try:
            sock.settimeout(timeout)
        except Exception:
            pass
    try:
        hdr = recv_exact(sock, 4)
        n = struct.unpack(">I", hdr)[0]
        if n <= 0 or n > CFG.MAX_MSG:
            return None
        body = recv_exact(sock, n)
        if not body.startswith(CFG.NETWORK_MAGIC):
            return None
        return body[len(CFG.NETWORK_MAGIC):]
    except Exception as e:
        if _is_disconnect_exc(e):
            return None
        
        log.exception("[recv_message] unexpected error")
        return None

def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            raise ConnectionError("Connection closed")
        buf += part
        
    if log.isEnabledFor(5):  # TRACE
        log.trace("[recv_exact] got %s bytes", len(buf))
    return buf

def sniff_first_json_frame(sock: socket.socket, timeout: float = 2.0) -> tuple[bytes | None, dict | None]:
    raw = recv_message(sock, timeout=timeout)
    if not raw:
        return None, None
    try:
        return raw, json.loads(raw.decode("utf-8"))
    except Exception:
        log.exception("[sniff_first_json_frame] error")
        return raw, None



# -----------------------------
# KEYPAIR HELPER
# -----------------------------
def load_or_create_keypair_at(path: str) -> tuple[str, str, str]:
    _ensure_dir(path)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        return obj["id"], obj["pubkey"], obj["privkey"]

    sk = SigningKey.generate()
    vk = sk.verify_key
    priv_hex = sk.encode(encoder=HexEncoder).decode()
    pub_hex  = vk.encode(encoder=HexEncoder).decode()
    node_id  = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"id": node_id, "pubkey": pub_hex, "privkey": priv_hex}, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except Exception:
        log.debug("[keys] chmod 600 failed (non-POSIX or permissions)")
    return node_id, pub_hex, priv_hex

def load_or_create_node_keys() -> tuple[str, str, str]:
    return load_or_create_keypair_at(CFG.NODE_KEY_PATH)


# -----------------------------
# ENVELOPE & SIGNATURE
# -----------------------------
def canonical_dumps(obj) -> bytes:
    return json.dumps(obj, separators=CFG.CANONICAL_SEP, sort_keys=True, ensure_ascii=False).encode('utf-8')

def gen_nonce(nbytes: int = 16) -> str:
    return secrets.token_hex(nbytes)

def sign_message_hex(privkey_hex: str, payload: bytes) -> str:
    sk = SigningKey(bytes.fromhex(privkey_hex))
    sig = sk.sign(payload).signature.hex()
    return sig

def verify_signature(pubkey_hex: str, payload: bytes, sig_hex: str) -> bool:
    try:
        VerifyKey(bytes.fromhex(pubkey_hex)).verify(payload, bytes.fromhex(sig_hex))
        return True
    except Exception:
        log.debug("[verify_signature] bad signature")
        return False

def is_envelope(obj: dict) -> bool:
    return isinstance(obj, dict) and \
           "net_id" in obj and "from" in obj and "msg" in obj and \
           "sig" in obj and "ts" in obj and "nonce" in obj

def build_envelope(inner_msg: dict, node_ctx: dict, extra: dict | None = None) -> dict:
    ts_now = int(time.time())
    nonce = gen_nonce(16)
    outer = {
        "net_id": node_ctx["net_id"],
        "ts": ts_now,
        "nonce": nonce,
        "from": node_ctx["node_id"],
        "msg": inner_msg
    }
    if extra:
        outer.update(extra)

    to_sign = canonical_dumps({"msg": inner_msg, "ts": ts_now, "nonce": nonce, "from": node_ctx["node_id"]})
    outer["sig"] = sign_message_hex(node_ctx["privkey"], to_sign)

    return outer

def verify_and_unwrap(envelope: dict, get_pubkey_by_nodeid) -> dict:
    net_id = envelope.get("net_id")
    if net_id != CFG.DEFAULT_NET_ID:
        raise ValueError("wrong network id")
    ts_val = envelope.get("ts")
    if not isinstance(ts_val, int) or abs(int(time.time()) - ts_val) > CFG.REPLAY_WINDOW_SEC:
        raise ValueError("timestamp window violation")
    if not envelope.get("nonce"):
        raise ValueError("missing nonce")

    envelope.pop("hmac", None)
    node_id = envelope.get("from")
    if not node_id:
        raise ValueError("missing node_id")
    inner = envelope.get("msg")
    if not isinstance(inner, dict):
        raise ValueError("missing msg")
    to_sign = canonical_dumps({"msg": inner, "ts": ts_val, "nonce": envelope["nonce"], "from": node_id})
    pub = None
    if callable(get_pubkey_by_nodeid):
        pub = get_pubkey_by_nodeid(node_id)
    if not pub:
        pub = envelope.get("pubkey")
        if not pub:
            raise ValueError("unknown peer pubkey and not provided")
    # Enforce binding: node_id must equal sha256(pubkey)
    try:
        derived = hashlib.sha256(bytes.fromhex(pub)).hexdigest()
        if derived != node_id:
            raise ValueError("node_id/pubkey mismatch")
    except Exception:
        raise ValueError("invalid pubkey in envelope")
    if not verify_signature(pub, to_sign, envelope.get("sig", "")):
        raise ValueError("bad signature")
    # Anti-replay within REPLAY_WINDOW_SEC using per-sender nonce cache
    _nonce_register(node_id, str(envelope.get("nonce")), int(ts_val))

    return inner

# =========================================================
# ==== [BEGIN: P2P SecureChannel X25519->HKDF->AESGCM] ====
# =========================================================

def _hkdf_derive(secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)

class SecureChannel:
    def __init__(self, sock: socket.socket, role: str, node_id: str | None = None, node_pub: str | None = None, node_priv: str | None = None, get_pinned=None, set_pinned=None):
        assert role in ("client", "server")
        
        self.sock = sock
        self.role = role
        self.aes: AESGCM | None = None
        self.established_at = 0.0
        self.node_id  = node_id
        self.node_pub = node_pub
        self.node_priv= node_priv
        self.get_pinned = get_pinned or (lambda nid: None)
        self.set_pinned = set_pinned or (lambda nid, pk: None)
        self.peer_node_id  = None
        self.peer_node_pub = None
        self.send_ctr = 0
        self.recv_ctr = -1

    def handshake(self):
        if self.role == "client":
            self._hs_client_auth()
        else:
            self._hs_server_auth()

    def _hs_client_auth(self):
        eph = x25519.X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        salt1 = os.urandom(16)
        
        if not (self.node_id and self.node_pub and self.node_priv):
            raise ValueError("node identity missing for authenticated handshake")
        sk = SigningKey(bytes.fromhex(self.node_priv))
        to_sign = b"|".join([
            b"HS1", CFG.DEFAULT_NET_ID.encode(),
            eph_pub, salt1,
            self.node_id.encode(), bytes.fromhex(self.node_pub)])
        
        sig = sk.sign(to_sign).signature.hex()
        hs1 = {
            "type": "P2P_HS1",
            "net": CFG.DEFAULT_NET_ID,
            "eph_pub": eph_pub.hex(),
            "salt":   salt1.hex(),
            "node_id": self.node_id,
            "node_pub": self.node_pub,
            "sig": sig,}
        
        send_message(self.sock, json.dumps(hs1).encode("utf-8"))

        raw = recv_message(self.sock, timeout=5.0)
        hs2 = json.loads(raw.decode("utf-8"))
        if hs2.get("type") != "P2P_HS2" or hs2.get("net") != CFG.DEFAULT_NET_ID:
            raise ValueError("bad P2P handshake (HS2)")
        peer_pub = bytes.fromhex(hs2["eph_pub"])
        salt2    = bytes.fromhex(hs2["salt"])

        self.peer_node_id  = str(hs2.get("node_id") or "")
        self.peer_node_pub = str(hs2.get("node_pub") or "")
        try:
            vk = VerifyKey(bytes.fromhex(self.peer_node_pub))
            to_verify = b"|".join([
                b"HS2", CFG.DEFAULT_NET_ID.encode(),
                bytes.fromhex(hs2["eph_pub"]), bytes.fromhex(hs2["salt"]),
                bytes.fromhex(hs1["eph_pub"]), bytes.fromhex(hs1["salt"]),
                self.peer_node_id.encode(), bytes.fromhex(self.peer_node_pub)])
            
            vk.verify(to_verify, bytes.fromhex(hs2["sig"]))
        except Exception:
            log.exception("[_hs_client_auth] bad HS2 signature")
            raise ValueError("Bad signature")

        pinned = self.get_pinned(self.peer_node_id)
        if pinned and pinned != self.peer_node_pub:
            raise ValueError("peer key mismatch (pinned)")
        if not pinned:
            self.set_pinned(self.peer_node_id, self.peer_node_pub)
        shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(peer_pub))
        info = b"|".join([b"P2Pv1", CFG.DEFAULT_NET_ID.encode(),
                          bytes.fromhex(hs1["eph_pub"]), bytes.fromhex(hs1["salt"]),
                          bytes.fromhex(hs2["eph_pub"]), bytes.fromhex(hs2["salt"])])
        
        key = _hkdf_derive(shared, salt1+salt2, info, CFG.P2P_AEAD_KEY_BYTES)
        self.aes = AESGCM(key)
        self.established_at = time.time()
        self.msg_count = 0

    def _hs_server_auth(self):
        raw = recv_message(self.sock, timeout=5.0)
        hs1 = json.loads(raw.decode("utf-8"))
        if hs1.get("type") != "P2P_HS1" or hs1.get("net") != CFG.DEFAULT_NET_ID:
            
            log.error("[_hs_server_auth] bad P2P handshake (HS1) %s", hs1)
            raise ValueError("bad P2P handshake (HS1)")

        self.peer_node_id  = str(hs1.get("node_id") or "")
        self.peer_node_pub = str(hs1.get("node_pub") or "")
        try:
            vk = VerifyKey(bytes.fromhex(self.peer_node_pub))
            to_verify = b"|".join([
                b"HS1", CFG.DEFAULT_NET_ID.encode(),
                bytes.fromhex(hs1["eph_pub"]), bytes.fromhex(hs1["salt"]),
                self.peer_node_id.encode(), bytes.fromhex(self.peer_node_pub)])
            
            vk.verify(to_verify, bytes.fromhex(hs1["sig"]))
        except Exception:
            log.exception("[_hs_server_auth] bad HS1 signature")
            raise ValueError("Bad signature")
            
        pinned = self.get_pinned(self.peer_node_id)
        if pinned and pinned != self.peer_node_pub:
            raise ValueError("peer key mismatch (pinned)")
        if not pinned:
            self.set_pinned(self.peer_node_id, self.peer_node_pub)
        peer_pub = bytes.fromhex(hs1["eph_pub"])
        salt1    = bytes.fromhex(hs1["salt"])

        eph = x25519.X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        
        salt2 = os.urandom(16)
        shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(peer_pub))
        info = b"|".join([b"P2Pv1", CFG.DEFAULT_NET_ID.encode(),
                          bytes.fromhex(hs1["eph_pub"]), bytes.fromhex(hs1["salt"]),
                          eph_pub, salt2])
        
        key = _hkdf_derive(shared, salt1+salt2, info, CFG.P2P_AEAD_KEY_BYTES)
        self.aes = AESGCM(key)
        self.established_at = time.time()
        self.msg_count = 0

        if not (self.node_id and self.node_pub and self.node_priv):
            raise ValueError("node identity missing for authenticated handshake")
        sk = SigningKey(bytes.fromhex(self.node_priv))
        to_sign = b"|".join([
            b"HS2", CFG.DEFAULT_NET_ID.encode(),
            eph_pub, salt2,
            bytes.fromhex(hs1["eph_pub"]), bytes.fromhex(hs1["salt"]),
            self.node_id.encode(), bytes.fromhex(self.node_pub)])
        
        sig = sk.sign(to_sign).signature.hex()
        hs2 = {
            "type": "P2P_HS2",
            "net": CFG.DEFAULT_NET_ID,
            "eph_pub": eph_pub.hex(),
            "salt":   salt2.hex(),
            "node_id": self.node_id,
            "node_pub": self.node_pub,
            "sig": sig,
        }
        send_message(self.sock, json.dumps(hs2).encode("utf-8"))
        
    def hs_server_from_obj(self, hs1_obj: dict):
        if hs1_obj.get("type") != "P2P_HS1" or hs1_obj.get("net") != CFG.DEFAULT_NET_ID:
            raise ValueError("bad P2P handshake (HS1)")

        peer_node_id  = str(hs1_obj.get("node_id") or "")
        peer_node_pub = str(hs1_obj.get("node_pub") or "")
        try:
            vk = VerifyKey(bytes.fromhex(peer_node_pub))
            to_verify = b"|".join([
                b"HS1", CFG.DEFAULT_NET_ID.encode(),
                bytes.fromhex(hs1_obj["eph_pub"]), bytes.fromhex(hs1_obj["salt"]),
                peer_node_id.encode(), bytes.fromhex(peer_node_pub),
            ])
            vk.verify(to_verify, bytes.fromhex(hs1_obj["sig"]))
        except Exception:
            log.exception("[hs_server_from_obj] bad HS1 signature")
            raise ValueError("Bad signature")

        pinned = self.get_pinned(peer_node_id)
        if pinned and pinned != peer_node_pub:
            raise ValueError("peer key mismatch (pinned)")
        if not pinned:
            self.set_pinned(peer_node_id, peer_node_pub)
        self.peer_node_id  = peer_node_id
        self.peer_node_pub = peer_node_pub

        peer_eph = bytes.fromhex(hs1_obj["eph_pub"])
        salt1    = bytes.fromhex(hs1_obj["salt"])
        eph = x25519.X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        salt2 = os.urandom(16)
        shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(peer_eph))
        info = b"|".join([b"P2Pv1", CFG.DEFAULT_NET_ID.encode(),
                          peer_eph, salt1, eph_pub, salt2])
        key = _hkdf_derive(shared, salt1 + salt2, info, CFG.P2P_AEAD_KEY_BYTES)
        self.aes = AESGCM(key)
        self.established_at = time.time()
        self.msg_count = 0

        if not (self.node_id and self.node_pub and self.node_priv):
            raise ValueError("node identity missing for authenticated handshake")
        sk = SigningKey(bytes.fromhex(self.node_priv))
        to_sign = b"|".join([
            b"HS2", CFG.DEFAULT_NET_ID.encode(),
            eph_pub, salt2,
            peer_eph, salt1,
            self.node_id.encode(), bytes.fromhex(self.node_pub)
        ])
        sig = sk.sign(to_sign).signature.hex()
        hs2 = {
            "type":    "P2P_HS2",
            "net":     CFG.DEFAULT_NET_ID,
            "eph_pub": eph_pub.hex(),
            "salt":    salt2.hex(),
            "node_id": self.node_id,
            "node_pub": self.node_pub,
            "sig":     sig,
        }
        send_message(self.sock, json.dumps(hs2).encode("utf-8"))

    def _ready(self):
        if not self.aes:
            raise RuntimeError("secure channel not established")
        if (time.time() - self.established_at) > float(CFG.P2P_SESSION_TTL_S):
            raise RuntimeError("secure channel expired (TTL)")
        if self.msg_count >= int(CFG.P2P_SESSION_MAX_MSG):
            raise RuntimeError("secure channel expired (MSG)")

    def send(self, pt: bytes):
        self._ready()
        seq = self.send_ctr + 1
        nonce = seq.to_bytes(CFG.P2P_AEAD_NONCE_BYTES, "big")
        aad   = CFG.P2P_AEAD_AAD_PREFIX + CFG.DEFAULT_NET_ID.encode("utf-8")
        ct    = self.aes.encrypt(nonce, pt, aad)
        frame = {"type": "P2P_DATA", "seq": seq, "ct": ct.hex()}
        send_message(self.sock, json.dumps(frame).encode("utf-8"))
        self.send_ctr = seq
        self.msg_count += 1

    def recv(self, timeout: float):
        self._ready()
        raw = recv_message(self.sock, timeout=timeout)
        if not raw:
            return None
        obj = json.loads(raw.decode("utf-8"))
        if obj.get("type") != "P2P_DATA":
            raise ValueError("expecting P2P_DATA")
        seq = obj.get("seq")
        if not isinstance(seq, int):
            raise ValueError("missing seq")
        if seq <= self.recv_ctr:
            raise ValueError("replayed/out-of-order seq")
        nonce = seq.to_bytes(CFG.P2P_AEAD_NONCE_BYTES, "big")
        aad   = CFG.P2P_AEAD_AAD_PREFIX + CFG.DEFAULT_NET_ID.encode("utf-8")
        ct    = bytes.fromhex(obj["ct"])
        pt    = self.aes.decrypt(nonce, ct, aad)
        self.recv_ctr = seq
        self.msg_count += 1
        return pt