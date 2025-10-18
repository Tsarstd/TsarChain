# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP173; BIP39; libsecp256k1; Signal-X3DH; RFC7748-X25519; NIST-800-38D-AES-GCM

import os, json, hashlib, base64, appdirs, time, re, threading
from pathlib import Path
from typing import Dict, Optional, Tuple, Sequence, List
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der
from bech32 import bech32_encode, convertbits
from mnemonic import Mnemonic
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


# ---------------- Local Project (With Node) ----------------
from ..storage.kv import kv_enabled, get as kv_get, put as kv_put, delete as kv_delete
from ..utils.helpers import hash160
from ..core.tx import Tx
from ..utils import config as CFG


_CHAT_KEYS_DIR = os.path.join("data_user", "chat_keys")
os.makedirs(_CHAT_KEYS_DIR, exist_ok=True)

_PREKEY_DIR = os.path.join("data_user", "chat_prekeys")
os.makedirs(_PREKEY_DIR, exist_ok=True)

_SECURE_KV_DB = "secure_wallet"

_APP_SECRET_PATH = Path(os.path.join("data_user", ".app_secret.json"))
_APP_SECRET_LOCK = threading.Lock()
_APP_SECRET_CACHE: Optional[str] = None


def _secure_kv_key(namespace: str, key: str) -> bytes:
    return f"{namespace}:{key}".encode("utf-8")


def encrypt_blob(blob: bytes, password: str) -> Dict:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, blob, None)
    return {
        "alg": "AESGCM",
        "nonce": nonce.hex(),
        "ct": ct.hex(),
        "kdf": "scrypt",
        "salt": salt.hex(),
        "n": 2**15,
        "r": 8,
        "p": 1,
    }


def decrypt_blob(enc: Dict, password: str) -> bytes:
    if str(enc.get("alg")).upper() != "AESGCM":
        raise ValueError("Unsupported cipher")
    
    if str(enc.get("kdf")).lower() != "scrypt":
        raise ValueError("Unsupported kdf")
    
    salt = bytes.fromhex(enc["salt"])
    key = _derive_key(password, salt, n=int(enc.get("n", 2**15)), r=int(enc.get("r", 8)), p=int(enc.get("p", 1)))
    aes = AESGCM(key)
    nonce = bytes.fromhex(enc["nonce"])
    ct = bytes.fromhex(enc["ct"])
    return aes.decrypt(nonce, ct, None)


def _secure_backend_read(namespace: str, key: str, path: Optional[Path]) -> Tuple[Optional[Dict], bool]:
    raw = None
    from_file = False
    if kv_enabled():
        try:
            val = kv_get(_SECURE_KV_DB, _secure_kv_key(namespace, key))
        except Exception:
            val = None
        if val:
            raw = val.decode("utf-8")
    if raw is None and path is not None and path.exists():
        raw = path.read_text(encoding="utf-8")
        from_file = True
    if raw is None:
        return None, from_file
    try:
        obj = json.loads(raw)
    except Exception as exc:
        raise ValueError(f"secure storage corrupted for {namespace}:{key}") from exc
    return obj, from_file and kv_enabled()


def _secure_backend_write(namespace: str, key: str, path: Optional[Path], payload: Dict) -> None:
    data = json.dumps(payload, separators=(",", ":"))
    if kv_enabled():
        kv_put(_SECURE_KV_DB, _secure_kv_key(namespace, key), data.encode("utf-8"))
        if path is not None and path.exists():
            try:
                path.unlink()
            except Exception:
                pass
    else:
        if path is None:
            raise ValueError("file path required for secure storage")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding="utf-8")


def _secure_backend_delete(namespace: str, key: str, path: Optional[Path]) -> None:
    if kv_enabled():
        try:
            kv_delete(_SECURE_KV_DB, _secure_kv_key(namespace, key))
        except Exception:
            pass
    if path is not None and path.exists():
        try:
            path.unlink()
        except Exception:
            pass


def _get_app_secret_password() -> str:
    global _APP_SECRET_CACHE
    with _APP_SECRET_LOCK:
        if _APP_SECRET_CACHE:
            return _APP_SECRET_CACHE
        record, _ = _secure_backend_read("app_secret", "global", _APP_SECRET_PATH)
        secret_hex: Optional[str] = None
        if isinstance(record, dict):
            secret_hex = str(record.get("secret") or "") or None
        if not secret_hex:
            secret_hex = os.urandom(32).hex()
            payload = {"secret": secret_hex, "created": int(time.time())}
            _secure_backend_write("app_secret", "global", _APP_SECRET_PATH, payload)
            try:
                os.chmod(_APP_SECRET_PATH, 0o600)
            except Exception:
                pass
        password = base64.urlsafe_b64encode(bytes.fromhex(secret_hex)).decode("utf-8")
        _APP_SECRET_CACHE = password
        return password


def _app_secret_provider(_prompt: str = "") -> str:
    return _get_app_secret_password()


def _secure_load(namespace: str, key: str, path: Optional[Path], password_provider, prompt: str) -> Tuple[Optional[Dict], bool]:
    obj, migrated = _secure_backend_read(namespace, key, path)
    if obj is None:
        return None, False
    if "enc" in obj:
        if not callable(password_provider):
            raise ValueError("password required")
        pwd = password_provider(prompt)
        if not pwd:
            raise ValueError("password required")
        plain = decrypt_blob(obj["enc"], pwd)
        return json.loads(plain.decode("utf-8")), False
    return obj, True


def _secure_store(namespace: str, key: str, path: Optional[Path], data: Dict, password_provider, prompt: str) -> None:
    if not callable(password_provider):
        raise ValueError("password provider required")
    pwd = password_provider(prompt)
    if not pwd:
        raise ValueError("password required")
    enc = encrypt_blob(json.dumps(data, separators=(",", ":")).encode("utf-8"), pwd)
    payload = {"version": 1, "enc": enc}
    _secure_backend_write(namespace, key, path, payload)
def load_chat_state(default: Optional[Dict] = None) -> Dict:
    fallback = default or {"blocked": [], "pubcache": {}, "textsize": "Medium"}
    path_obj = Path(CFG.CHAT_STATE)
    try:
        data, legacy = _secure_load("chat_state", "default", path_obj, _app_secret_provider, "Load chat state")
    except Exception:
        return fallback.copy()
    if data is None:
        return fallback.copy()
    if legacy:
        try:
            _secure_store("chat_state", "default", path_obj, data, _app_secret_provider, "Migrate chat state")
        except Exception:
            pass
    return {
        "blocked": list(dict.fromkeys(data.get("blocked", []) or [])),
        "pubcache": data.get("pubcache") or {},
        "textsize": data.get("textsize") or fallback["textsize"],
    }


def save_chat_state(data: Dict) -> None:
    path_obj = Path(CFG.CHAT_STATE)
    payload = {
        "blocked": sorted(set(data.get("blocked", []) or [])),
        "pubcache": data.get("pubcache") or {},
        "textsize": data.get("textsize") or "Medium",
    }
    _secure_store("chat_state", "default", path_obj, payload, _app_secret_provider, "Store chat state")


def load_wallet_registry(default: Optional[Sequence[str]] = None) -> List[str]:
    fallback = list(default or [])
    path_obj = Path(CFG.REGISTRY_PATH)
    try:
        data, legacy = _secure_load("wallet_registry", "default", path_obj, _app_secret_provider, "Load wallet registry")
    except Exception:
        return fallback
    if data is None:
        return fallback
    if legacy:
        try:
            _secure_store("wallet_registry", "default", path_obj, data, _app_secret_provider, "Migrate wallet registry")
        except Exception:
            pass
    wallets = data.get("wallets") if isinstance(data, dict) else None
    if not isinstance(wallets, list):
        return fallback
    seen: List[str] = []
    for addr in wallets:
        a = (addr or "").strip().lower()
        if a and a not in seen:
            seen.append(a)
    return seen


def save_wallet_registry(addrs: Sequence[str]) -> None:
    path_obj = Path(CFG.REGISTRY_PATH)
    uniq: List[str] = []
    for addr in addrs:
        a = (addr or "").strip().lower()
        if a and a not in uniq:
            uniq.append(a)
    payload = {"wallets": uniq, "updated": int(time.time())}
    _secure_store("wallet_registry", "default", path_obj, payload, _app_secret_provider, "Store wallet registry")


def ensure_wallet_registry(default: Optional[Sequence[str]] = None) -> List[str]:
    wallets = load_wallet_registry(default)
    if not wallets and default:
        save_wallet_registry(default)
        return list(default)
    if not wallets:
        save_wallet_registry([])
    return wallets


def load_user_key_record() -> Optional[Dict]:
    path_obj = Path(CFG.USER_KEY_PATH)
    try:
        data, legacy = _secure_load("user_key", "default", path_obj, _app_secret_provider, "Load user key")
    except Exception:
        data = None
        legacy = False
    if data is None:
        return None
    if legacy:
        try:
            _secure_store("user_key", "default", path_obj, data, _app_secret_provider, "Migrate user key")
        except Exception:
            pass
    return data


def save_user_key_record(record: Dict) -> None:
    path_obj = Path(CFG.USER_KEY_PATH)
    _secure_store("user_key", "default", path_obj, record, _app_secret_provider, "Store user key")


# ---------------- Secure Path ----------------
def get_secure_wallet_path():
    config_dir = appdirs.user_config_dir(CFG.APP_NAME, CFG.APP_AUTHOR)
    os.makedirs(config_dir, exist_ok=True, mode=0o700)
    return os.path.join(config_dir, "wallets.enc")

# -------------- PreKey management --------------
def _prekey_path(addr: str) -> str:
    safe = re.sub(r"[^0-9a-z]", "_", addr.lower())
    return os.path.join(_PREKEY_DIR, f"{safe}.json")

def _prekey_storage_key(addr: str) -> str:
    return addr.lower()

def _load_prekey_record(addr: str, password_provider=None) -> Optional[Dict]:
    addr_c = addr.lower()
    path = Path(_prekey_path(addr_c))
    record, legacy = _secure_load(
        namespace="chat_prekey",
        key=addr_c,
        path=path,
        password_provider=password_provider,
        prompt=f"Unlock chat prekeys for {addr_c}",
    )
    if record is None:
        return None
    if legacy:
        _secure_store("chat_prekey", addr_c, path, record, password_provider, f"Migrate chat prekeys for {addr_c}")
    return record

def _store_prekey_record(addr: str, record: Dict, password_provider) -> None:
    addr_c = addr.lower()
    path = Path(_prekey_path(addr_c))
    _secure_store("chat_prekey", addr_c, path, record, password_provider, f"Store chat prekeys for {addr_c}")

def _ecdsa_sign_spend(priv_hex: str, data: bytes) -> str:
    sk = SigningKey.from_string(bytes.fromhex(priv_hex), curve=SECP256k1)
    sig_der = sk.sign_deterministic(data, hashfunc=hashlib.sha256, sigencode=sigencode_der)
    return sig_der.hex()

def ensure_signed_prekey(addr: str, password_provider=None) -> dict:
    addr_c = addr.lower()
    record = _load_prekey_record(addr_c, password_provider)
    if record and record.get("spk") and record.get("spk_sk") and record.get("sig"):
        record.setdefault("opk_list", [])
        record.setdefault("opk_pairs", [])
        record.setdefault("addr", addr_c)
        return record

    if not callable(password_provider):
        raise ValueError("password required")

    pwd = password_provider(addr)
    if not pwd:
        raise ValueError("password required")
    sp_priv = get_priv_for_address(addr, pwd)
    sp_pub = pubkey_from_privhex(sp_priv)
    spk_sk, spk_pk = chat_dh_gen_keypair()
    payload = b"TSAR-SPK|" + bytes.fromhex(spk_pk) + b"|" + sp_pub
    sig = _ecdsa_sign_spend(sp_priv, payload)

    record = record or {}
    record.update({
        "addr": addr_c,
        "ik": record.get("ik"),
        "spk": spk_pk,
        "spk_sk": spk_sk,
        "sig": sig,
        "created": int(time.time()),
        "opk_list": record.get("opk_list") or [],
        "opk_pairs": record.get("opk_pairs") or [],
    })

    _store_prekey_record(addr_c, record, password_provider)
    return record

def add_one_time_prekeys(addr: str, n: int, password_provider=None) -> dict:
    if not callable(password_provider):
        raise ValueError("password required")
    record = ensure_signed_prekey(addr, password_provider)
    record.setdefault("opk_list", [])
    record.setdefault("opk_pairs", [])
    for _ in range(int(n)):
        sk, pk = chat_dh_gen_keypair()
        record["opk_list"].append(pk)
        record["opk_pairs"].append({"sk": sk, "pk": pk, "used": False})
    _store_prekey_record(addr, record, password_provider)
    return record

def get_prekey_inventory(addr: str, password_provider=None) -> dict:
    record = _load_prekey_record(addr, password_provider)
    if record is None:
        return {"opk_queue": 0, "opk_unused_pairs": 0, "created": 0}
    opk_queue = len(record.get("opk_list") or [])
    unused_pairs = sum(1 for it in record.get("opk_pairs") or [] if not it.get("used"))
    return {
        "opk_queue": opk_queue,
        "opk_unused_pairs": unused_pairs,
        "created": int(record.get("created") or 0),
    }

def rotate_signed_prekey(addr: str, password_provider=None) -> dict:
    if not callable(password_provider):
        raise ValueError("password provider required for SPK rotation")
    pwd = password_provider(addr)
    if not pwd:
        raise ValueError("password required")
    sp_priv = get_priv_for_address(addr, pwd)
    sp_pub  = pubkey_from_privhex(sp_priv)
    spk_sk, spk_pk = chat_dh_gen_keypair()
    payload = b"TSAR-SPK|" + bytes.fromhex(spk_pk) + b"|" + sp_pub
    sig = _ecdsa_sign_spend(sp_priv, payload)
    record = _load_prekey_record(addr, password_provider) or {}
    record.update({
        "addr": addr.lower(),
        "ik": record.get("ik"),
        "spk": spk_pk,
        "spk_sk": spk_sk,
        "sig": sig,
        "created": int(time.time()),
        "opk_list": [],
        "opk_pairs": [],
    })
    _store_prekey_record(addr, record, password_provider)
    return record

def get_local_prekeys_for_recv(addr: str, password_provider=None) -> dict:
    record = _load_prekey_record(addr, password_provider)
    if not record:
        return {}
    return {
        "spk_sk": record.get("spk_sk"),
        "spk": record.get("spk"),
        "opk_pairs": record.get("opk_pairs") or [],
    }

def consume_opk_priv(addr: str, opk_pk_hex: str, password_provider=None) -> str | None:
    record = _load_prekey_record(addr, password_provider)
    if not record:
        return None
    pairs = record.get("opk_pairs") or []
    for it in pairs:
        if (it.get("pk") or "").lower() == (opk_pk_hex or "").lower() and not it.get("used"):
            it["used"] = True
            _store_prekey_record(addr, record, password_provider)
            return it.get("sk")
    return None

def get_prekey_bundle_local(addr: str, password_provider=None) -> dict:
    _, ik = load_or_create_chat_dh_key(addr, password_provider)
    b = ensure_signed_prekey(addr, password_provider)
    opk = None
    if (b.get("opk_list") or []):
        opk = (b["opk_list"]).pop(0)
        _store_prekey_record(addr, b, password_provider)
    else:
        _store_prekey_record(addr, b, password_provider)
    return {"ik": ik, "spk": b["spk"], "sig": b["sig"], "opk": opk}


def _session_storage_key(me: str, peer: str) -> str:
    return f"{(me or '').lower()}|{(peer or '').lower()}"


def _session_path(me: str, peer: str) -> Path:
    base = Path(CFG.CHAT_SESSION_DIR)
    me_c = (me or "").lower() or "_"
    peer_c = (peer or "").lower() or "_"
    return base / me_c / peer_c


def load_chat_session(me: str, peer: str, password_provider) -> Optional[Dict]:
    key = _session_storage_key(me, peer)
    path = _session_path(me, peer)
    record, legacy = _secure_load(
        namespace="chat_session",
        key=key,
        path=path,
        password_provider=password_provider,
        prompt=f"Unlock chat session for {me.lower() if me else ''}",
    )
    if record and legacy:
        _secure_store("chat_session", key, path, record, password_provider,
                      f"Migrate chat session for {me.lower() if me else ''}")
    return record


def store_chat_session(me: str, peer: str, record: Dict, password_provider) -> None:
    key = _session_storage_key(me, peer)
    path = _session_path(me, peer)
    _secure_store("chat_session", key, path, record, password_provider,
                  f"Store chat session for {me.lower() if me else ''}")


def delete_chat_session(me: str, peer: str) -> None:
    key = _session_storage_key(me, peer)
    path = _session_path(me, peer)
    _secure_backend_delete("chat_session", key, path)

# ---------------- Encrypt - Decrypt .JSON ----------------
def encrypt_wallet_file(data: dict, master_password: str) -> bytes:
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    
    f = Fernet(key)
    encrypted_data = f.encrypt(json.dumps(data).encode())

    return salt + encrypted_data

def decrypt_wallet_file(encrypted_data: bytes, master_password: str) -> dict:
    salt = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    
    f = Fernet(key)
    decrypted_data = f.decrypt(ciphertext)
    return json.loads(decrypted_data.decode())


# ---------------- Chat DH key (with optional encryption) ----------------
def _chat_key_path(addr: str) -> str:
    return os.path.join(_CHAT_KEYS_DIR, f"{addr.lower()}.json")

def load_or_create_chat_dh_key(addr: str, password_provider=None) -> tuple[str, str]:
    addr_c = addr.lower()
    path = Path(_chat_key_path(addr_c))
    data, legacy = _secure_load(
        namespace="chat_key",
        key=addr_c,
        path=path,
        password_provider=password_provider,
        prompt=f"Unlock chat key for {addr_c}",
    )
    if data:
        if legacy:
            _secure_store("chat_key", addr_c, path, data, password_provider,
                          f"Migrate chat key for {addr_c}")
        sk_hex = data.get("sk_hex")
        pk_hex = data.get("pk_hex")
        if not sk_hex or not pk_hex:
            raise ValueError("Chat key store corrupted")
        return sk_hex, pk_hex

    if not callable(password_provider):
        raise ValueError("Password required to create chat key")

    sk_hex, pk_hex = chat_dh_gen_keypair()
    record = {"sk_hex": sk_hex, "pk_hex": pk_hex, "created": int(time.time())}
    _secure_store("chat_key", addr_c, path, record, password_provider,
                  f"Create encrypted chat key for {addr_c}")
    return sk_hex, pk_hex

def chat_dh_gen_keypair() -> tuple[str, str]:
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key()
    sk_hex = sk.private_bytes(
        encoding = serialization.Encoding.Raw,
        format   = serialization.PrivateFormat.Raw,
        encryption_algorithm = serialization.NoEncryption()
    ).hex()
    pk_hex = pk.public_bytes(
        encoding = serialization.Encoding.Raw,
        format   = serialization.PublicFormat.Raw
    ).hex()
    
    return sk_hex, pk_hex

def _derive_key(password: str, salt: bytes, n=2**15, r=8, p=1) -> bytes:
    """Scrypt KDF"""
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_privkey(hex_priv: str, password: str) -> Dict:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, bytes.fromhex(hex_priv), None)
    return {
        "kdf": "scrypt",
        "kdf_salt": salt.hex(),
        "kdf_n": 2**15,
        "kdf_r": 8,
        "kdf_p": 1,
        "cipher": "AESGCM",
        "nonce": nonce.hex(),
        "ct": ct.hex()
    }

def decrypt_privkey(enc_blob: Dict, password: str) -> str:
    salt = bytes.fromhex(enc_blob["kdf_salt"])
    key = _derive_key(password, salt,
                      n=enc_blob.get("kdf_n", 2**15),
                      r=enc_blob.get("kdf_r", 8),
                      p=enc_blob.get("kdf_p", 1))
    aes = AESGCM(key)
    nonce = bytes.fromhex(enc_blob["nonce"])
    ct = bytes.fromhex(enc_blob["ct"])
    plain = aes.decrypt(nonce, ct, None)
    return plain.hex()

# ---------------- Address helpers ----------------
WALLET_FILE = get_secure_wallet_path()


def pubkey_from_privhex(priv_hex: str) -> bytes:
    sk = SigningKey.from_string(bytes.fromhex(priv_hex), curve=SECP256k1)
    vk = sk.get_verifying_key()
    px = vk.pubkey.point.x()
    py = vk.pubkey.point.y()
    prefix = b'\x02' if (py % 2 == 0) else b'\x03'
    return prefix + px.to_bytes(32, 'big')

def pubkey_to_tsar_address(pubkey_bytes: bytes) -> str:
    pubkey_hash = hash160(pubkey_bytes)
    witver = 0
    converted = convertbits(pubkey_hash, 8, 5, True)
    data = [witver] + converted
    return bech32_encode(CFG.ADDRESS_PREFIX, data)



# ========= Keystore v2: multi-wallet ========= #


KEYSTORE_VERSION = 2


def _empty_keystore():
    return {"version": KEYSTORE_VERSION, "encrypted": True,
            "wallets": {}, "default": None, "contacts": {}}

def _read_file_bytes(path):
    with open(path, "rb") as f:
        return f.read()

def _write_atomic(path, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def load_keystore(password: str) -> dict:
    if not os.path.exists(WALLET_FILE):
        return _empty_keystore()

    raw = _read_file_bytes(WALLET_FILE)
    try:
        root = decrypt_wallet_file(raw, password)
    except Exception:
        try:
            root = json.loads(raw.decode("utf-8"))
        except Exception:
            raise ValueError("Invalid password or corrupted keystore")

    if root.get("version") == KEYSTORE_VERSION and "wallets" in root:
        if "contacts" not in root or not isinstance(root["contacts"], dict):
            root["contacts"] = {}
        if ks_default := root.get("default"):
            if ks_default not in root["wallets"]:
                root["default"] = next(iter(root["wallets"]), None)
        return root

    raise ValueError("Unsupported keystore format")

def save_keystore(ks: dict, password: str):
    ks["version"] = KEYSTORE_VERSION
    enc = encrypt_wallet_file(ks, password)
    _write_atomic(WALLET_FILE, enc)

def add_privkey_to_keystore(priv_hex: str, password: str) -> str:
    pubkey_bytes = pubkey_from_privhex(priv_hex)
    address = pubkey_to_tsar_address(pubkey_bytes)

    ks = load_keystore(password)
    if address in ks["wallets"]:
        return address

    blob = encrypt_privkey(priv_hex, password)
    ks["wallets"][address] = {"payload": blob, "meta": {"address": address}}
    if not ks.get("default"):
        ks["default"] = address
    save_keystore(ks, password)
    return address

def get_priv_for_address(address: str, password: str) -> str:
    ks = load_keystore(password)
    entry = ks["wallets"].get(address)
    if not entry:
        raise ValueError("Address not found in keystore")
    return decrypt_privkey(entry["payload"], password)

def list_addresses_in_keystore(password: str) -> list[str]:
    ks = load_keystore(password)
    return list(ks["wallets"].keys())

# ======= Contact Management ========

def list_contacts_in_keystore(password: str) -> dict[str, str]:
    ks = load_keystore(password)
    c = ks.get("contacts") or {}
    out = {}
    for addr, meta in c.items():
        alias = (meta or {}).get("alias", "").strip()
        if alias:
            out[str(addr).lower()] = alias
    return out

def upsert_contact_in_keystore(address: str, alias: str, password: str) -> bool:
    addr = (address or "").strip().lower()
    if not addr:
        raise ValueError("address required")
    if not alias or not alias.strip():
        raise ValueError("alias required")

    ks = load_keystore(password)
    if "contacts" not in ks or not isinstance(ks["contacts"], dict):
        ks["contacts"] = {}
    now = int(time.time())
    prev = ks["contacts"].get(addr) or {}
    ks["contacts"][addr] = {
        "alias": alias.strip(),
        "created": int(prev.get("created", now)),
        "updated": now,}
    save_keystore(ks, password)
    return True

def delete_contact_from_keystore(address: str, password: str) -> bool:
    addr = (address or "").strip().lower()
    ks = load_keystore(password)
    c = ks.get("contacts") or {}
    if addr in c:
        c.pop(addr, None)
        ks["contacts"] = c
        save_keystore(ks, password)
        return True
    return False


# --- Keystore utilities: delete & backup ---


def delete_address_from_keystore(address: str, password: str) -> bool:
    ks = load_keystore(password)
    if address not in ks["wallets"]:
        return False
    ks["wallets"].pop(address)
    if ks.get("default") == address:
        ks["default"] = next(iter(ks["wallets"]), None)
    save_keystore(ks, password)
    return True


def get_encrypted_keystore_bytes() -> bytes:
    if not os.path.exists(WALLET_FILE):
        raise FileNotFoundError("Keystore file not found")
    return _read_file_bytes(WALLET_FILE)


def restore_keystore_bytes(data: bytes, password: str):
    try:
        root = decrypt_wallet_file(data, password)
        if root.get("version") == KEYSTORE_VERSION and "wallets" in root:
            _write_atomic(WALLET_FILE, data)
            return
    except Exception:
        pass
    try:
        root = json.loads(data.decode("utf-8"))
    except Exception:
        raise ValueError("Invalid backup or wrong password")

    if root.get("version") == 1 and "payload" in root:
        addr = (root.get("meta") or {}).get("address")
        ks = _empty_keystore()
        if addr:
            ks["wallets"][addr] = {"payload": root["payload"], "meta": {"address": addr}}
            ks["default"] = addr
        enc = encrypt_wallet_file(ks, password)
        _write_atomic(WALLET_FILE, enc)
        return

    raise ValueError("Unsupported backup format")

def _write_atomic_json(path: str, obj: dict):
    data = json.dumps(obj, indent=2).encode("utf-8")
    _write_atomic(path, data)

def _hist_dir() -> str:
    p = os.path.join(CFG.WALLET_DATA_DIR, "history")
    os.makedirs(p, exist_ok=True, mode=0o700)
    return p

def _hist_path(address: str) -> str:
    safe = re.sub(r"[^0-9a-z]", "_", address.lower())
    return os.path.join(_hist_dir(), f"{safe}.json")

def _load_cache_raw(address: str) -> dict:
    path = _hist_path(address)
    if not os.path.exists(path):
        return {"version": 1, "address": address, "last_updated": 0, "items": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            root = json.load(f)
        if not isinstance(root.get("items"), dict):
            root["items"] = {}
        return root
    except Exception:
        return {"version": 1, "address": address, "last_updated": 0, "items": {}}

def _normalize_item(raw: dict) -> dict:
    txid = str(raw.get("txid","")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", txid):  # invalid txid → skip at the merge layer
        return {}
    item = {
        "txid": txid,
        "address": raw.get("address",""),
        "from": raw.get("from",""),
        "to": raw.get("to",""),
        "amount": int(raw.get("amount", 0) or 0),
        "status": str(raw.get("status","")),
        "confirmations": int(raw.get("confirmations", 0) or 0),
        "height": (None if raw.get("height", None) in ("", None) else int(raw.get("height"))),
        "direction": str(raw.get("direction","")),
    }
    return item

# ---------------- Security Layer ----------------


class Security:
    
    _attempts = {}
    _max_attempts = 5
    _lockout_time = 300
    
    @staticmethod
    def check_attempt(address: str) -> bool:
        if address in Security._attempts:
            attempts, lockout_until = Security._attempts[address]
            if time.time() < lockout_until:
                raise ValueError(f"Account locked. Try again in {int(lockout_until - time.time())} seconds")
        return True
    
    @staticmethod
    def record_failure(address: str):
        if address not in Security._attempts:
            Security._attempts[address] = [1, 0]
        else:
            Security._attempts[address][0] += 1
        
        if Security._attempts[address][0] >= Security._max_attempts:
            Security._attempts[address][1] = time.time() + Security._lockout_time
            raise ValueError("Too many failed attempts. Account locked for 5 minutes")
    
    @staticmethod
    def record_success(address: str):
        if address in Security._attempts:
            del Security._attempts[address]
    
    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, dict]:
        has_len8   = len(password) >= 8
        has_upper  = any(c.isupper() for c in password)
        has_lower  = any(c.islower() for c in password)
        has_digit  = any(c.isdigit() for c in password)
        has_special= any(c in "!@#$%^&*()_+-=[]{}|;:,<>?/" for c in password)

        checks = [has_len8, has_upper, has_lower, has_digit, has_special]
        score = sum(1 for x in checks if x)

        if len(password) >= 12 and score == 5:
            score = 5

        labels = ("very weak", "weak", "fair", "good", "strong", "excellent")
        label = labels[max(0, min(5, score))]

        ok = all(checks)
        return ok, {"score": score, "label": label}
    
    @staticmethod
    def secure_erase(data):
        try:
            if isinstance(data, str):
                data_bytes = bytearray(data.encode('utf-8'))
                for i in range(len(data_bytes)):
                    data_bytes[i] = 0
                return bytes(data_bytes)
            
            elif isinstance(data, (bytes, bytearray)):
                mutable_data = bytearray(data)
                for i in range(len(mutable_data)):
                    mutable_data[i] = 0
                return bytes(mutable_data)
            
            return data
            
        except Exception as e:
            print(f"Secure erase warning: {e}")
            return data
            
    @staticmethod
    def log_security_event(event_type: str, address: str = "", details: str = ""):
        log_dir = appdirs.user_log_dir("TsarWallet", "TsarStudio")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "security.log")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp} | {event_type} | {address} | {details}\n"
        
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(log_entry)



# ---------------- Wallet API ----------------

class Wallet:
    @staticmethod
    def sign_prepared_tx(unsigned_tx_dict, inputs_meta, privkey_hex):
        tx = Tx.from_dict(unsigned_tx_dict)
        if len(tx.inputs) != len(inputs_meta):
            raise ValueError("inputs mismatch")
        for i, meta in enumerate(inputs_meta):
            script_pubkey = bytes.fromhex(meta["script_pubkey"])
            amount        = int(meta["amount"])
            ok = tx.sign_input(i, privkey_hex, script_pubkey, amount)
            if not ok:
                raise ValueError(f"sign failed at input {i}")

        input_amounts = [int(m["amount"]) for m in inputs_meta]
        tx.set_fee_from_input_amounts(input_amounts)
        tx.compute_txid()
        return tx

    @staticmethod
    def create(password: str, mnemonic_strength: int = 128):
        if not password:
            raise ValueError("Password required")
        ok, msg = Security.validate_password_strength(password)
        if not ok:
            raise ValueError(f"Weak password: {msg}")

        mnemo = Mnemonic("english")
        mnemonic = mnemo.generate(strength=mnemonic_strength)
        seed = mnemo.to_seed(mnemonic, passphrase="")
        priv_bytes = hashlib.sha256(seed).digest()[:32]
        priv_hex = priv_bytes.hex()

        address = add_privkey_to_keystore(priv_hex, password)
        return address, mnemonic


    @staticmethod
    def create_from_privkey_hex(priv_hex: str, password: str):
        if not password:
            raise ValueError("Password required")
        if len(priv_hex.strip()) not in (64, 66):
            raise ValueError("Invalid private key length")
        return add_privkey_to_keystore(priv_hex.strip(), password)
    
    @staticmethod
    def create_from_mnemonic(mnemonic: str, password: str):
        mnemo = Mnemonic("english")
        if not mnemo.check(mnemonic):
            raise ValueError("Invalid mnemonic phrase")
        seed = mnemo.to_seed(mnemonic, passphrase="")
        priv_bytes = hashlib.sha256(seed).digest()[:32]
        priv_hex = priv_bytes.hex()
        return add_privkey_to_keystore(priv_hex, password)

    @staticmethod
    def unlock(password: str, address: str | None = None) -> Dict:
        if not os.path.exists(WALLET_FILE):
            raise FileNotFoundError("Wallet file not found")
        try:
            ks = load_keystore(password)
            wallets: dict = ks.get("wallets", {})
            if not wallets:
                raise ValueError("Keystore empty")

            target_addr = address
            if not target_addr:
                target_addr = ks.get("default") or (next(iter(wallets)) if wallets else None)
            if not target_addr or target_addr not in wallets:
                if len(wallets) == 1:
                    target_addr = next(iter(wallets))
                else:
                    raise ValueError("Multiple wallets present – specify address")

            Security.check_attempt(target_addr)
            try:
                enc_blob = wallets[target_addr]["payload"]
                priv_hex = decrypt_privkey(enc_blob, password)
                Security.record_success(target_addr)
                Security.log_security_event("WALLET_UNLOCKED", target_addr, "Successful unlock (v2)")
                return {"private_key": priv_hex, "address": target_addr}
            except Exception as e:
                Security.record_failure(target_addr)
                Security.log_security_event("UNLOCK_FAILED", target_addr, f"Failed attempt (v2): {e}")
                raise

        except Exception:
            with open(WALLET_FILE, "rb") as f:
                encrypted_data = f.read()
            try:
                data = decrypt_wallet_file(encrypted_data, password)
            except Exception:
                try:
                    data = json.loads(encrypted_data.decode("utf-8"))
                    data = data[0] if isinstance(data, list) else data
                except Exception as e:
                    Security.log_security_event("DECRYPT_FAILED", "", f"File decryption failed: {e}")
                    raise ValueError("Invalid password or corrupted wallet file")

            addr = (data.get("meta") or {}).get("address")
            Security.check_attempt(addr)
            try:
                priv_hex = decrypt_privkey(data["payload"], password)
                Security.record_success(addr)
                Security.log_security_event("WALLET_UNLOCKED", addr, "Successful unlock (v1)")
                return {"private_key": priv_hex, "address": addr}
            except Exception as e:
                Security.record_failure(addr)
                Security.log_security_event("UNLOCK_FAILED", addr, f"Failed attempt (v1): {e}")
                raise


    @staticmethod
    def from_private_key_hex(priv_hex: str):
        try:
            pubkey_bytes = pubkey_from_privhex(priv_hex)
            address = pubkey_to_tsar_address(pubkey_bytes)
            return {"private_key": priv_hex, "address": address}
        except Exception as e:
            print("[!] from_private_key_hex error:", e)
            return None
        
        # ---- Local history cache helpers ----

    @staticmethod
    def history_cache_merge(address: str, items: list[dict]) -> tuple[int,int]:
        root = _load_cache_raw(address)
        store: dict = root.get("items", {})
        now = int(time.time())
        added = updated = 0
        for r in (items or []):
            norm = _normalize_item(r)
            txid = norm.get("txid")
            if not txid:  # skip invalid
                continue
            prev = store.get(txid)
            if prev:
                # keep first_seen, update data + last_seen
                first_seen = prev.get("first_seen", now)
                prev.update(norm)
                prev["first_seen"] = first_seen
                prev["last_seen"] = now
                store[txid] = prev
                updated += 1
            else:
                norm["first_seen"] = now
                norm["last_seen"] = now
                store[txid] = norm
                added += 1
        root["items"] = store
        root["last_updated"] = now
        _write_atomic_json(_hist_path(address), root)
        return added, updated

    @staticmethod
    def history_cache_list(address: str, direction: str | None = None,
                           status: str | None = None, limit: int = 50, offset: int = 0) -> dict:
        root = _load_cache_raw(address)
        items = list((root.get("items") or {}).values())

        # filter
        if direction:
            items = [x for x in items if str(x.get("direction","")) == direction]
        if status:
            items = [x for x in items if str(x.get("status","")) == status]

        # sort: confirmed first by height desc, then unconfirmed by last_seen desc
        def _sort_key(x):
            conf = 1 if x.get("status") == "confirmed" else 0
            h = x.get("height")
            h_sort = (h if isinstance(h, int) else -1)
            return (conf, h_sort, x.get("last_seen", 0))
        items.sort(key=_sort_key, reverse=True)

        total = len(items)
        start = max(0, int(offset))
        end = max(start, start + int(limit or 50))
        page = items[start:end]
        return {"total": total, "items": page, "last_updated": root.get("last_updated", 0)}

    @staticmethod
    def history_cache_clear(address: str) -> bool:
        try:
            p = _hist_path(address)
            if os.path.exists(p):
                os.remove(p)
            return True
        except Exception:
            return False

    @staticmethod
    def history_cache_path(address: str) -> str:
        return _hist_path(address)
