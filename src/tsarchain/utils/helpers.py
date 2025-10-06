# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP143; BIP141; BIP173; CompactSize; Merkle; libsecp256k1; LowS-Policy
from __future__ import annotations
import hashlib, json, secrets, string
from bech32 import bech32_decode, convertbits
from typing import Union, Tuple
from ecdsa import SECP256k1, util, VerifyingKey

from ..utils import config as CFG

SIGHASH_ALL = 1

# opcode constants
OP_0 = 0x00
OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e
OP_1 = 0x51
OP_16 = 0x60
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE
OP_CHECKMULTISIGVERIFY = 0xAF
OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_RETURN = 0x6a

# ======== SIGNATURE VERIFY HELPERS ========
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HALF_N = SECP256K1_N // 2

def print_banner():
    banner = r"""
  _______ ______  _____   ____  _      ____  _               _             
 |__   __|  ____|/ ____| |  _ \(_)    / __ \| |             | |            
    | |  | |__  | (___   | |_) |_ ___| |  | | |__  _   _ ___| |_ ___  _ __ 
    | |  |  __|  \___ \  |  _ <| / __| |  | | '_ \| | | / __| __/ _ \| '__|
    | |  | |____ ____) | | |_) | \__ \ |__| | |_) | |_| \__ \ || (_) | |   
    |_|  |______|_____/  |____/|_|___/\____/|_.__/ \__,_|___/\__\___/|_|   
                                                                          
                                Tsar Chain CLI
                Long Live The Voice Sovereignty Monetary System
    """
    print(banner)

# -----------------------------
# SIGOPS UTIL
# -----------------------------

def to_bytes(x) -> bytes:
    try:
        if isinstance(x, Script):
            return x.serialize()
    except Exception:
        pass
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, str):
        try:
            return bytes.fromhex(x)
        except Exception:
            return x.encode("utf-8", "ignore")
    return b""

def small_int(op):
    if op == OP_0:
        return 0
    if isinstance(op, int) and OP_1 <= op <= OP_16:
        return op - (OP_1 - 1)
    return None

def read_push(script: bytes, i: int):
    if i >= len(script):
        return None, i
    op = script[i]; i += 1
    if op <= 0x4b:
        ln = op
    elif op == OP_PUSHDATA1:
        if i >= len(script): return None, i
        ln = script[i]; i += 1
    elif op == OP_PUSHDATA2:
        if i+1 >= len(script): return None, i
        ln = int.from_bytes(script[i:i+2], "little"); i += 2
    elif op == OP_PUSHDATA4:
        if i+3 >= len(script): return None, i
        ln = int.from_bytes(script[i:i+4], "little"); i += 4
    else:
        return (op, None), i-1
    data = script[i:i+ln]; i += ln
    return (None, data), i

def parse_ops(script: bytes):
    ops = []
    i = 0
    while i < len(script):
        b = script[i]
        if b <= 0x4b or b in (OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4):
            item, i2 = read_push(script, i)
            if item is None:
                break
            ops.append(item); i = i2
        else:
            ops.append((b, None)); i += 1
    return ops

def count_sigops_in_script(script: bytes) -> int:
    ops = parse_ops(script)
    total = 0
    for idx, (op, data) in enumerate(ops):
        if op in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
            total += 1
        elif op in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
            n = None
            j = idx - 1
            while j >= 0:
                opj, dataj = ops[j]
                si = small_int(opj) if opj is not None else None
                if si is not None:
                    n = si; break
                j -= 1
            total += min(n or 20, 20)
    return total

def is_p2pkh(spk: bytes) -> bool:
    return (
        len(spk) == 25 and
        spk[0] == OP_DUP and spk[1] == OP_HASH160 and
        spk[2] == 0x14 and
        spk[23] == OP_EQUALVERIFY and spk[24] == OP_CHECKSIG
    )

def is_p2sh(spk: bytes) -> bool:
    return len(spk) == 23 and spk[0] == OP_HASH160 and spk[1] == 0x14 and spk[-1] == OP_EQUAL

def is_p2wpkh(spk: bytes) -> bool:
    return len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14

def is_p2wsh(spk: bytes) -> bool:
    return len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20

def last_pushdata(script_sig: bytes) -> bytes | None:
    ops = parse_ops(script_sig)
    for op, data in reversed(ops):
        if op is None and data is not None:
            return data
    return None


# -----------------------------
# ENDIANNESS
# -----------------------------

def int_to_little_endian(n: int, length: int) -> bytes:
    return n.to_bytes(length, 'little')

def little_endian_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'little')


# -----------------------------
# HASHING
# -----------------------------

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def ripemd160(b: bytes) -> bytes:
    h = hashlib.new('ripemd160')
    h.update(b)
    return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))

def double_sha256(data: bytes) -> bytes:
    return sha256(sha256(data))

def hash256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# -----------------------------
# VARINT ENCODING (Bitcoin-style)
# -----------------------------

def encode_varint(i: int) -> bytes:
    if i < 0xfd:
        return i.to_bytes(1, 'little')
    elif i <= 0xffff:
        return b'\xfd' + i.to_bytes(2, 'little')
    elif i <= 0xffffffff:
        return b'\xfe' + i.to_bytes(4, 'little')
    else:
        return b'\xff' + i.to_bytes(8, 'little')

def serialize_bytes_with_len(b: bytes) -> bytes:
    return encode_varint(len(b)) + b


# -----------------------------
# SERIALIZATION / DESERIALIZATION
# -----------------------------

def serialize(obj: Union[dict, list, object]) -> bytes:
    def convert(o):
        if hasattr(o, "to_dict"):
            return o.to_dict()
        elif isinstance(o, bytes):
            return o.hex()
        raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")
    return json.dumps(obj, default=convert, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


# -----------------------------
# DECODE SIG
# -----------------------------

def decode_address(address: str) -> bytes:
    hrp, data = bech32_decode(address)
    if hrp != CFG.ADDRESS_PREFIX:
        raise ValueError(f"Invalid address prefix: expected '{CFG.ADDRESS_PREFIX}', got '{hrp}'")
    if not data:
        raise ValueError("Invalid Bech32 address: no data")
    witver = data[0]
    if witver != 0:
        raise ValueError(f"Unsupported witness version: {witver}")
    decoded = convertbits(data[1:], 5, 8, False)
    if len(decoded) != 20:
        raise ValueError(f"Invalid witness program length: {len(decoded)} (expected 20 for P2WPKH)")
    return bytes(decoded)

def decode_der_sig(signature: bytes):
    if signature[0] != 0x30:
        raise ValueError("Invalid DER encoding")
    r_len = signature[3]
    r = int.from_bytes(signature[4:4+r_len], 'big')
    s_index = 4 + r_len + 2
    s_len = signature[4 + r_len + 1]
    s = int.from_bytes(signature[s_index:s_index + s_len], 'big')
    return r, s

# -------------------- Merkle root --------------------

def merkle_root(transactions):
    if not transactions:
        return b"\x00" * 32

    txids = []
    for tx in transactions:
        b = None
        if isinstance(tx, (bytes, bytearray)):
            b = bytes(tx)
        elif hasattr(tx, "txid"):
            b = tx.txid
        elif hasattr(tx, "hash"):
            b = tx.hash()
        else:
            raise TypeError("merkle_root expects 32-byte txids or objects with .txid/.hash")

        if isinstance(b, str):
            b = bytes.fromhex(b)
        b = bytes(b)
        if len(b) != 32:
            raise ValueError(f"txid must be 32 bytes, got {len(b)}")
        txids.append(b)

    if len(txids) == 1:
        return txids[0]

    layer = txids
    while len(layer) > 1:
        if len(layer) & 1:
            layer = layer + [layer[-1]]
        nxt = []
        for i in range(0, len(layer), 2):
            nxt.append(hash256(layer[i] + layer[i + 1]))
        layer = nxt
    return layer[0]



# --- Compact bits <-> target (kanonik & unsigned) ---

def bits_to_target(bits: int) -> int:
    exp  = (bits >> 24) & 0xff
    mant = bits & 0x007fffff
    if exp >= 3:
        return mant << (8 * (exp - 3))
    else:
        return mant >> (8 * (3 - exp))

def target_to_bits(target: int) -> int:
    if target <= 0:
        target = 1
    exp = (target.bit_length() + 7) // 8
    if exp <= 3:
        mant = target << (8 * (3 - exp))
        exp = 3
    else:
        shift = 8 * (exp - 3)
        mant = target >> shift
        if mant & 0x00800000:
            mant >>= 8
            exp += 1
    mant &= 0x007fffff
    return (exp << 24) | mant

DIFFICULTY_CONST = (1 << 256) 

def target_to_difficulty(target: int) -> int:
    t = max(1, int(target))
    return DIFFICULTY_CONST // t

def difficulty_to_target(diff: int) -> int:
    d = max(1, int(diff))
    return max(1, DIFFICULTY_CONST // d)


# ========== Low-level serializers ===========

def _serialize_outpoint(txid: bytes, vout: int) -> bytes:
    if len(txid) == 32:
        out = txid[::-1]
    else:
        out = txid
    out += (vout if vout >= 0 else 0xffffffff).to_bytes(4, 'little')
    return out


def _serialize_txin(txin) -> bytes:
    out = b''
    out += _serialize_outpoint(txin.txid, txin.vout)
    script_bytes = getattr(txin.script_sig, 'serialize', lambda: b'')()
    out += serialize_bytes_with_len(script_bytes)
    seq = getattr(txin, 'sequence', 0xffffffff)
    out += seq.to_bytes(4, 'little')
    return out


def _serialize_txout(txout) -> bytes:
    out = int(txout.amount).to_bytes(8, 'little')
    script_bytes = getattr(txout.script_pubkey, 'serialize', lambda: b'')()
    out += serialize_bytes_with_len(script_bytes)
    return out


def _serialize_witness_for_txin(txin) -> bytes:
    wit = getattr(txin, 'witness', None) or []
    out = encode_varint(len(wit))
    for item in wit:
        out += serialize_bytes_with_len(item)
    return out


def serialize_tx(tx, include_witness: bool = True) -> bytes:
    res = b''
    res += int(tx.version).to_bytes(4, 'little')
    has_witness = include_witness and any(getattr(txin, 'witness', None) for txin in tx.inputs)
    if has_witness:
        res += b'\x00' + b'\x01'
    res += encode_varint(len(tx.inputs))
    for txin in tx.inputs:
        res += _serialize_txin(txin)
    res += encode_varint(len(tx.outputs))
    for txout in tx.outputs:
        res += _serialize_txout(txout)
    if has_witness:
        for txin in tx.inputs:
            res += _serialize_witness_for_txin(txin)
    res += int(getattr(tx, 'locktime', 0)).to_bytes(4, 'little')
    return res


def serialize_tx_for_txid(tx) -> bytes:
    return serialize_tx(tx, include_witness=False)


# ========== BIP143 sig-hash (SIGHASH_ALL only) ===========

def _hash_prevouts(tx) -> bytes:
    inputs = getattr(tx, 'inputs', [])
    if not inputs:
        return b'\x00' * 32
    data = b''
    for txin in inputs:
        txid = getattr(txin, 'txid', b'')
        if isinstance(txid, bytes) and len(txid) == 32:
            txid_bytes = txid[::-1]
        elif isinstance(txid, bytes):
            txid_bytes = txid
        else:
            raise TypeError("txin.txid must be bytes, not %s" % type(txid))
        vout = getattr(txin, 'vout', 0xffffffff)
        if not isinstance(vout, int):
            raise TypeError("txin.vout must be int, not %s" % type(vout))
        data += txid_bytes + vout.to_bytes(4, 'little')

    return hash256(data)


def _hash_sequence(tx) -> bytes:
    inputs = getattr(tx, 'inputs', [])
    if not inputs:
        return b'\x00' * 32
    data = b''
    for txin in inputs:
        sequence = getattr(txin, 'sequence', 0xffffffff)
        if not isinstance(sequence, int):
            raise TypeError("txin.sequence must be int, not %s" % type(sequence))
        data += sequence.to_bytes(4, 'little')
    return hash256(data)


def _hash_outputs(tx) -> bytes:
    outputs = getattr(tx, 'outputs', [])
    if not outputs:
        return b'\x00' * 32
    data = b''
    for txout in outputs:
        amount = int(getattr(txout, 'amount', 0))
        script_pubkey = getattr(txout, 'script_pubkey', None)

        if callable(getattr(script_pubkey, 'serialize', None)):
            script_serialized = script_pubkey.serialize()
        else:
            script_serialized = b''
        data += amount.to_bytes(8, 'little') + serialize_bytes_with_len(script_serialized)
    return hash256(data)


def bip143_sig_hash(tx, input_index: int, script_code: bytes, value: int, sighash: int = SIGHASH_ALL) -> bytes:
    if sighash != SIGHASH_ALL:
        raise NotImplementedError('Only SIGHASH_ALL supported')

    hash_prevouts = _hash_prevouts(tx)
    hash_sequence = _hash_sequence(tx)
    hash_outputs = _hash_outputs(tx)
    txin = tx.inputs[input_index]
    outpoint = (txin.txid[::-1] if len(txin.txid) == 32 else txin.txid) + (txin.vout if txin.vout >= 0 else 0xffffffff).to_bytes(4, 'little')
    data = b''
    data += int(tx.version).to_bytes(4, 'little')
    data += hash_prevouts
    data += hash_sequence
    data += outpoint
    data += serialize_bytes_with_len(script_code)
    data += int(value).to_bytes(8, 'little')
    data += getattr(txin, 'sequence', 0xffffffff).to_bytes(4, 'little')
    data += hash_outputs
    data += int(getattr(tx, 'locktime', 0)).to_bytes(4, 'little')
    data += int(sighash).to_bytes(4, 'little')

    return hash256(data)

# ========== Convenience: detect p2wpkh from scriptPubKey ==========

def is_p2wpkh_script(script_bytes: bytes) -> bool:
    return isinstance(script_bytes, (bytes, bytearray)) and len(script_bytes) == 22 and script_bytes[0] == 0x00 and script_bytes[1] == 0x14

def der_encode_sig(r, s):
    # Enforce low-S normalization to avoid malleability and pass mempool policy
    try:
        N = SECP256k1.order
        if s > (N // 2):
            s = N - s
    except Exception:
        pass
    def encode_int(x):
        b = x.to_bytes((x.bit_length() + 7) // 8, 'big')
        if b[0] & 0x80:
            b = b'\x00' + b
        return b
    rb = encode_int(r)
    sb = encode_int(s)
    return b'\x30' + (len(rb) + len(sb) + 4).to_bytes(1, 'big') + b'\x02' + len(rb).to_bytes(1, 'big') + rb + b'\x02' + len(sb).to_bytes(1, 'big') + sb



# ========== Compute ==========

def util_compute_txid(tx, include_txid: bool = False):
    tx_dict = tx.to_dict(include_txid=include_txid)
    serialized = serialize(tx_dict)
    return double_sha256(serialized)
    
def util_compute_wtxid(tx) -> bytes:
        raw = serialize_tx(tx, include_witness=True)
        return hash256(raw)

# ========== For (Block Id) ==========

def random_message_secure(length=8):
    chars = string.ascii_letters + string.digits
    templates = [
        "TsarChain::{rand}",
        "TsarStudio::{rand}",
        "Bootleg4Life_{rand}",
        "UndergroundCode_{rand}",
        "#TSAR_{rand}",
        "#BOOTLEG_{rand}",
        "FakeItReal_{rand}"]

    template = secrets.choice(templates)
    rand = ''.join(secrets.choice(chars) for _ in range(length))
    return template.format(rand=rand)


# ========== Script Class ==========

class Script:

    def __init__(self, cmds: list = None):
        self.cmds = list(cmds) if cmds else []

    @staticmethod
    def _encode_pushdata(b: bytes) -> bytes:
        n = len(b)
        if n <= 75:
            return bytes([n]) + b
        elif n <= 255:
            return b'\x4c' + bytes([n]) + b
        elif n <= 65535:
            return b'\x4d' + n.to_bytes(2, 'little') + b 
        else:
            return b'\x4e' + n.to_bytes(4, 'little') + b 

    @classmethod
    def _read_push_or_opcode(cls, first: int, data: bytes, i: int):
        
        if 1 <= first <= 75:
            n = first
            end = i + n
            if end > len(data):
                raise ValueError("script short read (small push)")
            return data[i:end], end

        if first == OP_0:
            return OP_0, i

        if first == OP_PUSHDATA1:
            if i + 1 > len(data):
                raise ValueError("script short read (PUSHDATA1 header)")
            n = data[i]
            i += 1
            end = i + n
            if end > len(data):
                raise ValueError("script short read (PUSHDATA1 payload)")
            return data[i:end], end

        if first == OP_PUSHDATA2:
            if i + 2 > len(data):
                raise ValueError("script short read (PUSHDATA2 header)")
            n = int.from_bytes(data[i:i+2], 'little')
            i += 2
            end = i + n
            if end > len(data):
                raise ValueError("script short read (PUSHDATA2 payload)")
            return data[i:end], end

        if first == OP_PUSHDATA4:
            if i + 4 > len(data):
                raise ValueError("script short read (PUSHDATA4 header)")
            n = int.from_bytes(data[i:i+4], 'little')
            i += 4
            end = i + n
            if end > len(data):
                raise ValueError("script short read (PUSHDATA4 payload)")
            return data[i:end], end

        return first, i
    
    @staticmethod
    def build_opreturn_script(data: bytes, max_bytes: int) -> str:
        if len(data) > max_bytes:
            raise ValueError("opreturn_too_large")
        b = bytearray([OP_RETURN])
        n = len(data)
        if n <= 75:
            b.append(n); b.extend(data)
        elif n <= 255:
            b.append(OP_PUSHDATA1); b.append(n); b.extend(data)
        elif n <= 520:
            b.append(OP_PUSHDATA2); b.extend(n.to_bytes(2, "little")); b.extend(data)
        else:
            raise ValueError("opreturn_exceeds_520_bytes")
        return b.hex()

    def serialize(self) -> bytes:
        out = bytearray()
        for cmd in self.cmds:
            if isinstance(cmd, int):
                out.append(cmd & 0xff)  # opcode
            elif isinstance(cmd, (bytes, bytearray)):
                out += self._encode_pushdata(bytes(cmd))
            else:
                raise TypeError(f"Unsupported script cmd type: {type(cmd)}")
        return bytes(out)

    @classmethod
    def deserialize(cls, data: bytes) -> 'Script':
        cmds = []
        i = 0
        n = len(data)
        while i < n:
            first = data[i]
            i += 1
            item, i = cls._read_push_or_opcode(first, data, i)
            cmds.append(item)
        return cls(cmds)

    @classmethod
    def parse(cls, raw_bytes: bytes) -> 'Script':
        return cls.deserialize(raw_bytes)

    def to_dict(self):
        cmds_serializable = []
        for cmd in self.cmds:
            if isinstance(cmd, int):
                cmds_serializable.append(cmd)
            elif isinstance(cmd, (bytes, bytearray)):
                cmds_serializable.append(bytes(cmd).hex())
            else:
                cmds_serializable.append(cmd)
        return {'cmds': cmds_serializable}

    @classmethod
    def from_dict(cls, data: dict) -> 'Script':
        cmds = []
        for cmd in data.get('cmds', []):
            if isinstance(cmd, int):
                cmds.append(cmd)
            elif isinstance(cmd, str):
                cmds.append(bytes.fromhex(cmd))
            else:
                cmds.append(cmd)
        return cls(cmds)

    # ---------------------------
    # Helpers
    # ---------------------------
    @staticmethod
    def p2wpkh_script(address: str):
        pubkey_hash = decode_address(address)
        return Script([OP_0, pubkey_hash])


class DerSigError(ValueError):
    pass

def _int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big", signed=False)

def _int_to_bytes(i: int) -> bytes:
    if i < 0:
        raise ValueError("negative integer")
    if i == 0:
        return b"\x00"
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, "big")

def is_low_s(s: int) -> bool:
    return 1 <= s <= HALF_N

def canonicalize_rs(r: int, s: int) -> Tuple[int, int]:
    if not (1 <= r < SECP256K1_N) or not (1 <= s < SECP256K1_N):
        raise DerSigError("r or s out of range")
    if s > HALF_N:
        s = SECP256K1_N - s
    return r, s

def der_encode_sig_strict(r: int, s: int) -> bytes:
    def enc_int(x: int) -> bytes:
        if x <= 0:
            raise DerSigError("DER int must be positive")
        xb = _int_to_bytes(x)
        if xb[0] & 0x80:
            xb = b"\x00" + xb
        if len(xb) > 1 and xb[0] == 0x00 and not (xb[1] & 0x80):
            raise DerSigError("non-minimal integer encoding")
        return xb

    r_b = enc_int(r)
    s_b = enc_int(s)

    seq = b"\x02" + bytes([len(r_b)]) + r_b + b"\x02" + bytes([len(s_b)]) + s_b
    if len(seq) >= 0x80:
        if len(seq) <= 0xFF:
            len_bytes = b"\x81" + bytes([len(seq)])
        else:
            raise DerSigError("sequence too long")
    else:
        len_bytes = bytes([len(seq)])
    return b"\x30" + len_bytes + seq

def der_parse_sig_strict(sig: bytes) -> Tuple[int, int]:
    if not isinstance(sig, (bytes, bytearray)):
        raise DerSigError("signature must be bytes")
    sig = bytes(sig)
    if len(sig) < 8:  # minimal DER with tiny r,s
        raise DerSigError("signature too short")

    idx = 0
    if sig[idx] != 0x30:
        raise DerSigError("bad sequence tag")
    idx += 1

    def read_len(buf: bytes, i: int) -> Tuple[int, int]:
        if i >= len(buf):
            raise DerSigError("truncated length")
        first = buf[i]
        i += 1
        if first < 0x80:
            return first, i
        n = first & 0x7F
        if n == 0 or n > 2:
            raise DerSigError("invalid length form")
        if i + n > len(buf):
            raise DerSigError("truncated long length")
        length = 0
        for j in range(n):
            length = (length << 8) | buf[i + j]
        i += n
        if length < 0x80:
            raise DerSigError("non-minimal length encoding")
        return length, i

    seq_len, idx = read_len(sig, idx)
    if idx + seq_len != len(sig):
        raise DerSigError("superfluous data after sequence")

    if sig[idx] != 0x02:
        raise DerSigError("missing r integer tag")
    idx += 1
    r_len, idx = read_len(sig, idx)
    if r_len == 0 or idx + r_len > len(sig):
        raise DerSigError("invalid r length")
    r_bytes = sig[idx:idx + r_len]
    idx += r_len

    if r_bytes[0] & 0x80:
        raise DerSigError("r negative")
    if len(r_bytes) > 1 and r_bytes[0] == 0x00 and not (r_bytes[1] & 0x80):
        raise DerSigError("r non-minimal")
    r = _int_from_bytes(r_bytes)
    if not (1 <= r < SECP256K1_N):
        raise DerSigError("r out of range")

    if sig[idx] != 0x02:
        raise DerSigError("missing s integer tag")
    idx += 1
    s_len, idx = read_len(sig, idx)
    if s_len == 0 or idx + s_len > len(sig):
        raise DerSigError("invalid s length")
    s_bytes = sig[idx:idx + s_len]
    idx += s_len
    if idx != len(sig):
        raise DerSigError("trailing bytes in signature")

    if s_bytes[0] & 0x80:
        raise DerSigError("s negative")
    if len(s_bytes) > 1 and s_bytes[0] == 0x00 and not (s_bytes[1] & 0x80):
        raise DerSigError("s non-minimal")
    s = _int_from_bytes(s_bytes)
    if not (1 <= s < SECP256K1_N):
        raise DerSigError("s out of range")

    return r, s

def strip_sighash_flag(sig_with_type: bytes) -> Tuple[bytes, int]:
    if len(sig_with_type) < 2:
        raise DerSigError("signature missing sighash byte")
    return sig_with_type[:-1], sig_with_type[-1]

def sign_digest_der_low_s_strict(sk, digest32):
    if not isinstance(digest32, (bytes, bytearray)) or len(digest32) != 32:
        raise ValueError("sign_digest_der_low_s_strict expects a 32-byte digest")
    
    sigencode_canon = getattr(util, "sigencode_der_canonize", None)
    if sigencode_canon is not None:
        try:
            return sk.sign_digest_deterministic(
                digest32,
                sigencode=sigencode_canon,
                allow_truncate=False,
                hashfunc=hashlib.sha256,)
        except TypeError:
            return sk.sign_digest_deterministic(
                digest32,
                sigencode=sigencode_canon,
                hashfunc=hashlib.sha256,)

    try:
        r_b, s_b = sk.sign_digest_deterministic(
            digest32,
            sigencode=util.sigencode_strings,
            allow_truncate=False,
            hashfunc=hashlib.sha256,)
    except TypeError:
        r_b, s_b = sk.sign_digest_deterministic(
            digest32,
            sigencode=util.sigencode_strings,
            hashfunc=hashlib.sha256,)
        
    r = int.from_bytes(r_b, "big")
    s = int.from_bytes(s_b, "big")
    
    if s > HALF_N:
        s = SECP256K1_N - s

    try:
        return der_encode_sig_strict(r, s)
    except NameError:
        return der_encode_sig(r, s)


def verify_der_strict_low_s(vk: VerifyingKey, digest32: bytes, der_sig: bytes) -> bool:
    r, s = der_parse_sig_strict(der_sig)
    if not is_low_s(s):
        return False
    try:
        return vk.verify_digest(der_sig, digest32, sigdecode=util.sigdecode_der)
    except Exception:
        return False

def is_signature_canonical_low_s(der_sig: bytes) -> bool:
    try:
        r, s = der_parse_sig_strict(der_sig)
        return is_low_s(s)
    except DerSigError:
        return False

def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# ===========================================================================
# ------------------------- Native acceleration (Rust) ----------------------
# ===========================================================================

from typing import Optional

# status & reason for debugging
_HAVE_NATIVE = False
_native_reason = "not_tried"

# pegangan fallback Python-asli
_py_count_sigops_in_script = count_sigops_in_script
_py_bip143_sig_hash        = bip143_sig_hash
_py_verify_der_strict_low_s= verify_der_strict_low_s
_py_merkle_root            = merkle_root

# hanya import tsarcore_native bila NATIVE==1
try:
    if CFG.NATIVE != 1:
        _native_reason = "disabled_by_config"
        raise ImportError("tsarcore_native disabled via config.NATIVE")

    from tsarcore_native import (
        count_sigops as _native_count_sigops,
        sighash_bip143 as _native_sighash_bip143,
        secp_verify_der_low_s as _native_verify_der_low_s,
        merkle_root as _native_merkle_root,      # merkle root is locked to python version, for consensus convenience
        hash256 as _native_hash256,
        hash160 as _native_hash160,
        secp_verify_der_low_s_many as _native_verify_many,
    )
    
    _HAVE_NATIVE = True
    _native_reason = "import_ok"
except Exception as _e:
    _HAVE_NATIVE = False
    _native_count_sigops = None
    _native_sighash_bip143 = None
    _native_verify_der_low_s = None
    _native_merkle_root = None       # merkle root is locked to python version, for consensus convenience
    _native_hash256 = None
    _native_hash160 = None
    _native_verify_many = None
    
    if _native_reason == "not_tried":
        _native_reason = f"import_failed:{type(_e).__name__}"

def _vk_to_bytes(vk: "VerifyingKey") -> Optional[bytes]:
    try:
        raw = vk.to_string()  # 64B (X||Y)
        return b"\x04" + raw
    except Exception:
        return None

# ---- overrides: use native if available, else fallback Python ----

def count_sigops_in_script(script: bytes) -> int:
    if _HAVE_NATIVE and _native_count_sigops is not None:
        try:
            return int(_native_count_sigops(bytes(script)))
        except Exception:
            pass
    return int(_py_count_sigops_in_script(script))

def hash256_native(data: bytes) -> bytes:
    if _HAVE_NATIVE and _native_hash256 is not None:
        try:
            return bytes(_native_hash256(bytes(data)))
        except Exception:
            pass
    return hash256(data)

def hash160_native(data: bytes) -> bytes:
    if _HAVE_NATIVE and _native_hash160 is not None:
        try:
            return bytes(_native_hash160(bytes(data)))
        except Exception:
            pass
    return hash160(data)

def batch_verify_der_low_s(items, enforce_low_s: bool = True, parallel: bool = True):
    if _HAVE_NATIVE and _native_verify_many is not None:
        try:
            return list(_native_verify_many(items, enforce_low_s, parallel))
        except Exception:
            pass
    out = []
    for pub, dig, sig in items:
        try:
            vk = VerifyingKey.from_string(pub, curve=SECP256k1)
            ok = verify_der_strict_low_s(vk, dig, sig)
        except Exception:
            ok = False
        out.append(bool(ok))
    return out

def bip143_sig_hash(tx, input_index: int, script_code: bytes, value: int, sighash: int = SIGHASH_ALL) -> bytes:
    if _HAVE_NATIVE and _native_sighash_bip143 is not None:
        try:
            tx_bytes = serialize_tx(tx, include_witness=True)
            digest32 = _native_sighash_bip143(tx_bytes, int(input_index), bytes(script_code), int(value), int(sighash))
            if isinstance(digest32, (list, tuple)):
                digest32 = bytes(digest32)
            return bytes(digest32)
        except Exception:
            pass
    return _py_bip143_sig_hash(tx, input_index, script_code, value, sighash)

def verify_der_strict_low_s(vk: "VerifyingKey", digest32: bytes, der_sig: bytes) -> bool:
    if _HAVE_NATIVE and _native_verify_der_low_s is not None and isinstance(digest32, (bytes, bytearray)) and len(digest32) == 32:
        pub = _vk_to_bytes(vk)
        if pub:
            try:
                return bool(_native_verify_der_low_s(pub, bytes(digest32), bytes(der_sig)))
            except Exception:
                pass
    return bool(_py_verify_der_strict_low_s(vk, digest32, der_sig))

def merkle_root(transactions):
    return _py_merkle_root(transactions)  # merkle root is locked to python version, for consensus convenience
