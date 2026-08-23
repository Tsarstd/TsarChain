# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: BIP143; BIP141; libsecp256k1; LowS-Policy; Signal-X3DH

import struct
from ecdsa import SECP256k1, SigningKey

# ---------------- Local Project ----------------
from ..utils.helpers import Script
from ..utils.helpers import (
    SIGHASH_ALL,
    bip143_sig_hash,
    to_bytes,
    is_p2wpkh,
    is_p2wsh,
    count_sigops_in_script,
    last_pushdata,
    sign_digest_der_low_s_native,
    tx_to_compact_tuple,
    txid_from_compact,
    wtxid_from_compact,
)

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.core(tx)")

_TX_HEADER_STRUCT = "<II?H"
_TXIN_STRUCT = "<32sIQHH"
_COINBASE_EXTRA_STRUCT = "<BHHq"


def _extract_script_bytes(script) -> bytes:
    ser = getattr(script, "serialize", None)
    if callable(ser):
        return ser()
    if isinstance(script, str):
        return bytes.fromhex(script)
    return bytes(script or b"")


class Tx:
    def __init__(self, version: int = 1, locktime: int = 0, txid: bytes = None, is_coinbase: bool = False, inputs=None, outputs=None, auto_compute_txid: bool = True):
        self.version = int(version)
        self.inputs = list(inputs or [])
        self.outputs = list(outputs or [])
        self.locktime = int(locktime)
        self.txid = txid
        self.is_coinbase = bool(is_coinbase)
        if self.is_coinbase:
            self.fee = 0
        else:
            self.fee = None

        if auto_compute_txid:
            try:
                self.compute_txid()
            except Exception:
                log.exception("auto_compute_err")
            
    # -------- Fee helpers ----------

    def set_fee_from_input_amounts(self, input_amounts: list[int]) -> int:
        if self.is_coinbase:
            self.fee = 0
            return 0

        for i, a in enumerate(input_amounts):
            if i < len(self.inputs):
                self.inputs[i].amount = int(a)

        total_in = sum(int(a) for a in input_amounts)
        total_out = sum(int(getattr(out, "amount", 0) or 0) for out in self.outputs)
        fee = total_in - total_out
        if fee < 0:
            raise ValueError("Output is greater than input, negative costs")

        self.fee = fee
        return fee

    # -------- Signing ----------

    def sign_input(self, index: int, priv_key_hex: str, prev_output, amount: int) -> bool:
        spk = getattr(prev_output, "script_pubkey", None)
        if spk is not None:
            ser = getattr(spk, "serialize", None)
            script_pubkey_bytes = ser() if callable(ser) else (bytes(spk) if isinstance(spk, (bytes, bytearray)) else bytes.fromhex(spk) if isinstance(spk, str) else b"")
        else:
            ser = getattr(prev_output, "serialize", None)
            if callable(ser):
                script_pubkey_bytes = ser()
            elif isinstance(prev_output, (bytes, bytearray)):
                script_pubkey_bytes = bytes(prev_output)
            elif isinstance(prev_output, str):
                script_pubkey_bytes = bytes.fromhex(prev_output)
            else:
                raise TypeError("prev_output must be TxOut, Script, or bytes")
        if not (len(script_pubkey_bytes) >= 22 and script_pubkey_bytes[0] == 0x00 and script_pubkey_bytes[1] == 0x14):
            raise ValueError("Not a P2WPKH")
        pubkey_hash = script_pubkey_bytes[2:22]
        
        # scriptCode tanpa prefix varint; panjang akan ditambahkan di fungsi sighash
        script_code = b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"
        z = bip143_sig_hash(self, index, script_code, int(amount), SIGHASH_ALL)
        der = sign_digest_der_low_s_native(priv_key_hex, z)
        sig = der + bytes([SIGHASH_ALL])
        sk = SigningKey.from_string(bytes.fromhex(priv_key_hex), curve=SECP256k1)
        vk = sk.get_verifying_key()
        pubkey_bytes = vk.to_string("compressed")
        self.inputs[index].witness = [sig, pubkey_bytes]
        return True
    
    def sigops_count(self, utxo_lookup=None) -> int:
        if getattr(self, "is_coinbase", False):
            return 0

        total = 0
        for vin in self.inputs:
            add = 1
            prev_spk = None

            if utxo_lookup is not None:
                prev_spk = utxo_lookup(vin.txid, vin.vout)
                if isinstance(prev_spk, str):
                    prev_spk = bytes.fromhex(prev_spk)

            script_sig = to_bytes(getattr(vin, "script_sig", b""))
            wstack = [ to_bytes(w) for w in getattr(vin, "witness", []) or [] ]

            if prev_spk is not None:
                if is_p2wpkh(prev_spk):
                    add = 1
                elif is_p2wsh(prev_spk):
                    ws = wstack[-1] if wstack else b""
                    add = count_sigops_in_script(ws) or 1
                else:
                    add = count_sigops_in_script(prev_spk) or 1
            else:
                # Tanpa UTXO: coba tebak dari redeem/witnessScript
                rs = last_pushdata(script_sig)
                if rs:
                    add = max(1, count_sigops_in_script(rs))
                elif wstack:
                    ws = wstack[-1]
                    add = max(1, count_sigops_in_script(ws))
                else:
                    add = 1

            total += int(add)
        return int(total)


    # -------- IDs ----------

    def compute_txid(self) -> bytes:
        compact = tx_to_compact_tuple(self)
        self.txid = txid_from_compact(compact)
        return self.txid

    def compute_wtxid(self) -> bytes:
        compact = tx_to_compact_tuple(self)
        return wtxid_from_compact(compact)

    # -------- Serde ----------

    def to_dict(self, include_txid: bool = True) -> dict:
        return {
            "version": self.version,
            "inputs": [txin.to_dict() for txin in self.inputs],
            "outputs": [txout.to_dict() for txout in self.outputs],
            "locktime": self.locktime,
            "txid": self.txid.hex() if (include_txid and isinstance(self.txid, (bytes, bytearray))) else None,
            "fee": self.fee,
            "is_coinbase": self.is_coinbase,}

    @classmethod
    def from_dict(cls, data: dict):
        if isinstance(data, Tx):
            return data
        if not isinstance(data, dict):
            raise TypeError("from_dict expects dict or Tx")

        txid = bytes.fromhex(data["txid"]) if data.get("txid") else None
        inputs = [TxIn.from_dict(x) for x in data.get("inputs", [])]
        outputs = [TxOut.from_dict(x) for x in data.get("outputs", [])]
        obj = cls(
            version=data.get("version", 1),
            inputs=inputs,
            outputs=outputs,
            locktime=data.get("locktime", 0),
            txid=txid,
            is_coinbase=bool(data.get("is_coinbase", False)),
            auto_compute_txid=False,)
        obj.fee = data.get("fee", None if not obj.is_coinbase else 0)
        if obj.txid is None:
            obj.compute_txid()
        return obj

    def to_storage_bytes(self) -> bytes:
        parts = [struct.pack(_TX_HEADER_STRUCT, self.version, self.locktime, self.is_coinbase, len(self.inputs))]
        for txin in self.inputs:
            prev_b = txin.txid if isinstance(txin.txid, (bytes, bytearray)) else bytes.fromhex(txin.txid)
            ss_bytes = _extract_script_bytes(txin.script_sig)
            parts.append(struct.pack(_TXIN_STRUCT, prev_b, int(txin.vout), int(getattr(txin, "amount", 0) or 0), len(ss_bytes), len(txin.witness)))
            if ss_bytes:
                parts.append(ss_bytes)
            for w in txin.witness:
                wb = bytes.fromhex(w) if isinstance(w, str) else bytes(w)
                parts.append(struct.pack("<H", len(wb)) + wb)
        
        parts.append(struct.pack("<H", len(self.outputs)))
        for txout in self.outputs:
            amt = int(getattr(txout, "amount", 0) or 0)
            spk = getattr(txout, "script_pubkey", None)
            spk_bytes = _extract_script_bytes(spk)
            parts.append(struct.pack("<QH", amt, len(spk_bytes)) + spk_bytes)
            
        if self.is_coinbase:
            to_addr = (getattr(self, "to_address", "") or "").encode("utf-8")
            blk_id = (str(getattr(self, "block_id", "") or "")).encode("utf-8")
            h = int(getattr(self, "height", 0) or 0)
            parts.append(struct.pack(_COINBASE_EXTRA_STRUCT, len(to_addr), len(blk_id), 0, h))
            parts.append(to_addr)
            parts.append(blk_id)

        return b"".join(parts)

    @classmethod
    def from_storage_bytes(cls, raw: bytes) -> "Tx":
        offset = 0
        version, locktime, is_coinbase, in_count = struct.unpack_from(_TX_HEADER_STRUCT, raw, offset)
        offset += struct.calcsize(_TX_HEADER_STRUCT)
        
        inputs = []
        for _ in range(in_count):
            prev_txid, vout, amt, ss_len, wit_count = struct.unpack_from(_TXIN_STRUCT, raw, offset)
            offset += struct.calcsize(_TXIN_STRUCT)
            ss_bytes = raw[offset:offset + ss_len]
            offset += ss_len
            script_sig = Script.deserialize(ss_bytes) if ss_bytes else Script([])
            
            witness = []
            for _ in range(wit_count):
                (w_len,) = struct.unpack_from("<H", raw, offset)
                offset += 2
                wb = raw[offset:offset + w_len]
                offset += w_len
                witness.append(wb)
                
            inputs.append(TxIn(txid=prev_txid, vout=vout, amount=amt, script_sig=script_sig, witness=witness))
            
        (out_count,) = struct.unpack_from("<H", raw, offset)
        offset += 2
        
        outputs = []
        for _ in range(out_count):
            amt, spk_len = struct.unpack_from("<QH", raw, offset)
            offset += struct.calcsize("<QH")
            spk_bytes = raw[offset:offset + spk_len]
            offset += spk_len
            script_pubkey = Script.deserialize(spk_bytes) if spk_bytes else Script([])
            outputs.append(TxOut(amount=amt, script_pubkey=script_pubkey))
            
        if is_coinbase:
            from .coinbase import CoinbaseTx
            to_addr_len, blk_id_len, _, h = struct.unpack_from(_COINBASE_EXTRA_STRUCT, raw, offset)
            offset += struct.calcsize(_COINBASE_EXTRA_STRUCT)
            to_addr = raw[offset:offset + to_addr_len].decode("utf-8", errors="replace")
            offset += to_addr_len
            blk_id = raw[offset:offset + blk_id_len].decode("utf-8", errors="replace")
            offset += blk_id_len
            obj = CoinbaseTx.__new__(CoinbaseTx)
            obj.version = version
            obj.locktime = locktime
            obj.is_coinbase = True
            obj.inputs = inputs
            obj.outputs = outputs
            obj.to_address = to_addr
            obj.reward = outputs[0].amount if outputs else 0
            obj.block_id = blk_id
            obj.height = h
            obj.fee = 0
            obj.txid = None
            obj.compute_txid()
            return obj
            
        tx = cls(version=version, locktime=locktime, is_coinbase=False, inputs=inputs, outputs=outputs)
        return tx

    # -------- Convenience props ----------
    
    @property
    def tx_ins(self):
        return self.inputs

    @tx_ins.setter
    def tx_ins(self, val):
        self.inputs = list(val or [])

    @property
    def tx_outs(self):
        return self.outputs

    @tx_outs.setter
    def tx_outs(self, val):
        self.outputs = list(val or [])

    def __repr__(self):
        return f"<Tx v={self.version} vin={len(self.inputs)} vout={len(self.outputs)} lock={self.locktime} fee={self.fee}>"


class TxIn:
    def __init__(self, txid: bytes, vout: int, amount: int = 0, script_sig: Script = None, witness: list = None):
        if not isinstance(txid, (bytes, bytearray)) or len(txid) != 32:
            raise ValueError("txid must be 32-byte bytes")
        if not isinstance(vout, int):
            raise TypeError("vout must be an integer")
        if not isinstance(amount, int) or amount < 0:
            raise ValueError("amount must be an integer >= 0")

        self.txid = bytes(txid)
        self.vout = int(vout)
        self.amount = int(amount)
        self.script_sig = script_sig or Script([])
        self.witness = list(witness or [])

    def to_dict(self) -> dict:
        return {
            "txid": self.txid.hex(),
            "vout": self.vout,
            "amount": self.amount,
            "script_sig": getattr(self.script_sig, "to_hex", lambda: self.script_sig.serialize().hex())(),
            "witness": [w.hex() if isinstance(w, (bytes, bytearray)) else str(w) for w in self.witness],}

    @classmethod
    def from_dict(cls, data: dict):
        if not isinstance(data, dict):
            raise TypeError("TxIn.from_dict expects dict")
        raw = bytes.fromhex(data["script_sig"]) if data.get("script_sig") else b""
        script_sig = Script.parse(raw) if raw else Script([])
        witness = [bytes.fromhex(w) for w in data.get("witness", [])]
        amount = int(data.get("amount", 0))
        return cls(
            txid=bytes.fromhex(data["txid"]),
            vout=int(data["vout"]),
            amount=amount,
            script_sig=script_sig,
            witness=witness,)
        
    def __repr__(self):
        return f"<TxIn {self.txid.hex()}:{self.vout} amt={self.amount} wit={len(self.witness)}>"


class TxOut:
    def __init__(self, amount: int, script_pubkey: Script):
        if not isinstance(amount, int) or amount < 0:
            raise ValueError("amount must be integer >= 0")
        if not isinstance(script_pubkey, Script):
            raise TypeError("script_pubkey must be Script instance")
            
        self.amount = amount
        self.script_pubkey = script_pubkey

    def to_dict(self) -> dict:
        return {
            "amount": self.amount,
            "script_pubkey": self.script_pubkey.serialize().hex(),}

    @classmethod
    def from_dict(cls, data: dict):
        if not isinstance(data, dict):
            raise TypeError("TxOut.from_dict expects dict")
        
        spk = data.get("script_pubkey")
        if isinstance(spk, dict):
            script = Script.from_dict(spk)
        elif isinstance(spk, str):
            script = Script.deserialize(bytes.fromhex(spk))
        else:
            raise TypeError("Unsupported script_pubkey format")
        amount = int(data["amount"])
        return cls(amount=amount, script_pubkey=script)

    def __repr__(self):
        return f"<TxOut amt={self.amount}>"
