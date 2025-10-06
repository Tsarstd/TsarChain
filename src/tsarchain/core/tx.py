# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP143; BIP141; libsecp256k1; LowS-Policy
from ecdsa import SECP256k1, SigningKey

from ..utils.helpers import Script
from ..utils.helpers import (util_compute_txid, util_compute_wtxid, SIGHASH_ALL, bip143_sig_hash, to_bytes, is_p2pkh, is_p2wpkh, is_p2wsh, is_p2sh,
                             count_sigops_in_script, last_pushdata, sign_digest_der_low_s_strict)


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
                pass
            
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
            raise ValueError("Output lebih besar dari input, fee negatif")

        self.fee = fee
        return fee

    def total_output(self) -> int:
        return sum(o.amount for o in self.outputs)

    # -------- Signing ----------

    def sign_input(self, index: int, priv_key_hex: str, prev_output, amount: int) -> bool:
        if hasattr(prev_output, "script_pubkey"):
            script_pubkey_bytes = prev_output.script_pubkey.serialize()
        elif hasattr(prev_output, "serialize"):
            script_pubkey_bytes = prev_output.serialize()
        elif isinstance(prev_output, (bytes, bytearray)):
            script_pubkey_bytes = bytes(prev_output)
        else:
            raise TypeError("prev_output must be TxOut, Script, or bytes")
        if not (len(script_pubkey_bytes) >= 22 and script_pubkey_bytes[0] == 0x00 and script_pubkey_bytes[1] == 0x14):
            raise ValueError("Bukan scriptPubKey P2WPKH")

        pubkey_hash = script_pubkey_bytes[2:22]
        script_code = b"\x19\x76\xa9\x14" + pubkey_hash + b"\x88\xac"

        z = bip143_sig_hash(self, index, script_code, int(amount), SIGHASH_ALL)

        sk = SigningKey.from_string(bytes.fromhex(priv_key_hex), curve=SECP256k1)
        der = sign_digest_der_low_s_strict(sk, z)
        sig = der + bytes([SIGHASH_ALL])

        vk = sk.get_verifying_key()
        try:
            pubkey_bytes = vk.to_string("compressed")
        except TypeError:
            pubkey_bytes = vk.to_string()
        self.inputs[index].witness = [sig, pubkey_bytes]
        return True
    
    def sigops_count(self, utxo_lookup=None) -> int:
        if getattr(self, "is_coinbase", False):
            return 0

        total = 0
        for vin in self.inputs:
            add = 1  # fallback aman
            prev_spk = None

            if utxo_lookup is not None:
                try:
                    prev_spk = utxo_lookup(vin.txid, vin.vout)
                    if isinstance(prev_spk, str):
                        prev_spk = bytes.fromhex(prev_spk)
                except Exception:
                    prev_spk = None

            script_sig = to_bytes(getattr(vin, "script_sig", b""))
            wstack = [ to_bytes(w) for w in getattr(vin, "witness", []) or [] ]

            if prev_spk is not None:
                if is_p2wpkh(prev_spk) or is_p2pkh(prev_spk):
                    add = 1
                elif is_p2wsh(prev_spk):
                    ws = wstack[-1] if wstack else b""
                    add = count_sigops_in_script(ws) or 1
                elif is_p2sh(prev_spk):
                    rs = last_pushdata(script_sig) or b""
                    add = count_sigops_in_script(rs) or 1
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
        self.txid = util_compute_txid(self, include_txid=False)
        return self.txid

    def compute_wtxid(self) -> bytes:
        return util_compute_wtxid(self)

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
