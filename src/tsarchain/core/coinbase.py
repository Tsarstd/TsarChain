# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from typing import Optional


from ..core.tx import Tx, TxIn, TxOut
from ..utils.helpers import Script
from ..utils.helpers import random_message_secure
from ..utils import config as CFG

# ---------- Helper ----------

def _int_to_le_bytes(x: int) -> bytes:
    if x <= 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "little")

# ========== CoinbaseTx ==========
class CoinbaseTx(Tx):
    def __init__(self, to_address: str, reward: int, block_id: Optional[str] = None, height: int = 0,):
        if not to_address:
            raise ValueError("to_address is required")
        if reward <= 0:
            raise ValueError("reward must be positive")

        self.to_address = to_address
        self.reward = int(reward)
        self.height = int(height)
        
        if block_id is None:
            if self.height == 0:
                self.block_id = CFG.GENESIS_BLOCK_ID_DEFAULT
            else:
                self.block_id = random_message_secure()
        else:
            self.block_id = str(block_id).strip()

        graffiti_id = self.block_id.encode("utf-8")
        if len(graffiti_id) > CFG.MAX_COINBASE_EXTRADATA:
            graffiti_id = graffiti_id[:CFG.MAX_COINBASE_EXTRADATA]
            try:
                self.block_id = graffiti_id.decode("utf-8", errors="ignore")
            except Exception:
                self.block_id = graffiti_id.hex()


        script_pubkey = Script.p2wpkh_script(self.to_address)
        txout = TxOut(amount=self.reward, script_pubkey=script_pubkey)

        height_bytes = _int_to_le_bytes(self.height)
        script_sig = Script([height_bytes, self.block_id.encode("utf-8")])

        coinbase_input = TxIn(
            txid=b"\x00" * 32,
            vout=0xFFFFFFFF,
            script_sig=script_sig,
        )

        super().__init__(
            inputs=[coinbase_input],
            outputs=[txout],
            is_coinbase=True,
            auto_compute_txid=True,
        )

    def to_dict(self, include_txid: bool = True):
        base = super().to_dict(include_txid=include_txid)
        base.update({
            "type": "Coinbase",
            "to_address": self.to_address,
            "reward": int(self.reward),
            "block_id": self.block_id,
            "height": int(self.height),
        })
        return base

    @classmethod
    def from_dict(cls, data: dict):
        if not isinstance(data, dict):
            raise TypeError("CoinbaseTx.from_dict expects dict")

        to_addr = data.get("to_address") or data.get("address")
        reward = int(data.get("reward", 0))
        block_id = data.get("block_id")
        height = int(data.get("height", 0))
        obj = cls(to_address=to_addr, reward=reward, block_id=block_id, height=height)
        if "inputs" in data:
            obj.inputs = [TxIn.from_dict(i) for i in data["inputs"]]
        if "outputs" in data:
            obj.outputs = [TxOut.from_dict(o) for o in data["outputs"]]
        obj.is_coinbase = True
        obj.fee = 0

        if data.get("txid"):
            try:
                obj.txid = bytes.fromhex(data["txid"])
            except Exception:
                obj.compute_txid()
        else:
            obj.compute_txid()
        return obj

    def __repr__(self) -> str:
        txid_hex = (self.txid.hex() if isinstance(self.txid, (bytes, bytearray)) else str(self.txid))[:12]
        return f"<CoinbaseTx {txid_hex}... reward={self.reward} height={self.height}>"
