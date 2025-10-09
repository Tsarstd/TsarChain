# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md
from decimal import Decimal, ROUND_DOWN, InvalidOperation
from typing import Optional, Dict, Any

# ---------------- Local Project (Wallet Only) ----------------
from .data_security import Wallet

# ---------------- Local Project (With Node) ----------------
from ..utils import config as CFG


class SendService:
    @staticmethod
    def parse_amount_str(raw: str) -> tuple[int, str]:
        if not raw:
            raise ValueError("Amount kosong.")
        txt = raw.replace(" ", "").replace("_", "").replace(",", ".")
        if txt.startswith("."):
            txt = "0" + txt
        try:
            dec = Decimal(txt)
        except InvalidOperation:
            raise ValueError("Invalid amount format.")
        if dec <= 0:
            raise ValueError("Amount must be > 0.")
        quant = Decimal("1").scaleb(-CFG.MAX_DECIMALS)
        dec_q = dec.quantize(quant, rounding=ROUND_DOWN)
        sats = int(dec_q * Decimal(CFG.TSAR))
        if sats < int(CFG.DUST_THRESHOLD_SAT):
            raise ValueError(f"Amount terlalu kecil (< {CFG.DUST_THRESHOLD_SAT} sat, dust).")
        coin_str = format(dec_q, "f").rstrip("0").rstrip(".")
        if not coin_str:
            coin_str = "0"
        return sats, coin_str

    @staticmethod
    def clamp_fee_rate(rate: Optional[int]) -> int:
        try:
            if rate is None:
                return int(CFG.DEFAULT_FEE_RATE_SATVB)
            return max(int(CFG.MIN_FEE_RATE_SATVB), min(int(rate), int(CFG.MAX_FEE_RATE_SATVB)))
        except Exception:
            return int(CFG.DEFAULT_FEE_RATE_SATVB)

    @staticmethod
    def estimate_vbytes(n_inputs: int = 1, n_outputs: int = 2) -> int:
        return int(CFG.TX_BASE_VBYTES) + int(n_inputs) * int(CFG.SEGWIT_INPUT_VBYTES) + int(n_outputs) * int(CFG.SEGWIT_OUTPUT_VBYTES)

    @staticmethod
    def estimate_fee(amount_sats: int, fee_rate_satvb: int, spendable: Optional[int] = None) -> Dict[str, int | float]:
        n_outputs = 2
        if spendable is not None:
            approx_fee_room = fee_rate_satvb * 500
            if amount_sats + approx_fee_room >= spendable * 0.995:
                n_outputs = 1

        vbytes = SendService.estimate_vbytes(n_inputs=1, n_outputs=n_outputs)
        fee_sat = int(fee_rate_satvb) * int(vbytes)
        fee_tsar = fee_sat / CFG.TSAR
        total_tsar = (amount_sats + fee_sat) / CFG.TSAR

        return {
            "vbytes": vbytes,
            "fee_sat": fee_sat,
            "fee_tsar": fee_tsar,
            "total_tsar": total_tsar,
            "n_outputs": n_outputs,}

    def create_sign_broadcast(
        self,
        from_addr: str,
        to_addr: str,
        amount_sats: int,
        password_provider,
        rpc_send,
        fee_rate,
        on_progress,
        on_done,
        opret_hex: str | None = None,
    ) -> None:
        
        use_multi = bool(opret_hex)
        if use_multi:
            payload = {
                "type": "CREATE_TX_MULTI",
                "from": (from_addr or "").strip().lower(),
                "fee_rate": None,
                "outputs": [
                    { "address": (to_addr or "").strip().lower(), "amount": int(amount_sats) },
                    { "amount": 0, "opret_hex": (opret_hex or "").strip().lower() },
                ],
            }
        else:
            payload = {
                "type": "CREATE_TX",
                "from": (from_addr or "").strip().lower(),
                "to": (to_addr or "").strip().lower(),
                "amount": int(amount_sats),
            }
        fee_rate = self.clamp_fee_rate(fee_rate)
        if use_multi:
            payload["fee_rate"] = int(fee_rate)
        else:
            if fee_rate is not None:
                payload["fee_rate"] = int(fee_rate)

        def _on_tpl(resp: Optional[Dict[str, Any]]):
            if not resp or resp.get("type") != "TX_TEMPLATE":
                err = None
                try:
                    err = (resp or {}).get("error")
                except Exception:
                    pass
                on_progress(f"[-] Failed to get tx template{(': ' + str(err)) if err else ''}")
                on_done({"error": "template_failed"})
                return

            data = resp["data"]
            unsigned_tx = data["tx"]
            inputs_meta = data["inputs"]

            pwd = password_provider(from_addr)
            if not pwd:
                on_progress("[-] No password entered")
                on_done({"error": "no_password"})
                return
            try:
                w = Wallet.unlock(pwd, from_addr)
                privkey_hex = w["private_key"]
            except Exception as e:
                on_progress(f"[-] Unlock failed: {e}")
                on_done({"error": "unlock_failed"})
                return

            try:
                signed_tx = Wallet.sign_prepared_tx(unsigned_tx, inputs_meta, privkey_hex)
            except Exception as e:
                on_progress(f"[-] Sign failed: {e}")
                on_done({"error": "sign_failed"})
                return

            def _finish(resp2: Optional[Dict[str, Any]]):
                on_done(resp2)

            rpc_send({"type": "NEW_TX", "data": signed_tx.to_dict()}, _finish)

        on_progress(f"[*] Creating TX from {from_addr} -> {to_addr}" + (" + OP_RETURN" if opret_hex else ""))
        try:
            rpc_send(payload, _on_tpl)
        except Exception as e:
            on_progress(f"[-] RPC error: {e}")
            on_done({"error": "rpc_exception", "detail": str(e)})
