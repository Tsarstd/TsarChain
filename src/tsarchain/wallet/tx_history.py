# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md
from typing import Callable, Optional, Dict, Any, List


# ---------------- Local Project (Wallet Only) ----------------
from .data_security import Wallet


class HistoryService:
    def fetch_history(
        self,
        address: str,
        limit: int,
        offset: int,
        direction: Optional[str],
        status: Optional[str],
        rpc_send,
        on_done: Callable[[Optional[Dict[str, Any]]], None],) -> None:
        
        payload = {
            "type": "GET_TX_HISTORY",
            "address": (address or "").strip().lower(),
            "limit": int(limit),
            "offset": int(offset),
            "direction": direction,
            "status": status,
        }
        rpc_send(payload, on_done)

    def fetch_tx_detail(self, txid: str, rpc_send, on_done: Callable[[Optional[Dict[str, Any]]], None]) -> None:
        rpc_send({"type": "GET_TX_DETAIL", "txid": (txid or "").lower()}, on_done)

    # --------- history cache wrappers ---------

    @staticmethod
    def cache_merge(address: str, items: List[dict]) -> tuple[int, int]:
        return Wallet.history_cache_merge(address, items)

    @staticmethod
    def cache_list(address: str, direction=None, status=None, limit: int = 50, offset: int = 0) -> dict:
        return Wallet.history_cache_list(address, direction=direction, status=status, limit=limit, offset=offset)

    @staticmethod
    def cache_clear(address: str) -> bool:
        return Wallet.history_cache_clear(address)

    @staticmethod
    def cache_path(address: str) -> str:
        return Wallet.history_cache_path(address)
