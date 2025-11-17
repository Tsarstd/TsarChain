from __future__ import annotations

from typing import Dict


def init_storage_registry(self) -> None:
    if not hasattr(self, "storage_peers") or self.storage_peers is None:
        self.storage_peers = {}


def register_storage_peer(self, peer_ip: str, meta: Dict) -> None:
    port = int(meta.get("port", 0))
    with self.lock:
        if not hasattr(self, "storage_peers") or self.storage_peers is None:
            self.storage_peers = {}
        self.storage_peers[(peer_ip, port)] = meta


__all__ = ("init_storage_registry", "register_storage_peer")
