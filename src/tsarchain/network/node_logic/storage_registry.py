# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

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
        node_id = meta.get("node_id")
        # enforce pin consistency for the same node_id
        if node_id:
            keys_to_remove = []
            for key, old_meta in self.storage_peers.items():
                if (old_meta or {}).get("node_id") != node_id:
                    continue
                if (old_meta or {}).get("pubkey") and meta.get("pubkey") and (old_meta or {}).get("pubkey") != meta.get("pubkey"):
                    return
                # prefer latest entry / explicit port
                if key != (peer_ip, port):
                    keys_to_remove.append(key)
            for key in keys_to_remove:
                self.storage_peers.pop(key, None)
        self.storage_peers[(peer_ip, port)] = meta
