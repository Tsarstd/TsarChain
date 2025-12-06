# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain – see LICENSE and TRADEMARKS.md

"""
Backend penyimpanan untuk Archivist (storage node).
- JSON filesystem: mempertahankan perilaku lama (index.json + folder incoming/final).
- LMDB: memakai tiga environment terpisah (index_db, incoming_db, final_db) dengan batas ukuran dari config.
"""

from __future__ import annotations

import os
import json
from typing import Dict, Iterator, Tuple, Optional

from tsarcore_native import open_storage as _native_open_storage

from ...storage.kv import kv_enabled
from ...utils import config as CFG


from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.contracts.storage_node.database")


def _iter_prefix(store, db_name: str, prefix: bytes) -> Iterator[Tuple[bytes, bytes]]:
    start_after: Optional[bytes] = None
    while True:
        chunk = store.iter_prefix_chunk(
            db_name,
            prefix,
            limit=int(CFG.KV_ITER_CHUNK),
            start_after=start_after,
        ) or []
        if not chunk:
            break
        for k, v in chunk:
            yield bytes(k), bytes(v)
            start_after = bytes(k)
        if len(chunk) < int(CFG.KV_ITER_CHUNK):
            break


class ArchivistDatabase:
    """
    Abstraksi backend untuk index + blob archivist.
    Jika KV_BACKEND != lmdb, hanya menyediakan loader/saver JSON; operasi blob didelegasikan ke filesystem oleh caller.
    """

    def __init__(self, storage_dir: str | None = None, *, enable_blobs: bool = True, enable_index: bool = True):
        self.storage_dir = storage_dir or CFG.STORAGE_DIR
        self.use_kv = kv_enabled()
        self.enable_index = enable_index
        self.enable_blobs = enable_blobs
        self._kv_index = None
        self._kv_incoming = None
        self._kv_final = None
        # in-memory fallback when index disabled (node-only)
        self._mem_index = {"files": {}, "bytes_used": 0, "art_map": {}}

        if self.use_kv and self.enable_index:
            self._kv_index = self._open_store(CFG.ARCHIVIST_INDEX_DB_PATH)
            if self.enable_blobs:
                self._kv_incoming = self._open_store(CFG.ARCHIVIST_INCOMING_DB_PATH)
                self._kv_final = self._open_store(CFG.ARCHIVIST_FINAL_DB_PATH)

    # ---------------- KV helpers ----------------
    def _open_store(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        return _native_open_storage(
            "lmdb",
            path,
            map_size_init=int(CFG.STORAGE_SIZE_INIT),
            map_size_max=int(CFG.STORAGE_MAX_BYTES),
            pretty_json=False,
        )

    # ---------------- Index ----------------
    def load_index(self) -> Dict:
        if not self.enable_index:
            return dict(self._mem_index)
        if not self.use_kv:
            return self._load_index_json()
        files: Dict[str, Dict] = {}
        art_map: Dict[str, str] = {}
        try:
            for k, v in _iter_prefix(self._kv_index, "idx", b"file:"):
                gid = k.decode("utf-8")[5:]
                try:
                    meta = json.loads(v.decode("utf-8"))
                except Exception:
                    continue
                files[gid] = meta
            for k, v in _iter_prefix(self._kv_index, "idx", b"art:"):
                art = k.decode("utf-8")[4:]
                try:
                    art_map[art] = v.decode("utf-8")
                except Exception:
                    continue
        except Exception as exc:
            log.error("[db] load_index lmdb error: %s", exc)
        bytes_used = 0
        try:
            bytes_used = sum(int(m.get("size_bytes", 0)) for m in files.values())
        except Exception:
            bytes_used = 0
        return {"files": files, "bytes_used": bytes_used, "art_map": art_map}

    def save_index(self, index: Dict) -> None:
        if not self.enable_index:
            # store in-memory only (node: no archivist index persistence)
            self._mem_index = {
                "files": dict(index.get("files") or {}),
                "bytes_used": int(index.get("bytes_used", 0) or 0),
                "art_map": dict(index.get("art_map") or {}),
            }
            return
        if not self.use_kv:
            self._save_index_json(index)
            return
        try:
            self._kv_index.clear_db("idx")
        except Exception:
            log.debug("[db] clear_db idx failed (ignore)")
        ops = []
        for gid, meta in (index.get("files") or {}).items():
            try:
                ops.append((f"file:{gid}".encode("utf-8"), json.dumps(meta).encode("utf-8")))
            except Exception:
                continue
        for art, gid in (index.get("art_map") or {}).items():
            try:
                ops.append((f"art:{art}".encode("utf-8"), str(gid).encode("utf-8")))
            except Exception:
                continue
        if ops:
            try:
                self._kv_index.put_batch("idx", ops)
            except Exception as exc:
                log.error("[db] save_index batch failed: %s", exc)

    # ---------------- Blob operations (LMDB only) ----------------
    def append_incoming(self, gid: str, chunk: bytes, max_chunk: int) -> int:
        if not self.use_kv:
            raise RuntimeError("kv_disabled")
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        if len(chunk) > int(max_chunk):
            raise ValueError("chunk_too_big")
        key = f"blob:{gid}".encode("utf-8")
        existing = self._kv_incoming.get_bytes("incoming", key)
        data = bytes(existing) + bytes(chunk) if existing is not None else bytes(chunk)
        if len(data) > int(CFG.GRAFFITI_MAX_SIZE_BYTES):
            raise ValueError("file_too_large")
        self._kv_incoming.put_bytes("incoming", key, data)
        return len(data)

    def get_incoming_bytes(self, gid: str) -> Optional[bytes]:
        if not self.use_kv:
            raise RuntimeError("kv_disabled")
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        key = f"blob:{gid}".encode("utf-8")
        data = self._kv_incoming.get_bytes("incoming", key)
        return bytes(data) if data is not None else None

    def pop_incoming(self, gid: str) -> Optional[bytes]:
        if not self.use_kv:
            raise RuntimeError("kv_disabled")
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        key = f"blob:{gid}".encode("utf-8")
        data = self._kv_incoming.get_bytes("incoming", key)
        if data is None:
            return None
        self._kv_incoming.delete("incoming", key)
        return bytes(data)

    def put_final(self, gid: str, data: bytes) -> None:
        if not self.use_kv:
            raise RuntimeError("kv_disabled")
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        key = f"blob:{gid}".encode("utf-8")
        self._kv_final.put_bytes("final", key, bytes(data))

    def promote_incoming(self, gid: str) -> bool:
        """
        Pindahkan blob dari incoming_db ke final_db. Mengembalikan True jika ada data yang dipindah.
        """
        if not self.use_kv:
            raise RuntimeError("kv_disabled")
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        data = self.pop_incoming(gid)
        if data is None:
            return False
        self.put_final(gid, data)
        return True

    def get_final_bytes(self, gid: str) -> Optional[bytes]:
        if not self.use_kv:
            raise RuntimeError("kv_disabled")
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        key = f"blob:{gid}".encode("utf-8")
        data = self._kv_final.get_bytes("final", key)
        return bytes(data) if data is not None else None

    def delete_blob(self, gid: str, *, incoming: bool = False, final: bool = False) -> None:
        if not self.use_kv:
            raise RuntimeError("kv_disabled")
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        key = f"blob:{gid}".encode("utf-8")
        if incoming:
            try:
                self._kv_incoming.delete("incoming", key)
            except Exception:
                pass
        if final:
            try:
                self._kv_final.delete("final", key)
            except Exception:
                pass

    # ---------------- JSON fallback ----------------
    def _idx_path(self) -> str:
        return os.path.join(self.storage_dir, "index.json")

    def _load_index_json(self) -> Dict:
        default = {"files": {}, "bytes_used": 0, "art_map": {}}
        path = self._idx_path()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        data.setdefault("files", {})
        data.setdefault("bytes_used", 0)
        data.setdefault("art_map", {})
        try:
            data["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in (data.get("files") or {}).values())
        except Exception:
            pass
        return data

    def _save_index_json(self, data: Dict) -> None:
        path = self._idx_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, path)


__all__ = ["ArchivistDatabase"]
