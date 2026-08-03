# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain – see LICENSE

"""
- LMDB: index_db + final_db, incoming always filesystem (temporary).
"""

from __future__ import annotations

import os
import json
from typing import Dict, Iterator, Tuple, Optional

from tsarcore_native import open_storage as _native_open_storage

from tsarchain.utils import config as CFG

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.contracts.storage_node.database_archivist")


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
    Abstraksi backend LMDB untuk index + blob archivist.
    """

    def __init__(self, storage_dir: str | None = None, *, enable_blobs: bool = True, enable_index: bool = True):
        self.storage_dir = storage_dir or CFG.STORAGE_DIR
        self.enable_index = enable_index
        self.enable_blobs = enable_blobs
        self._mem_index = {"files": {}, "bytes_used": 0, "art_map": {}}

        if self.enable_index:
            self._kv_index = self._open_store(CFG.ARCHIVIST_INDEX_DB_PATH)
            if self.enable_blobs:
                self._kv_final = self._open_store(CFG.ARCHIVIST_FINAL_DB_PATH)


    # ---------------- Index ----------------
    def load_index(self) -> Dict:
        if not self.enable_index:
            return dict(self._mem_index)
        files: Dict[str, Dict] = {}
        art_map: Dict[str, str] = {}
        for k, v in _iter_prefix(self._kv_index, "idx", b"file:"):
            gid = k.decode("utf-8")[5:]
            meta = json.loads(v.decode("utf-8"))
            files[gid] = meta
        for k, v in _iter_prefix(self._kv_index, "idx", b"art:"):
            art = k.decode("utf-8")[4:]
            art_map[art] = v.decode("utf-8")
            
        bytes_used = sum(int(m.get("size_bytes", 0)) for m in files.values())
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
        self._kv_index.clear_db("idx")
        ops = []
        for gid, meta in (index.get("files") or {}).items():
            ops.append((f"file:{gid}".encode("utf-8"), json.dumps(meta).encode("utf-8")))
        for art, gid in (index.get("art_map") or {}).items():
            ops.append((f"art:{art}".encode("utf-8"), str(gid).encode("utf-8")))
        if ops:
            self._kv_index.put_batch("idx", ops)


    # ---------------- Blob operations (incoming filesystem, final LMDB) ----------------
    def append_incoming(self, gid: str, chunk: bytes, max_chunk: int) -> int:
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        if len(chunk) > int(max_chunk):
            raise ValueError("chunk_too_big")
        path = self._incoming_part_path(gid)
        try:
            current = os.path.getsize(path) if os.path.exists(path) else 0
        except OSError:
            current = 0
        new_size = int(current) + int(len(chunk))
        if new_size > int(CFG.GRAFFITI_MAX_SIZE_BYTES):
            raise ValueError("file_too_large")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "ab") as f:
            f.write(chunk)
        return new_size


    def get_incoming_bytes(self, gid: str) -> Optional[bytes]:
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        bin_path = self._incoming_bin_path(gid)
        part_path = self._incoming_part_path(gid)
        path = bin_path if os.path.isfile(bin_path) else part_path
        if not os.path.isfile(path):
            return None
        with open(path, "rb") as f:
            return f.read()


    def pop_incoming(self, gid: str) -> Optional[bytes]:
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        bin_path = self._incoming_bin_path(gid)
        part_path = self._incoming_part_path(gid)
        path = bin_path if os.path.isfile(bin_path) else part_path
        if not os.path.isfile(path):
            return None
        with open(path, "rb") as f:
            data = f.read()
        try:
            if os.path.isfile(path):
                os.remove(path)
            if path != part_path and os.path.isfile(part_path):
                os.remove(part_path)
        except OSError:
            pass
        return data


    def put_final(self, gid: str, data: bytes) -> None:
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        key = f"blob:{gid}".encode("utf-8")
        self._kv_final.put_bytes("final", key, bytes(data))


    def promote_incoming(self, gid: str) -> bool:
        """
        Pindahkan blob dari incoming filesystem ke final_db. Mengembalikan True jika ada data yang dipindah.
        """
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        data = self.pop_incoming(gid)
        if data is None:
            return False
        self.put_final(gid, data)
        return True


    def get_final_bytes_range(self, gid: str, offset: int, length: int) -> Optional[bytes]:
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        key = f"blob:{gid}".encode("utf-8")
        data = self._kv_final.get_bytes_range("final", key, offset, length)
        return bytes(data) if data is not None else None


    def get_final_merkle_path(self, gid: str, chunk_size: int, index: int) -> Optional[list]:
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        key = f"blob:{gid}".encode("utf-8")
        return self._kv_final.get_merkle_path("final", key, chunk_size, index)


    def delete_blob(self, gid: str, *, incoming: bool = False, final: bool = False) -> None:
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        if incoming:
            for path in (self._incoming_part_path(gid), self._incoming_bin_path(gid)):
                if os.path.isfile(path):
                    try:
                        os.remove(path)
                    except OSError:
                        pass
        if final:
            key = f"blob:{gid}".encode("utf-8")
            self._kv_final.delete("final", key)


    # ---------------- KV helpers ----------------
    def _open_store(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        init_size = int(CFG.STORAGE_SIZE_INIT)
        max_size = int(CFG.STORAGE_MAX_BYTES)

        if os.path.isfile(path):
            try:
                existing = os.path.getsize(path)
                if existing > init_size:
                    init_size = existing
            except OSError:
                pass
        if max_size > 0 and max_size < init_size:
            max_size = init_size
        drive_override = os.getenv("TSAR_STORAGE_DRIVE_TYPE")
        store = _native_open_storage(
            "lmdb",
            path,
            map_size_init=int(init_size),
            map_size_max=int(max_size),
            pretty_json=False,
            drive_type=drive_override,
        )
        dt = getattr(store, "drive_type", "unknown")
        log.info(f"Archivist LMDB storage initialized at '{path}' [Drive Profile: {dt.upper()}]")
        return store


    def _incoming_dir(self) -> str:
        path = os.path.join(self.storage_dir, "incoming")
        os.makedirs(path, exist_ok=True)
        return path


    def _incoming_part_path(self, gid: str) -> str:
        return os.path.join(self._incoming_dir(), f"{gid}.part")


    def _incoming_bin_path(self, gid: str) -> str:
        return os.path.join(self._incoming_dir(), f"{gid}.bin")


__all__ = ["ArchivistDatabase"]
