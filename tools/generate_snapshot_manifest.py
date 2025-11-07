#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

"""
Utility to generate (and optionally sign) a snapshot manifest JSON file.
Run this on the machine yang menerbitkan data.mdb agar klien bisa mendapatkan metadata height/sha256.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict
from ecdsa import SECP256k1, SigningKey


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _load_meta(path: Path | None) -> Dict[str, Any]:
    if not path or not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _load_signing_key(raw: str) -> SigningKey:
    if SigningKey is None:
        raise RuntimeError("ecdsa library belum terpasang. pip install ecdsa untuk fitur penandatanganan.")
    candidate = Path(raw)
    if candidate.exists():
        key_hex = candidate.read_text(encoding="utf-8").strip()
    else:
        key_hex = raw.strip()
    if len(key_hex) != 64:
        raise ValueError("Kunci privat harus berupa hex 32-byte (64 karakter).")
    return SigningKey.from_string(bytes.fromhex(key_hex), curve=SECP256k1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate snapshot manifest for TsarChain data.mdb")
    parser.add_argument("--data", default="data/DB/data.mdb", help="Path ke file data.mdb yang akan dipublikasikan")
    parser.add_argument("--meta", default="data/DB/snapshot.meta.json", help="Path snapshot.meta.json untuk mengambil info tambahan")
    parser.add_argument("--output", default="data/DB/snapshot.manifest.json", help="File output manifest")
    parser.add_argument("--url", help="URL publik tempat data.mdb akan tersedia (http(s)://...)")
    parser.add_argument("--height", type=int, help="Tinggi blok snapshot (override jika tidak memakai meta)")
    parser.add_argument("--timestamp", type=int, help="Unix timestamp saat snapshot dibuat")
    parser.add_argument("--note", help="Catatan tambahan yang akan dimasukkan ke manifest")
    parser.add_argument("--sign-key", help="Hex private key (atau path file) untuk menandatangani manifest")
    args = parser.parse_args()

    data_path = Path(args.data).expanduser().resolve()
    if not data_path.exists():
        parser.error(f"File data.mdb tidak ditemukan: {data_path}")

    meta = _load_meta(Path(args.meta).expanduser().resolve())

    height = args.height if args.height is not None else meta.get("height")
    if height is None:
        parser.error("Parameter --height diperlukan (atau jalankan node sekali agar snapshot.meta.json terisi).")

    timestamp = args.timestamp if args.timestamp is not None else meta.get("generated_at") or int(time.time())
    source_url = args.url or meta.get("source") or ""
    size = data_path.stat().st_size
    sha256_hex = _sha256_file(data_path)

    manifest: Dict[str, Any] = {
        "version": 1,
        "snapshot_url": source_url,
        "size": int(size),
        "sha256": sha256_hex,
        "height": int(height),
        "generated_at": int(timestamp),
    }
    if args.note:
        manifest["note"] = args.note

    if args.sign_key:
        try:
            sk = _load_signing_key(args.sign_key)
        except Exception as exc:  # pragma: no cover - CLI error path
            parser.error(f"Gagal memuat kunci privat: {exc}")
        payload = json.dumps(
            {k: v for k, v in manifest.items() if k != "signature"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        manifest["signature"] = sk.sign(payload, hashfunc=hashlib.sha256).hex()

    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Manifest tersimpan di {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
