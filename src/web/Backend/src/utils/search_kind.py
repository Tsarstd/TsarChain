# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import re

ART_ID_PREFIX = "graf"

_HEX64_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
_BLOCK_HEIGHT_REGEX = re.compile(r"^\d{1,7}$")


def is_hex64(s: str | None) -> bool:
    if not s or type(s) is not str:
        return False
    return bool(_HEX64_REGEX.match(s))


def guess_kind(raw: str | None) -> str:
    if not raw or type(raw) is not str:
        return "unknown"
    q = raw.strip()
    if not q:
        return "unknown"

    lower = q.lower()
    if lower.startswith(ART_ID_PREFIX):
        return "art_id"
    if lower.startswith("tsar") and len(q) >= 20:
        return "address"
    if _BLOCK_HEIGHT_REGEX.match(q):
        return "block_height"
    if _HEX64_REGEX.match(q):
        return "hash64"

    return "unknown"
