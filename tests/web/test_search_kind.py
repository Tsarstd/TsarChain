# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

from web.Backend.src.utils.search_kind import guess_kind, is_hex64


def test_is_hex64():
    assert is_hex64("a" * 64) is True
    assert is_hex64("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") is True
    assert is_hex64("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF") is True
    assert is_hex64("a" * 63) is False
    assert is_hex64("a" * 65) is False
    assert is_hex64("g" * 64) is False
    assert is_hex64("") is False
    assert is_hex64(None) is False
    assert is_hex64(123) is False


def test_guess_kind():
    # Empty / None / invalid
    assert guess_kind(None) == "unknown"
    assert guess_kind("") == "unknown"
    assert guess_kind("   ") == "unknown"
    assert guess_kind(123) == "unknown"

    # Graffiti art_id
    assert guess_kind("graf123456") == "art_id"
    assert guess_kind("GRAF123456") == "art_id"

    # Address
    assert guess_kind("tsar1qqqqqqqqqqqqqqqqqqqqqqqqqqqq") == "address"
    assert guess_kind("tsar1short") == "unknown"  # length < 20

    # Block height
    assert guess_kind("0") == "block_height"
    assert guess_kind("1234567") == "block_height"
    assert guess_kind("12345678") == "unknown"  # > 7 digits

    # 64-hex hash
    assert guess_kind("a" * 64) == "hash64"

    # Unrecognized string
    assert guess_kind("some-random-query") == "unknown"
