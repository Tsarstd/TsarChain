# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: BIP143; BIP141; Merkle; libsecp256k1; LowS-Policy
import time
import secrets
import argparse
from typing import List, Tuple

import tsarchain.utils.helpers as H
from ecdsa import SigningKey, VerifyingKey, SECP256k1, util as ecdsa_util


# -----------------------------
# Utilities
# -----------------------------

def human(n):
    try:
        return f"{int(n):,}".replace(",", ".")
    except Exception:
        return str(n)

def hx(b: bytes, n: int = 64) -> str:
    if not isinstance(b, (bytes, bytearray)):
        try:
            b = bytes(b)
        except Exception:
            return str(b)
    s = b.hex()
    return s if len(s) <= n else s[:n] + "…"

def _make_low_s_der(sk: SigningKey, digest32: bytes) -> bytes:
    rb, sb = sk.sign_digest(digest32, sigencode=ecdsa_util.sigencode_strings)
    r = int.from_bytes(rb, "big")
    s = int.from_bytes(sb, "big")
    n = SECP256k1.order
    if s > n // 2:
        s = n - s
    return ecdsa_util.sigencode_der(r, s, n)

def _make_high_s_from_low_der(der_low: bytes) -> bytes:
    r, s = H.decode_der_sig(der_low)
    n = SECP256k1.order
    if s <= n // 2:
        s = n - s

    try:
        return H.der_encode_sig_strict(r, s)
    except AttributeError:
        def enc_int(x: int) -> bytes:
            b = x.to_bytes((x.bit_length() + 7) // 8, 'big') or b'\x00'
            if b[0] & 0x80:
                b = b'\x00' + b
            return b
        rb, sb = enc_int(r), enc_int(s)
        seq = b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb
        return b"\x30" + bytes([len(seq)]) + seq

def _vk_bytes_uncompressed(vk: VerifyingKey) -> bytes:
    return b"\x04" + vk.to_string()

def _vk_bytes_raw64(vk: VerifyingKey) -> bytes:
    return vk.to_string()  # X||Y (64B)


# -----------------------------
# Merkle variants (for diagnosis)
# -----------------------------

def _py_merkle(txids: List[bytes]) -> bytes:
    return H._py_merkle_root(txids)

def _py_merkle_rev_leaves(txids: List[bytes]) -> bytes:
    tx = [t[::-1] for t in txids]
    return H._py_merkle_root(tx)

def _py_merkle_rev_final(txids: List[bytes]) -> bytes:
    return H._py_merkle_root(txids)[::-1]

def _py_merkle_rev_both(txids: List[bytes]) -> bytes:
    return H._py_merkle_root([t[::-1] for t in txids])[::-1]


# -----------------------------
# Micro-bench functions
# -----------------------------

def bench_sigops(iters: int) -> float:
    scripts = [b"\xac", b"\x51\xae", b"\x60\xae"]  # CHECKSIG; 1 CHECKMULTISIG; 16 CHECKMULTISIG
    t0 = time.perf_counter()
    s = 0
    for i in range(iters):
        s += H.count_sigops_in_script(scripts[i % 3])
    dt = time.perf_counter() - t0
    assert s >= 0
    return dt

def bench_merkle(n_txids: int, reps: int) -> float:
    txids = [secrets.token_bytes(32) for _ in range(n_txids)]
    t0 = time.perf_counter()
    last = None
    for _ in range(reps):
        last = H.merkle_root(txids)
    dt = time.perf_counter() - t0
    assert isinstance(last, (bytes, bytearray)) and len(last) == 32
    return dt

def bench_verify_ecdsa(num_keys: int, iters: int) -> float:
    vectors = []
    for _ in range(num_keys):
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.verifying_key
        d = secrets.token_bytes(32)
        der = _make_low_s_der(sk, d)
        if hasattr(H, "is_signature_canonical_low_s"):
            assert H.is_signature_canonical_low_s(der)
        vectors.append((vk, d, der))

    # sanity
    for (vk, d, der) in vectors[:min(5, len(vectors))]:
        ok = H.verify_der_strict_low_s(vk, d, der)
        assert ok

    t0 = time.perf_counter()
    ok_count = 0
    for i in range(iters):
        vk, d, der = vectors[i % num_keys]
        if H.verify_der_strict_low_s(vk, d, der):
            ok_count += 1
    dt = time.perf_counter() - t0
    assert ok_count >= 0
    return dt

def bench_verify_batch(num_keys: int, iters: int) -> float:
    vecs = []
    for _ in range(num_keys):
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.verifying_key
        d = secrets.token_bytes(32)
        der = _make_low_s_der(sk, d)
        vecs.append((vk, d, der))

    if getattr(H, "_HAVE_NATIVE", False):
        items = [(_vk_bytes_uncompressed(vk), d, der) for (vk, d, der) in vecs]
    else:
        items = [(_vk_bytes_raw64(vk), d, der) for (vk, d, der) in vecs]

    singles = [H.verify_der_strict_low_s(vk, d, der) for (vk, d, der) in vecs]
    batch_once = H.batch_verify_der_low_s(items, enforce_low_s=True, parallel=True)
    assert list(map(bool, batch_once)) == list(map(bool, singles)), "batch != single result"

    t0 = time.perf_counter()
    cnt = 0
    for _ in range(max(1, iters // num_keys)):
        res = H.batch_verify_der_low_s(items, enforce_low_s=True, parallel=True)
        cnt += sum(1 for x in res if x)
    dt = time.perf_counter() - t0
    assert cnt >= 0
    return dt

def bench_hashes(total_bytes: int = 2_000_000) -> Tuple[float, float]:
    blobs = []
    left = total_bytes
    while left > 0:
        n = min(left, secrets.randbelow(4096) + 1)
        blobs.append(secrets.token_bytes(n))
        left -= n

    t0 = time.perf_counter()
    for b in blobs:
        _ = H.hash256_native(b)
    dt256 = time.perf_counter() - t0

    t0 = time.perf_counter()
    for b in blobs:
        _ = H.hash160_native(b)
    dt160 = time.perf_counter() - t0

    return dt256, dt160


# -----------------------------
# Correctness tests
# -----------------------------

def check_hash_parity(samples: int = 200):
    for _ in range(samples):
        b = secrets.token_bytes(secrets.randbelow(512) + 1)
        assert H.hash256_native(b) == H.hash256(b)
        assert H.hash160_native(b) == H.hash160(b)

def diagnose_merkle_diff(txids: List[bytes], r_native: bytes, r_py: bytes, show_debug=False) -> str:
    cand1 = _py_merkle_rev_leaves(txids)
    cand2 = _py_merkle_rev_final(txids)
    cand3 = _py_merkle_rev_both(txids)

    if r_native == cand1:
        tag = "leaves_reversed"
    elif r_native == cand2:
        tag = "final_reversed"
    elif r_native == cand3:
        tag = "both_reversed"
    else:
        tag = "unknown"

    if show_debug:
        print("  > py      :", hx(r_py))
        print("  > native  :", hx(r_native))
        print("  > cand1(L):", hx(cand1), "== native?", cand1 == r_native)
        print("  > cand2(F):", hx(cand2), "== native?", cand2 == r_native)
        print("  > cand3(LF):", hx(cand3), "== native?", cand3 == r_native)
        print("  > sample leaves:", hx(txids[0]), hx(txids[-1]))
    return tag

def check_merkle_parity(strict: bool = False, show_debug: bool = False):
    mismatches = []
    for n in (1, 2, 3, 8, 17, 32):
        txids = [secrets.token_bytes(32) for _ in range(n)]
        r_native = H.merkle_root(txids)
        r_py = H._py_merkle_root(txids)

        ok_types = (
            isinstance(r_native, (bytes, bytearray)) and len(r_native) == 32,
            isinstance(r_py, (bytes, bytearray)) and len(r_py) == 32,
        )
        if not all(ok_types):
            raise AssertionError("Merkle root must be 32 bytes on both paths")

        if r_native != r_py:
            tag = diagnose_merkle_diff(txids, r_native, r_py, show_debug=show_debug)
            mismatches.append((n, tag, r_native, r_py))

    # empty set semantics
    empty_native = H.merkle_root([])
    ok_empty_form = isinstance(empty_native, (bytes, bytearray)) and len(empty_native) == 32 and set(empty_native) <= {0}
    assert ok_empty_form, "merkle([]) must be 32 zero bytes on native path"
    empty_py = H._py_merkle_root([])
    if not (isinstance(empty_py, (bytes, bytearray)) and len(empty_py) == 32):
        print("[warn] _py_merkle_root([]) bukan 32-byte; pertimbangkan samakan perilaku dengan native")

    if mismatches:
        print("\n[merkle] parity: MISMATCHES detected")
        buckets = {}
        for n, tag, _, _ in mismatches:
            buckets.setdefault(tag, []).append(n)
        for tag, sizes in buckets.items():
            print(f"  - case={tag:>14}  sizes={sizes}")
        if strict:
            # tampilkan contoh satu mismatch sebelum fail
            n, tag, r_native, r_py = mismatches[0]
            print(f"  example mismatch (n={n}, case={tag}):")
            print("    py     :", hx(r_py))
            print("    native :", hx(r_native))
            raise AssertionError("native vs python merkle mismatch (strict mode)")
    else:
        print("[ok] merkle parity (all tested sizes)")

def check_verify_low_s():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    d = secrets.token_bytes(32)
    der_low = _make_low_s_der(sk, d)
    der_high = _make_high_s_from_low_der(der_low)
    assert H.verify_der_strict_low_s(vk, d, der_low) is True
    assert H._py_verify_der_strict_low_s(vk, d, der_low) is True
    assert H.verify_der_strict_low_s(vk, d, der_high) is False
    assert H._py_verify_der_strict_low_s(vk, d, der_high) is False

def check_batch_matches_single(num: int = 64):
    vecs = []
    for _ in range(num):
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.verifying_key
        d = secrets.token_bytes(32)
        der = _make_low_s_der(sk, d)
        vecs.append((vk, d, der))

    singles = [H.verify_der_strict_low_s(vk, d, der) for (vk, d, der) in vecs]

    if getattr(H, "_HAVE_NATIVE", False):
        items = [(_vk_bytes_uncompressed(vk), d, der) for (vk, d, der) in vecs]
    else:
        items = [(_vk_bytes_raw64(vk), d, der) for (vk, d, der) in vecs]

    batch = H.batch_verify_der_low_s(items, enforce_low_s=True, parallel=True)
    assert list(map(bool, batch)) == list(map(bool, singles)), "batch != single result"

# ---- BIP143 SIGHASH (ALL) parity test ----

class _RawScript:
    def __init__(self, b: bytes): self.b = bytes(b)
    def serialize(self) -> bytes: return self.b

class _TxIn:
    def __init__(self, txid: bytes, vout: int, script_sig: _RawScript = None, sequence: int = 0xffffffff, witness=None):
        self.txid = txid
        self.vout = vout
        self.script_sig = script_sig or _RawScript(b"")
        self.sequence = sequence
        self.witness = witness or []

class _TxOut:
    def __init__(self, amount: int, script_pubkey: _RawScript):
        self.amount = int(amount)
        self.script_pubkey = script_pubkey

class _Tx:
    def __init__(self, version: int, inputs: List[_TxIn], outputs: List[_TxOut], locktime: int = 0):
        self.version = int(version)
        self.inputs = inputs
        self.outputs = outputs
        self.locktime = int(locktime)

def check_bip143_parity():
    prev_txid = secrets.token_bytes(32)
    inp = _TxIn(txid=prev_txid, vout=1, script_sig=_RawScript(b""))
    spk1 = _RawScript(b"\x00\x14" + secrets.token_bytes(20))
    spk2 = _RawScript(b"\x00\x14" + secrets.token_bytes(20))
    out1 = _TxOut(50_000, spk1)
    out2 = _TxOut(30_000, spk2)
    tx = _Tx(version=2, inputs=[inp], outputs=[out1, out2], locktime=0)

    script_code = b"\x76\xa9\x14" + b"\x11"*20 + b"\x88\xac"
    digest_native = H.bip143_sig_hash(tx, 0, script_code, value=50_000, sighash=H.SIGHASH_ALL)
    digest_py = H._py_bip143_sig_hash(tx, 0, script_code, value=50_000, sighash=H.SIGHASH_ALL)
    assert isinstance(digest_native, (bytes, bytearray)) and len(digest_native) == 32
    assert digest_native == digest_py, "BIP143 digest mismatch (native vs python)"


# -----------------------------
# CLI
# -----------------------------

def main():
    ap = argparse.ArgumentParser(description="TsarChain native test (correctness + microbench)")
    ap.add_argument("--sigops-iters", type=int, default=250_000)
    ap.add_argument("--merkle-n", type=int, default=1_000)
    ap.add_argument("--merkle-reps", type=int, default=200)
    ap.add_argument("--ecdsa-keys", type=int, default=200)
    ap.add_argument("--ecdsa-iters", type=int, default=5_000)
    ap.add_argument("--batch-keys", type=int, default=256)
    ap.add_argument("--batch-iters", type=int, default=2_048)
    ap.add_argument("--hash-total", type=int, default=1_500_000, help="total bytes for hash benches")
    ap.add_argument("--no-bench-batch", action="store_true")
    ap.add_argument("--no-bench-hash", action="store_true")
    ap.add_argument("--strict-merkle", action="store_true", help="fail jika merkle mismatch")
    ap.add_argument("--show-merkle-debug", action="store_true", help="tampilkan detail diagnosis merkle")
    args = ap.parse_args()

    print(f"native loaded? {getattr(H, '_HAVE_NATIVE', False)}  reason={getattr(H, '_native_reason', '?')}")
    print("Functions available:", [x for x in (
        "count_sigops_in_script", "bip143_sig_hash",
        "verify_der_strict_low_s", "merkle_root",
        "hash256_native", "hash160_native", "batch_verify_der_low_s"
    ) if hasattr(H, x)])

    # -------- correctness --------
    print("\n== correctness checks ==")
    check_hash_parity()
    print("[ok] hash256/hash160 parity")

    check_merkle_parity(strict=args.strict_merkle, show_debug=args.show_merkle_debug)
    print("[note] merkle parity check finished")

    check_verify_low_s()
    print("[ok] verify_der_strict_low_s (low-S true, high-S false)")

    check_batch_matches_single()
    print("[ok] batch_verify_der_low_s == single verify")

    check_bip143_parity()
    print("[ok] bip143_sig_hash parity (SIGHASH_ALL)")

    # -------- microbenches --------
    print("\n== microbench ==")
    dt = bench_sigops(args.sigops_iters)
    rate = args.sigops_iters / dt
    print(f"[sigops] {human(args.sigops_iters)} loops in {dt:.3f}s -> {human(int(rate))} ops/s")

    dt = bench_merkle(args.merkle_n, args.merkle_reps)
    rate = args.merkle_reps / dt
    print(f"[merkle] {args.merkle_reps} trees (n={args.merkle_n}) in {dt:.3f}s -> {rate:.1f} trees/s")

    dt = bench_verify_ecdsa(args.ecdsa_keys, args.ecdsa_iters)
    rate = args.ecdsa_iters / dt
    print(f"[ecdsa-single] {human(args.ecdsa_iters)} verifications in {dt:.3f}s -> {human(int(rate))} verif/s")

    if not args.no_bench_batch:
        dt = bench_verify_batch(args.batch_keys, args.batch_iters)
        total_verifs = (args.batch_iters // max(1, args.batch_keys)) * args.batch_keys
        rate = max(1, total_verifs) / dt if dt > 0 else 0
        print(f"[ecdsa-batch] ~{human(total_verifs)} verifications in {dt:.3f}s -> ~{human(int(rate))} verif/s")

    if not args.no_bench_hash:
        dt256, dt160 = bench_hashes(args.hash_total)
        print(f"[hash256_native] {human(args.hash_total)}B in {dt256:.3f}s")
        print(f"[hash160_native] {human(args.hash_total)}B in {dt160:.3f}s")


if __name__ == "__main__":
    main()
