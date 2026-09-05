# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: Signal-X3DH; RFC7748-X25519; BIP173-Bech32; SECP256k1-LowS

"""
Integration test & benchmark for RPC endpoint 'CHAT_REGISTER'.
Tests cryptographic validation, address proofing, prekey bundle persistence,
rate-limiting, and concurrent server throughput under high network traffic
without needing to boot a live network node daemon.
"""

import sys
import time
import secrets
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Tuple

# Ensure src/ is in sys.path
SRC_DIR = Path(__file__).resolve().parents[2] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Reconfigure stdout for unicode safety on Windows consoles
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from tsarchain.utils import config as CFG
import kremlin.security.data_security as WALL
import kremlin.security.chat.chat_common as COM
from tsarchain.network.rpc.processing_msg import process_message
from tsarchain.network.rpc_helper.guard import GuardHandler
from tsarchain.network.rpc_helper.chat import ChatHandler
from tsarchain.network.node_logic.chat_state import init_chat_state


def human(n: float | int) -> str:
    try:
        return f"{int(n):,}".replace(",", ".")
    except Exception:
        return str(n)


class MockRpcServer:
    """Lightweight in-memory TsarChain network node for isolated RPC testing."""

    def __init__(self):
        init_chat_state(self)
        self.peers = set()
        self.storage_peers = {}
        self.peer_pubkeys = {}
        self.guard = GuardHandler(self)
        self.chat = ChatHandler(self)
        self._bundles: Dict[str, dict] = {}
        self.relayed_presences: List[dict] = []

    def tb_node_allow(self, table, key, rate_per_window, window_s, burst, backoff_key=None):
        return self.guard.tb_node_allow(table, key, rate_per_window, window_s, burst, backoff_key=backoff_key)

    def backoff_node(self, key, secs):
        return self.guard.backoff_node(key, secs)

    def get_prekey_bundle(self, addr: str) -> dict:
        return dict(self._bundles.get(addr, {}))

    def put_prekey_bundle(self, addr: str, bundle: dict) -> None:
        self._bundles[addr] = dict(bundle)

    def relay_presence_async(self, pres: dict, exclude=None) -> None:
        self.relayed_presences.append(pres)


def generate_registration_payload(
    priv_hex: str | None = None,
    ts_offset: int = 0,
    corrupt_presence_sig: bool = False,
    corrupt_reg_sig: bool = False,
    corrupt_spk_sig: bool = False,
    mismatch_address: bool = False,
) -> Tuple[Dict[str, Any], str, str]:
    """Generates a canonically signed CHAT_REGISTER payload using wallet crypto helpers."""
    if not priv_hex:
        priv_hex = secrets.token_hex(32)

    spend_pub = WALL.pubkey_from_privhex(priv_hex).hex()
    addr = WALL.pubkey_to_tsar_address(bytes.fromhex(spend_pub))

    if mismatch_address:
        alt_priv = secrets.token_hex(32)
        alt_pub = WALL.pubkey_from_privhex(alt_priv)
        addr = WALL.pubkey_to_tsar_address(alt_pub)

    _, chat_pk = COM.chat_dh_gen_keypair()
    _, spk_pk = COM.chat_dh_gen_keypair()
    _, opk_pk = COM.chat_dh_gen_keypair()

    ts = int(time.time()) + ts_offset

    reg_bytes = b"|".join([b"CHAT_REG", addr.encode(), bytes.fromhex(spend_pub), bytes.fromhex(chat_pk), str(ts).encode()])
    reg_sig = COM.sign(priv_hex, reg_bytes)
    if corrupt_reg_sig:
        reg_sig = secrets.token_hex(len(reg_sig) // 2)

    pres_bytes = b"|".join([b"CHAT_PRESENCE", addr.encode(), bytes.fromhex(chat_pk), bytes.fromhex(spend_pub), str(ts).encode()])
    pres_sig = COM.sign(priv_hex, pres_bytes)
    if corrupt_presence_sig:
        pres_sig = secrets.token_hex(len(pres_sig) // 2)

    spk_bytes = CFG.CHAT_SPK + bytes.fromhex(spk_pk) + b"|" + bytes.fromhex(spend_pub)
    spk_sig = COM.sign(priv_hex, spk_bytes)
    if corrupt_spk_sig:
        spk_sig = secrets.token_hex(len(spk_sig) // 2)

    payload = {
        "type": "CHAT_REGISTER",
        "address": addr,
        "spend_pub": spend_pub,
        "chat_pub": chat_pk,
        "ts": ts,
        "reg_sig": reg_sig,
        "presence_sig": pres_sig,
        "spk": spk_pk,
        "sig": spk_sig,
        "opk": opk_pk,
    }
    return payload, addr, spend_pub


# -----------------------------------------------------------------------------
# Correctness Tests
# -----------------------------------------------------------------------------

def test_valid_registration():
    server = MockRpcServer()
    payload, addr, spend_pub = generate_registration_payload()

    res = process_message(server, payload, addr=("10.1.1.1", 10001))
    assert res.get("type") == "CHAT_REGISTERED", f"Unexpected response: {res}"
    assert res.get("address") == addr
    assert res.get("pubkey") == payload["chat_pub"]

    # Verify RAM state
    assert server.chat_spend_pub.get(addr) == spend_pub
    assert server.chat_presence_pub.get(addr) == payload["chat_pub"]
    assert server.chat_presence_ts.get(addr) == payload["ts"]

    # Verify Prekey bundle in database
    bundle = server.get_prekey_bundle(addr)
    assert bundle.get("ik") == payload["chat_pub"]
    assert bundle.get("spk") == payload["spk"]
    assert bundle.get("sig") == payload["sig"]
    assert bundle.get("spend_pub") == spend_pub
    assert bundle.get("opk_list") == [payload["opk"]]
    assert len(server.relayed_presences) == 1


def test_tampered_presence_signature():
    server = MockRpcServer()
    payload, _, _ = generate_registration_payload(corrupt_presence_sig=True)
    res = process_message(server, payload, addr=("10.1.2.1", 10002))
    assert res.get("error") == "bad_presence_sig", f"Expected bad_presence_sig, got: {res}"


def test_tampered_reg_signature():
    server = MockRpcServer()
    payload, _, _ = generate_registration_payload(corrupt_reg_sig=True)
    res = process_message(server, payload, addr=("10.1.3.1", 10003))
    assert res.get("error") == "bad reg_sig", f"Expected bad reg_sig, got: {res}"


def test_tampered_spk_signature():
    server = MockRpcServer()
    payload, _, _ = generate_registration_payload(corrupt_spk_sig=True)
    res = process_message(server, payload, addr=("10.1.4.1", 10004))
    assert res.get("error") == "bad_spk_sig", f"Expected bad_spk_sig, got: {res}"


def test_address_proof_mismatch():
    server = MockRpcServer()
    payload, _, _ = generate_registration_payload(mismatch_address=True)
    res = process_message(server, payload, addr=("10.1.5.1", 10005))
    assert res.get("error") == "register proof mismatch", f"Expected register proof mismatch, got: {res}"


def test_stale_timestamp():
    server = MockRpcServer()
    # Anti replay window is +-300 seconds (5 minutes)
    payload, _, _ = generate_registration_payload(ts_offset=-400)
    res = process_message(server, payload, addr=("10.1.6.1", 10006))
    assert res.get("error") == "stale ts", f"Expected stale ts, got: {res}"


def test_rate_limiting_per_address():
    server = MockRpcServer()
    priv_hex = secrets.token_hex(32)
    addr_burst = int(CFG.CHAT_REG_RL_ADDR_BURST)

    success_count = 0
    rate_limited = False

    # Send addr_burst + 3 requests from the same account
    for i in range(addr_burst + 3):
        ip = f"10.2.{i}.1"  # Unique IPs to isolate address limiter
        payload, _, _ = generate_registration_payload(priv_hex=priv_hex)
        res = process_message(server, payload, addr=(ip, 20000 + i))
        if res.get("type") == "CHAT_REGISTERED":
            success_count += 1
        elif res.get("error") in ("pow_required", "rate_limited"):
            rate_limited = True

    assert success_count == addr_burst, f"Expected exactly {addr_burst} accepted, got {success_count}"
    assert rate_limited, "Rate limiter did not trip after burst exhaustion"


def test_rate_limiting_per_ip():
    server = MockRpcServer()
    ip_burst = int(CFG.CHAT_REG_RL_IP_BURST)
    client_ip = "192.168.100.50"

    success_count = 0
    rate_limited = False

    # Send ip_burst + 3 requests from the same IP (different addresses)
    for i in range(ip_burst + 3):
        payload, _, _ = generate_registration_payload()
        res = process_message(server, payload, addr=(client_ip, 30000 + i))
        if res.get("type") == "CHAT_REGISTERED":
            success_count += 1
        elif res.get("error") in ("pow_required", "rate_limited"):
            rate_limited = True

    assert success_count == ip_burst, f"Expected exactly {ip_burst} accepted, got {success_count}"
    assert rate_limited, "IP rate limiter did not trip after burst exhaustion"


def run_correctness_checks():
    checks = [
        ("valid registration & prekey persistence", test_valid_chat_register),
        ("tampered presence signature rejection", test_tampered_presence_signature),
        ("tampered register signature rejection", test_tampered_reg_signature),
        ("tampered SPK signature rejection", test_tampered_spk_signature),
        ("address proof mismatch rejection", test_address_proof_mismatch),
        ("stale timestamp rejection", test_stale_timestamp),
        ("per-address rate limiting enforcement", test_rate_limiting_per_address),
        ("per-ip rate limiting enforcement", test_rate_limiting_per_ip),
    ]
    for label, fn in checks:
        fn()
        print(f"[chat_register] {label}: ok")


# Alias for naming consistency
test_valid_chat_register = test_valid_registration


# -----------------------------------------------------------------------------
# Micro-benchmarks
# -----------------------------------------------------------------------------

def bench_client_payload_generation(count: int) -> Tuple[float, List[Dict[str, Any]]]:
    t0 = time.perf_counter()
    payloads = [generate_registration_payload()[0] for _ in range(count)]
    dt = time.perf_counter() - t0
    return dt, payloads


def bench_sequential_server_throughput(server: MockRpcServer, payloads: List[Dict[str, Any]]) -> float:
    t0 = time.perf_counter()
    ok_count = 0
    for i, p in enumerate(payloads):
        # Distribute across unique /24 subnets to simulate a wide decentralized network
        ip = f"10.{(i // 250) % 250}.{i % 250}.1"
        res = process_message(server, p, addr=(ip, 12000 + i))
        if res.get("type") == "CHAT_REGISTERED":
            ok_count += 1
    dt = time.perf_counter() - t0
    assert ok_count == len(payloads), f"Expected {len(payloads)} ok, got {ok_count}"
    return dt


def bench_concurrent_server_throughput(server: MockRpcServer, payloads: List[Dict[str, Any]], workers: int) -> float:
    def _worker(item: Tuple[int, Dict[str, Any]]) -> bool:
        idx, p = item
        ip = f"172.{(idx // 250) % 250}.{idx % 250}.1"
        res = process_message(server, p, addr=(ip, 20000 + idx))
        return res.get("type") == "CHAT_REGISTERED"

    items = list(enumerate(payloads))
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(_worker, items))
    dt = time.perf_counter() - t0
    ok_count = sum(1 for r in results if r)
    assert ok_count == len(payloads), f"Expected {len(payloads)} ok, got {ok_count}"
    return dt


def bench_rate_limiter_rejection(server: MockRpcServer, attempts: int) -> float:
    # Trip rate limiter with same address
    priv = secrets.token_hex(32)
    p, _, _ = generate_registration_payload(priv_hex=priv)
    ip = "192.168.1.1"

    # Burn burst allowance
    for i in range(int(CFG.CHAT_REG_RL_ADDR_BURST)):
        process_message(server, p, addr=(f"10.0.{i}.1", 10000 + i))

    t0 = time.perf_counter()
    rejected = 0
    for i in range(attempts):
        res = process_message(server, p, addr=(f"10.0.{i}.2", 15000 + i))
        if res.get("error") in ("pow_required", "rate_limited"):
            rejected += 1
    dt = time.perf_counter() - t0
    assert rejected == attempts, f"Expected {attempts} rejections, got {rejected}"
    return dt


# -----------------------------------------------------------------------------
# Main CLI
# -----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="TsarChain RPC 'CHAT_REGISTER' integration test & throughput benchmark"
    )
    parser.add_argument("--count", type=int, default=200, help="number of simulated user registrations (default: 200)")
    parser.add_argument("--workers", type=int, default=4, help="number of concurrent client worker threads (default: 4)")
    parser.add_argument("--rejection-iters", type=int, default=5_000, help="number of rate-limiter rejection loops (default: 5000)")
    parser.add_argument("--no-bench", action="store_true", help="run correctness checks only")
    parser.add_argument("--lite", action="store_true", help="use smaller test volume for rapid test runs")
    parser.add_argument("--verbose", action="store_true", help="enable verbose internal logger warnings")
    args = parser.parse_args()

    if not args.verbose:
        import logging
        logging.disable(logging.WARNING)

    count = 50 if args.lite else args.count
    workers = min(count, args.workers)
    rejection_iters = 1_000 if args.lite else args.rejection_iters

    print("=" * 72)
    print("🚀 TSARCHAIN RPC 'CHAT_REGISTER' INTEGRATION TEST & BENCHMARK")
    print("=" * 72)
    print(f"Parameters: simulated_users={count}, concurrent_workers={workers}")

    # -------- Correctness Checks --------
    print("\n== correctness checks ==")
    run_correctness_checks()

    if args.no_bench:
        print("\n✅ All correctness checks passed (--no-bench specified).")
        return

    # -------- Microbenchmarks --------
    print("\n== microbench ==")

    # 1. Client-side payload signing & bundle creation
    dt_client, payloads = bench_client_payload_generation(count)
    rate_client = count / dt_client if dt_client > 0 else 0
    print(f"[client-sign] {human(count)} payloads signed (3x Secp256k1 Low-S + X25519) in {dt_client:.3f}s -> {human(int(rate_client))} payloads/s ({dt_client/count*1000:.2f} ms/payload)")

    # 2. Server-side sequential throughput
    server_seq = MockRpcServer()
    dt_seq = bench_sequential_server_throughput(server_seq, payloads)
    rate_seq = count / dt_seq if dt_seq > 0 else 0
    print(f"[server-seq]  {human(count)} RPC registrations processed in {dt_seq:.3f}s -> {human(int(rate_seq))} req/s ({dt_seq/count*1000:.3f} ms/req)")

    # 3. Server-side concurrent throughput
    server_conc = MockRpcServer()
    # Generate fresh payloads for concurrent run
    _, conc_payloads = bench_client_payload_generation(count)
    dt_conc = bench_concurrent_server_throughput(server_conc, conc_payloads, workers)
    rate_conc = count / dt_conc if dt_conc > 0 else 0
    print(f"[server-conc] {human(count)} RPC registrations ({workers} workers) in {dt_conc:.3f}s -> {human(int(rate_conc))} req/s ({dt_conc/count*1000:.3f} ms/req)")

    # 4. Rate-limiter fast-rejection throughput (anti-DoS defense speed)
    server_reject = MockRpcServer()
    dt_rej = bench_rate_limiter_rejection(server_reject, rejection_iters)
    rate_rej = rejection_iters / dt_rej if dt_rej > 0 else 0
    print(f"[server-dos]  {human(rejection_iters)} rate-limited spam requests rejected in {dt_rej:.3f}s -> {human(int(rate_rej))} drops/s ({dt_rej/rejection_iters*1000:.3f} ms/drop)")

    print("\n" + "=" * 72)
    print("🔒 ALL CHAT_REGISTER TESTS & BENCHMARKS COMPLETED SUCCESSFULLY.")
    print("=" * 72)


if __name__ == "__main__":
    main()
