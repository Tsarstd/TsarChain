# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from typing import List, Tuple

from tsarchain.network.dandelion_pp import DandelionPP
from tsarchain.utils import config as CFG


class _DummyTx:
    def __init__(self, txid_hex: str):
        self.txid = bytes.fromhex(txid_hex)

    def to_dict(self) -> dict:
        return {"txid": self.txid.hex()}


class _HostStub:
    def __init__(self, send_ok: bool = True):
        self.send_calls: List[Tuple[Tuple[str, int], dict]] = []
        self.fluff_calls: List[Tuple[str, set]] = []
        self.send_ok = send_ok

    def _send(self, peer: Tuple[str, int], msg: dict) -> bool:
        self.send_calls.append((peer, msg))
        return self.send_ok

    def broadcast_tx_fluff(self, tx, tx_id: str, peers: set, exclude=None):
        self.fluff_calls.append((tx_id, peers))
        return len(peers)


@pytest.fixture(autouse=True)
def _patch_timer(monkeypatch):
    """Force scheduled fluff to run synchronously to keep tests fast/deterministic."""
    class _ImmediateTimer:
        def __init__(self, _delay, fn, *args, **kwargs):
            self.fn = fn
            self.daemon = True

        def start(self):
            self.fn()

        def cancel(self):
            pass

    import tsarchain.network.dandelion_pp as dpp
    monkeypatch.setattr(dpp.threading, "Timer", _ImmediateTimer)
    yield


@pytest.fixture
def dummy_tx():
    return _DummyTx("01" * 32)


@pytest.fixture
def peers_basic():
    return {("127.0.0.1", 9000), ("127.0.0.2", 9001)}


def test_outbound_stem_then_fluff(monkeypatch, dummy_tx, peers_basic):
    monkeypatch.setattr(CFG, "ENABLE_DANDELION_PP", True)
    monkeypatch.setattr(CFG, "MIN_PEERS_FOR_DANDELION", 0)

    host = _HostStub(send_ok=True)
    dpp = DandelionPP(host)
    tx_id = dummy_tx.txid.hex()

    handled = dpp.handle_outbound(dummy_tx, tx_id, peers_basic)
    assert handled is True
    assert len(host.send_calls) == 1
    peer, msg = host.send_calls[0]
    assert peer in peers_basic
    assert msg.get("phase") == "stem"
    assert host.fluff_calls and host.fluff_calls[0][0] == tx_id


def test_inbound_stem_dedup_and_fallback_to_fluff(monkeypatch, dummy_tx, peers_basic):
    monkeypatch.setattr(CFG, "ENABLE_DANDELION_PP", True)
    monkeypatch.setattr(CFG, "MIN_PEERS_FOR_DANDELION", 0)

    host = _HostStub(send_ok=False)  # Stem fails → straight to fluff
    dpp = DandelionPP(host)
    tx_id = dummy_tx.txid.hex()
    origin = ("127.0.0.1", 9000)

    handled = dpp.handle_inbound_stem(dummy_tx, tx_id, peers_basic, origin=origin)
    assert handled is True
    assert len(host.send_calls) == 1
    assert host.fluff_calls and host.fluff_calls[0][0] == tx_id

    # resend → dedup, no additional action
    handled_again = dpp.handle_inbound_stem(dummy_tx, tx_id, peers_basic, origin=None)
    assert handled_again is True
    assert len(host.send_calls) == 1
    assert len(host.fluff_calls) == 1


def test_disabled(monkeypatch, dummy_tx, peers_basic):
    monkeypatch.setattr(CFG, "ENABLE_DANDELION_PP", False)
    monkeypatch.setattr(CFG, "MIN_PEERS_FOR_DANDELION", 0)

    host = _HostStub()
    dpp = DandelionPP(host)
    tx_id = dummy_tx.txid.hex()

    handled = dpp.handle_outbound(dummy_tx, tx_id, peers_basic)
    assert handled is False
    assert len(host.send_calls) == 0
    assert len(host.fluff_calls) == 0


def test_min_peers_not_met(monkeypatch, dummy_tx):
    monkeypatch.setattr(CFG, "ENABLE_DANDELION_PP", True)
    monkeypatch.setattr(CFG, "MIN_PEERS_FOR_DANDELION", 3)

    host = _HostStub()
    dpp = DandelionPP(host)
    tx_id = dummy_tx.txid.hex()
    peers = {("1.1.1.1", 8000), ("2.2.2.2", 8001)}  # only 2 peers

    handled = dpp.handle_outbound(dummy_tx, tx_id, peers)
    assert handled is False
    assert len(host.send_calls) == 0


def test_outbound_no_peer(monkeypatch, dummy_tx):
    monkeypatch.setattr(CFG, "ENABLE_DANDELION_PP", True)
    monkeypatch.setattr(CFG, "MIN_PEERS_FOR_DANDELION", 0)

    host = _HostStub()
    dpp = DandelionPP(host)
    tx_id = dummy_tx.txid.hex()

    handled = dpp.handle_outbound(dummy_tx, tx_id, set())  # empty peer
    assert handled is False
    assert len(host.send_calls) == 0


def test_outbound_exclude_all_peers(monkeypatch, dummy_tx, peers_basic):
    monkeypatch.setattr(CFG, "ENABLE_DANDELION_PP", True)
    monkeypatch.setattr(CFG, "MIN_PEERS_FOR_DANDELION", 0)

    host = _HostStub()
    dpp = DandelionPP(host)
    tx_id = dummy_tx.txid.hex()
    # exclude = all existing peers
    exclude = ("127.0.0.1", 9000)
    single_peer = {("127.0.0.1", 9000)}
    handled = dpp.handle_outbound(dummy_tx, tx_id, single_peer, exclude=exclude)
    assert handled is False  # no candidate
    assert len(host.send_calls) == 0


def test_inbound_stem_no_candidate_fluff(monkeypatch, dummy_tx, peers_basic):
    monkeypatch.setattr(CFG, "ENABLE_DANDELION_PP", True)
    monkeypatch.setattr(CFG, "MIN_PEERS_FOR_DANDELION", 0)

    host = _HostStub(send_ok=True)
    dpp = DandelionPP(host)
    tx_id = dummy_tx.txid.hex()
    # Set exclude = all peers so there are no candidates.
    # handle_inbound_stem selects a peer excluding the specified ones, but what if there is only one peer and the origin is that peer?
    # Simpler: set up peers with a single peer, and set the origin to that peer, resulting in no candidates.
    single_peer = {("10.0.0.1", 7000)}
    handled = dpp.handle_inbound_stem(dummy_tx, tx_id, single_peer, origin=("10.0.0.1", 7000))
    assert handled is True
    # No stem send; straight to fluff.
    assert len(host.send_calls) == 0
    assert host.fluff_calls and host.fluff_calls[0][0] == tx_id


def test_fluff_manual_cancels_timer(monkeypatch, dummy_tx, peers_basic):
    # Override the timer to prevent immediate execution; we need to test cancellation.
    # Should we use the original timer? It is better to patch the timer with one we can control.
    # However, in the fixture, we have already patched the Timer to execute immediately, causing the fluff to run right away.
    # To test cancellation, we need a timer that does not execute immediately.
    # We will re-patch it for this test.
    monkeypatch.setattr(CFG, "ENABLE_DANDELION_PP", True)
    monkeypatch.setattr(CFG, "MIN_PEERS_FOR_DANDELION", 0)

    # Create a cancellable timer (one that doesn't start immediately).
    from threading import Timer as RealTimer

    class _ControlledTimer:
        def __init__(self, delay, fn, *args, **kwargs):
            self.timer = RealTimer(delay, fn, *args, **kwargs)
            self.cancelled = False

        def start(self):
            self.timer.start()

        def cancel(self):
            self.cancelled = True
            self.timer.cancel()

    host = _HostStub(send_ok=True)
    dpp = DandelionPP(host)
    tx_id = dummy_tx.txid.hex()

    # Timer patch for this test
    import tsarchain.network.dandelion_pp as dpp_mod
    monkeypatch.setattr(dpp_mod.threading, "Timer", _ControlledTimer)

    # Call handle_outbound, will create a timer
    handled = dpp.handle_outbound(dummy_tx, tx_id, peers_basic)
    assert handled is True
    assert len(host.send_calls) == 1

    # Before the timer runs, call manual fluff
    dpp.fluff(dummy_tx, tx_id, peers_basic)
    assert host.fluff_calls and host.fluff_calls[0][0] == tx_id

    with dpp.lock:
        timer = dpp._timers.get(tx_id)
        if timer:
            assert timer.cancelled is True
        else:
            pass
    with dpp.lock:
        assert tx_id not in dpp._timers


def test_fluff_already_done_ignores_new_stem(monkeypatch, dummy_tx, peers_basic):
    monkeypatch.setattr(CFG, "ENABLE_DANDELION_PP", True)
    monkeypatch.setattr(CFG, "MIN_PEERS_FOR_DANDELION", 0)

    host = _HostStub(send_ok=True)
    dpp = DandelionPP(host)
    tx_id = dummy_tx.txid.hex()

    dpp.fluff(dummy_tx, tx_id, peers_basic)
    assert tx_id in dpp._fluffed

    handled = dpp.handle_inbound_stem(dummy_tx, tx_id, peers_basic)
    assert handled is True
    assert len(host.send_calls) == 0
    assert len(host.fluff_calls) == 1


def test_compute_fluff_delay(monkeypatch):
    monkeypatch.setattr(CFG, "MIN_FLUFF_DELAY_S", 1.0)
    monkeypatch.setattr(CFG, "MAX_FLUFF_DELAY_S", 5.0)
    monkeypatch.setattr(CFG, "SYNC_TIMEOUT", 2.0)

    host = _HostStub()
    dpp = DandelionPP(host)
    delays = [dpp._compute_fluff_delay() for _ in range(20)]
    for d in delays:
        assert 0.5 <= d <= 5.0
    assert len(set(delays)) > 1  # kemungkinan besar ada jitter