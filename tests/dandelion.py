# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE and TRADEMARKS.md

from typing import List, Tuple

import pytest

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

    def _broadcast_tx_fluff(self, tx, tx_id: str, peers: set, exclude=None):
        self.fluff_calls.append((tx_id, peers))
        # mirror GossipMixin return (count of attempted peers)
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

    # Only override Timer; keep threading.RLock intact.
    monkeypatch.setattr(dpp.threading, "Timer", _ImmediateTimer)
    yield


def test_outbound_stem_then_fluff(monkeypatch):
    monkeypatch.setattr(CFG, "ENABLE_DANDELION_PP", True)
    monkeypatch.setattr(CFG, "MIN_PEERS_FOR_DANDELION", 0)

    host = _HostStub(send_ok=True)
    dpp = DandelionPP(host)
    peers = {("127.0.0.1", 9000)}
    tx = _DummyTx("01" * 32)
    tx_id = tx.txid.hex()

    handled = dpp.handle_outbound(tx, tx_id, peers)
    assert handled is True
    assert len(host.send_calls) == 1
    peer, msg = host.send_calls[0]
    assert peer in peers
    assert msg.get("phase") == "stem"
    # scheduled fluff executed immediately by patched timer
    assert host.fluff_calls and host.fluff_calls[0][0] == tx_id


def test_inbound_stem_dedup_and_fallback_to_fluff(monkeypatch):
    monkeypatch.setattr(CFG, "ENABLE_DANDELION_PP", True)
    monkeypatch.setattr(CFG, "MIN_PEERS_FOR_DANDELION", 0)

    # make stem forwarding fail so we hit fluff immediately
    host = _HostStub(send_ok=False)
    dpp = DandelionPP(host)
    peers = {("10.0.0.1", 8001), ("10.0.0.2", 8002)}
    tx = _DummyTx("02" * 32)
    tx_id = tx.txid.hex()

    handled = dpp.handle_inbound_stem(tx, tx_id, peers, origin=("10.0.0.1", 8001))
    assert handled is True
    # stem send attempted once and failed
    assert len(host.send_calls) == 1
    # should have fluffed because stem failed
    assert host.fluff_calls and host.fluff_calls[0][0] == tx_id

    # second time same tx should be dropped (dedup)
    handled_again = dpp.handle_inbound_stem(tx, tx_id, peers, origin=None)
    assert handled_again is True
    # no additional send or fluff beyond first attempt
    assert len(host.send_calls) == 1
    assert len(host.fluff_calls) == 1
