# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE

import time
import threading
import pytest

from tsarchain.utils.thread_check import (
    ThreadMonitor,
    ThreadInfo,
    ThreadState,
    get_thread_monitor,
    start_thread_monitoring,
    stop_thread_monitoring,
)


def test_thread_info_dataclass():
    info = ThreadInfo(
        name="TestThread",
        ident=12345,
        daemon=True,
        alive=True,
        is_current=False,
        state="running",
    )
    assert info.name == "TestThread"
    assert info.ident == 12345
    assert info.daemon is True
    assert info.alive is True
    assert info.is_current is False
    assert info.state == "running"


def test_get_all_threads_fast_and_detailed():
    monitor = ThreadMonitor()
    threads_fast = monitor.get_all_threads(include_stack=False)
    assert len(threads_fast) > 0
    assert any(t.is_current for t in threads_fast)
    assert all(t.stack_info is None for t in threads_fast)

    threads_detailed = monitor.get_all_threads(include_stack=True)
    assert len(threads_detailed) > 0
    current = next(t for t in threads_detailed if t.is_current)
    assert current.stack_info is not None
    assert "thread_check_test.py" in current.stack_info or "pytest" in current.stack_info or "in" in current.stack_info


def test_get_thread_counts():
    monitor = ThreadMonitor()
    counts = monitor.get_thread_counts()

    assert "total" in counts
    assert "alive" in counts
    assert "daemon" in counts
    assert "user" in counts
    assert "mining" in counts
    assert "network" in counts
    assert "sync" in counts
    assert "rpc" in counts
    assert "archivist" in counts

    assert counts["total"] >= 1
    assert counts["alive"] >= 1


def test_thread_counts_archivist_recognition():
    dummy_stop = threading.Event()
    arch_thread = threading.Thread(
        target=dummy_stop.wait,
        name="ArchivistRetentionThread",
        daemon=True,
    )
    arch_thread.start()

    try:
        monitor = ThreadMonitor()
        counts = monitor.get_thread_counts()
        assert counts["archivist"] >= 1
    finally:
        dummy_stop.set()
        arch_thread.join(timeout=1.0)


def test_thread_monitoring_lifecycle():
    monitor = ThreadMonitor(update_interval=0.1)
    assert not monitor.monitoring

    monitor.start_monitoring()
    assert monitor.monitoring
    assert monitor._monitor_thread is not None
    assert monitor._monitor_thread.is_alive()

    time.sleep(0.3)
    assert monitor.last_update > 0

    monitor.stop_monitoring()
    assert not monitor.monitoring


def test_check_for_deadlocks_warning():
    monitor = ThreadMonitor()
    warnings = monitor.check_for_deadlocks()
    assert isinstance(warnings, list)


def test_print_thread_report(capsys):
    monitor = ThreadMonitor()
    monitor.print_thread_report(detailed=True)
    out, err = capsys.readouterr()
    assert "Thread Health Report" in out or len(out) >= 0


def test_global_thread_monitor_helpers():
    m1 = get_thread_monitor()
    m2 = get_thread_monitor()
    assert m1 is m2

    start_thread_monitoring()
    assert m1.monitoring

    stop_thread_monitoring()
    assert not m1.monitoring
