# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md
# Refs: see REFERENCES.md

from __future__ import annotations

import threading
from collections import deque


def init_chat_state(self) -> None:
    self.chat_lock = threading.Lock()
    self.chat_mailboxes = {}
    self.chat_seen_ids = set()
    self.chat_seen_order = deque(maxlen=5000)
    self.chat_presence_pub = {}
    self.chat_presence_seen = set()
    self.chat_rate = {}
    self.chat_window_sec = 2.0
    self.chat_burst_max = 10
    self.chat_mailbox = {}
    self.chat_spend_pub = {}
    self.mailboxes = {}
    self.chat_global_count = 0
    self.chat_seen_mid = {}
    self.chat_seen_max = 512
    self.rl_addr = {}
    self.rl_ip = {}
    self.backoff_until = {}
    self.chat_gc_last = 0
    self.chat_prekeys = {}


__all__ = ("init_chat_state",)
