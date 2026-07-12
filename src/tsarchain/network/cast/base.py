# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE and TRADEMARKS.md

class BroadcastHandlerProxy:
    def __init__(self, broadcast):
        self.broadcast = broadcast

    def __getattr__(self, name):
        if self.__dict__.get('_in_getattr', False):
            raise AttributeError(name)
        self._in_getattr = True
        try:
            if hasattr(self.broadcast, name):
                return getattr(self.broadcast, name)
        finally:
            self._in_getattr = False
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

    def __setattr__(self, name, value):
        if name in ('broadcast', '_in_getattr') or getattr(self, 'broadcast', None) is self:
            super().__setattr__(name, value)
        elif hasattr(self, 'broadcast') and hasattr(self.broadcast, name):
            setattr(self.broadcast, name, value)
        else:
            super().__setattr__(name, value)
