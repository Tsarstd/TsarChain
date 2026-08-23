# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

class BroadcastHandlerProxy:
    def __init__(self, broadcast):
        self.broadcast = broadcast

    def __getattr__(self, name):
        if self.__dict__.get('_in_getattr', False):
            raise AttributeError(name)
        self._in_getattr = True
        try:
            return getattr(self.broadcast, name)
        except AttributeError:
            raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")
        finally:
            self._in_getattr = False

    def __setattr__(self, name, value):
        if name in ('broadcast', '_in_getattr') or getattr(self, 'broadcast', None) is self:
            super().__setattr__(name, value)
        else:
            bcast = getattr(self, 'broadcast', None)
            if bcast is not None and (name in getattr(bcast, '__dict__', {}) or getattr(bcast.__class__, name, None) is not None):
                setattr(bcast, name, value)
            else:
                super().__setattr__(name, value)
