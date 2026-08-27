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
        if name in ('broadcast', '_in_getattr'):
            super().__setattr__(name, value)
            return
        bcast = self.__dict__.get('broadcast')
        if bcast is not None and bcast is not self and (name in bcast.__dict__ or name in bcast.__class__.__dict__):
            bcast.__dict__[name] = value
        else:
            super().__setattr__(name, value)
