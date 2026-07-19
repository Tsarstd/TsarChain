# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

class NetworkHandlerProxy:
    def __init__(self, network):
        self.network = network

    def __getattr__(self, name):
        if self.__dict__.get('_in_getattr', False):
            raise AttributeError(name)
        self._in_getattr = True
        try:
            if hasattr(self.network, name):
                return getattr(self.network, name)
        finally:
            self._in_getattr = False
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

    def __setattr__(self, name, value):
        if name in ('network', '_in_getattr') or getattr(self, 'network', None) is self:
            super().__setattr__(name, value)
        elif hasattr(self, 'network') and hasattr(self.network, name):
            setattr(self.network, name, value)
        else:
            super().__setattr__(name, value)
