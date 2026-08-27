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
            return getattr(self.network, name)
        except AttributeError:
            raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")
        finally:
            self._in_getattr = False

    def __setattr__(self, name, value):
        if name in ('network', '_in_getattr'):
            super().__setattr__(name, value)
            return
        net = self.__dict__.get('network')
        if net is not None and net is not self and (name in net.__dict__ or name in net.__class__.__dict__):
            net.__dict__[name] = value
        else:
            super().__setattr__(name, value)
