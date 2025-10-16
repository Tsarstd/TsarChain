# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Seed/Bootstrap CLI for TsarChain network nodes

import signal
import time

from tsarchain.network.node import Network
from tsarchain.utils.helpers import print_banner_seeds
from tsarchain.utils import config as CFG


class SeedNode:
    def __init__(self):
        self.network: Network | None = None
        self.running = True

    def start(self):
        print_banner_seeds()
        print("Starting TsarChain seed node...")
        signal.signal(signal.SIGINT, self.stop_signal)
        signal.signal(signal.SIGTERM, self.stop_signal)

        try:
            self.network = Network()
            print(f"Seed node online on port {self.network.port}")
            print(f"Bootstrap peers: {sorted(self.network.persistent_peers)}")
            print("Press Ctrl+C to stop.")

            while self.running:
                time.sleep(2)
        except Exception as exc:
            print(f"Seed node error: {exc}")
        finally:
            self.shutdown()

    def stop_signal(self, *_args):
        print("\nStopping seed node...")
        self.running = False

    def shutdown(self):
        if self.network:
            try:
                self.network.shutdown()
            except Exception:
                pass
            self.network = None
        print("Seed node stopped.")


def main():
    if not CFG.BOOTSTRAP_NODES and not getattr(CFG, "BOOTSTRAP_NODE", None):
        print("Warning: no bootstrap peers configured.")
    seed = SeedNode()
    seed.start()


if __name__ == "__main__":
    main()
