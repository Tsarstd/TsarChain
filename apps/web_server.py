# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

"""
TsarChain — Web Explorer API Backend Server

Role
- Multi-threaded HTTP server powering the TsarChain Web Explorer.
- Serves blocks, transactions, UTXO addresses, receipts, and history books.
- Handles on-demand streaming and caching for Graffiti cultural artifacts.

Intended environment
- Node host or dedicated explorer API service.

Key flags
--host          : Host interface to bind on (default: 0.0.0.0).
--port          : Port to listen on (default: 4000).
--node-host     : TsarChain node RPC host (default: 127.0.0.1).
--node-port     : TsarChain node RPC port (default: 38169).
"""

from __future__ import annotations

import argparse
from http.server import ThreadingHTTPServer
from typing import Optional

from tsarchain.utils import config as CFG
from tsarchain.utils.tsar_logging import get_ctx_logger, setup_logging
from web.Backend.src.server import create_handler_class
from web.Backend.src.services.explorer_service import ExplorerService
from web.Backend.src.routes.explorer_routes import ExplorerRoutes

log = get_ctx_logger("apps.web_server")


def run_server(
    host: Optional[str] = None,
    port: Optional[int] = None,
    node_host: Optional[str] = None,
    node_port: Optional[int] = None,
) -> None:
    server_host = host or CFG.WEB_SERVER_HOST
    server_port = port or CFG.WEB_SERVER_PORT
    target_node_host = node_host or CFG.WEB_NODE_HOST
    target_node_port = node_port or CFG.WEB_NODE_PORT

    svc = ExplorerService(node_host=target_node_host, node_port=target_node_port)
    routes = ExplorerRoutes(service=svc, host=target_node_host, port=target_node_port)
    handler_cls = create_handler_class(routes=routes)

    try:
        httpd = ThreadingHTTPServer((server_host, server_port), handler_cls)
        log.info("[backend] TsarChain explorer API listening on %s:%s", server_host, server_port)
        print(f"[backend] TsarChain explorer API listening on {server_host}:{server_port}")
    except OSError as err:
        if server_host != "0.0.0.0":
            log.warning("[backend] Binding to %s failed (%s), retrying on 0.0.0.0:%s", server_host, err, server_port)
            httpd = ThreadingHTTPServer(("0.0.0.0", server_port), handler_cls)
            print(f"[backend] TsarChain explorer API listening on 0.0.0.0:{server_port}")
        else:
            raise

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log.info("[backend] Shutting down explorer API server...")
    finally:
        httpd.server_close()


def main() -> None:
    setup_logging("logging/web.log", force=True)

    parser = argparse.ArgumentParser(description="TsarChain Web Explorer Backend Server")
    parser.add_argument("--host", type=str, default=CFG.WEB_SERVER_HOST, help="Host interface to bind on (default: %(default)s)")
    parser.add_argument("--port", type=int, default=CFG.WEB_SERVER_PORT, help="Port to listen on (default: %(default)s)")
    parser.add_argument("--node-host", type=str, default=CFG.WEB_NODE_HOST, help="TsarChain node RPC host (default: %(default)s)")
    parser.add_argument("--node-port", type=int, default=CFG.WEB_NODE_PORT, help="TsarChain node RPC port (default: %(default)s)")

    args = parser.parse_args()

    log.info(
        "[web_server] Starting Explorer API on %s:%s (Node: %s:%s)",
        args.host,
        args.port,
        args.node_host,
        args.node_port,
    )
    run_server(
        host=args.host,
        port=args.port,
        node_host=args.node_host,
        node_port=args.node_port,
    )


if __name__ == "__main__":
    main()
