#!/usr/bin/env python3
"""Wait for the fixed loopback conformance fixture ports."""

from __future__ import annotations

import socket
import sys
import time


def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} PORT [PORT ...]", file=sys.stderr)
        return 64

    ports = [int(value) for value in sys.argv[1:]]
    deadline = time.monotonic() + 15.0
    for port in ports:
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    print(f"fixture port {port} did not become ready", file=sys.stderr)
                    return 1
                time.sleep(0.05)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
