#!/usr/bin/env python3
"""Expose the loopback-only Autobahn fixture to Docker's bridge interface."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path


TARGET_HOST = "127.0.0.1"
TARGET_PORT = 18081


async def copy(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
    try:
        while data := await source.read(64 * 1024):
            destination.write(data)
            await destination.drain()
    finally:
        try:
            destination.write_eof()
        except (AttributeError, OSError):
            pass


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(
            TARGET_HOST, TARGET_PORT
        )
    except OSError:
        writer.close()
        await writer.wait_closed()
        return
    try:
        await asyncio.gather(
            copy(reader, upstream_writer), copy(upstream_reader, writer)
        )
    finally:
        upstream_writer.close()
        writer.close()
        await asyncio.gather(
            upstream_writer.wait_closed(), writer.wait_closed(), return_exceptions=True
        )


async def run(listen_address: str, ready_file: Path) -> None:
    server = await asyncio.start_server(relay, listen_address, TARGET_PORT)
    ready_file.write_text(f"{listen_address}:{TARGET_PORT}\n", encoding="utf-8")
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("listen_address")
    parser.add_argument("ready_file", type=Path)
    arguments = parser.parse_args()
    asyncio.run(run(arguments.listen_address, arguments.ready_file))


if __name__ == "__main__":
    main()
