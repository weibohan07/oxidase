#!/usr/bin/env python3
"""Bounded, isolated Linux allocation-stack experiment, NOT H/C qualification.

Only gateways spawned by this helper may be profiled or signalled. Heaptrack
records allocation metadata and call stacks, not allocation contents. Nothing
here changes Oxidase, its default allocator, Yama, or the normal-release runner.
Never pass real credentials/configuration: this program generates public fixture
data only. Attach is an explicitly unstable upstream experiment, not a fallback
that silently substitutes for launch (or vice versa).
"""

import argparse
import concurrent.futures
import gzip
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import resource
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request


SCHEMA = "oxidase.allocation-attribution/v1"
VERSION = "1.5.0"
ARCHIVE_URL = "https://download.kde.org/stable/heaptrack/1.5.0/heaptrack-1.5.0.tar.xz"
# Actually retrieved from KDE's .sha256 file and independently hashed locally.
ARCHIVE_SHA256 = "a278d9d8f91e8bfb8a1c2f5b73eecab47fd45d0693f5dbea637536413cec2ea5"
PRIMARY = {
    "checksum": ARCHIVE_URL + ".sha256",
    "readme": "https://raw.githubusercontent.com/KDE/heaptrack/v1.5.0/README.md",
    "wrapper": "https://raw.githubusercontent.com/KDE/heaptrack/v1.5.0/src/track/heaptrack.sh.cmake",
    "collector": "https://raw.githubusercontent.com/KDE/heaptrack/v1.5.0/src/track/libheaptrack.cpp",
    "parser": "https://raw.githubusercontent.com/KDE/heaptrack/v1.5.0/src/analyze/print/heaptrack_print.cpp",
    "build": "https://raw.githubusercontent.com/KDE/heaptrack/v1.5.0/CMakeLists.txt",
    "yama": "https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html",
}
PACKAGES = ("build-essential", "cmake", "gdb", "libboost-dev", "libboost-system-dev",
            "libboost-filesystem-dev", "libboost-iostreams-dev", "libboost-program-options-dev", "libboost-container-dev",
            "libunwind-dev", "libdw-dev", "zlib1g-dev")
BUILD_FLAGS = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_PROFILE_RELEASE_DEBUG",
               "CARGO_TARGET_DIR")
MAX_TRACE = 64 * 1024 * 1024
MAX_DECODED = 512 * 1024 * 1024
MAX_LOG = 4 * 1024 * 1024
# Existing production default, not a limit added/increased by this experiment.
MAX_CONNECTION_REQUESTS = 1000
FORBIDDEN = (b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN RSA PRIVATE KEY-----",
             b"-----BEGIN EC PRIVATE KEY-----", b"resource-qualification-test-admin-token",
             b"discovery-soak-test-only-admin-token", b"Bearer ")
STOP = threading.Event()


class Unavailable(Exception):
    """A missing/failed measurement, never a fabricated numerical result."""


class SamplerCapture:
    """Sampler-local bounded data, never a mutable reference to final receipt."""
    def __init__(self):
        self.lock = threading.Lock()
        self.samples, self.errors = [], []
        self.closed = False
    def append(self, sample):
        with self.lock:
            if self.closed:
                return
            if len(self.samples) >= 2048:
                raise Unavailable("sampler capture capacity")
            self.samples.append(sample)
    def fail(self, error):
        with self.lock:
            if not self.closed and not self.errors:
                self.errors.append(error)
    def freeze(self):
        with self.lock:
            self.closed = True
            return list(self.samples), list(self.errors)


def settle_sampler(sampler, stop, capture, report, *, require=False):
    stop.set()
    if sampler:
        sampler.join(timeout=3)
    joined = sampler is None or not sampler.is_alive()
    samples, failures = capture.freeze()
    report["samples"] = samples
    report["cleanup"]["sampler_joined"] = joined
    if not joined or failures:
        report["result"] = "INCONCLUSIVE"
        report["error"] = failures[0] if failures else "sampler did not acknowledge exit"
        if require:
            raise Unavailable(report["error"])
    return joined


def now():
    return time.monotonic_ns()


def sha256(path, maximum=1024 * 1024 * 1024):
    metadata = path.stat()
    if not path.is_file() or metadata.st_size > maximum:
        raise Unavailable("file shape/size prevents bounded identity hash")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(65536), b""):
            digest.update(data)
    after = path.stat()
    if (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise Unavailable("binary changed while hashing")
    return digest.hexdigest()


def json_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def clean_environment():
    # Do not propagate workflow credentials, allocator tuning or user preload.
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8", "RUST_LOG": "warn", "DEBUGINFOD_URLS": ""}


def text_command(argv, timeout=10, maximum=65536):
    with tempfile.TemporaryFile() as capture:
        process = subprocess.Popen(argv, stdout=capture, stderr=subprocess.STDOUT,
                                   env=clean_environment(), start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise Unavailable("dependency command timed out") from None
        capture.seek(0)
        data = capture.read(maximum + 1)
        if len(data) > maximum or code:
            raise Unavailable("dependency command failed or exceeded output bound")
        return data.decode("utf-8", errors="strict").strip()


def parse_stat(text):
    left, right = text.find("("), text.rfind(")")
    if left < 1 or right <= left:
        raise Unavailable("invalid /proc stat comm")
    rest = text[right + 2:].split()
    if len(rest) < 20:
        raise Unavailable("truncated /proc stat")
    return {"pid": int(text[:left].strip()), "state": rest[0], "ppid": int(rest[1]),
            "start_ticks": int(rest[19])}


def identity(pid, binary=None, proc=Path("/proc")):
    root = proc / str(pid)
    before = parse_stat((root / "stat").read_text())
    boot = (proc / "sys/kernel/random/boot_id").read_text().strip()
    executable = root / "exe"
    stat = executable.stat()
    digest = sha256(executable)
    after = parse_stat((root / "stat").read_text())
    if before["pid"] != pid or before["start_ticks"] != after["start_ticks"]:
        raise Unavailable("PID reused during identity capture")
    if binary is not None and digest != sha256(binary):
        raise Unavailable("gateway executable differs from expected binary")
    return {"pid": pid, "start_ticks": before["start_ticks"], "boot_id": boot,
            "exe_sha256": digest, "dev": stat.st_dev, "ino": stat.st_ino,
            "bytes": stat.st_size, "mtime_ns": stat.st_mtime_ns}


def verify_process(record, proc=Path("/proc")):
    root = proc / str(record["pid"])
    current = parse_stat((root / "stat").read_text())
    stat = (root / "exe").stat()
    if (current["pid"] != record["pid"] or current["start_ticks"] != record["start_ticks"]
            or current["state"] == "Z"
            or (proc / "sys/kernel/random/boot_id").read_text().strip() != record["boot_id"]
            or (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns) != (
                record["dev"], record["ino"], record["bytes"], record["mtime_ns"])):
        raise Unavailable("gateway identity lost or PID reused")


def safe_signal(record, sig):
    # PIDFD anchors the signal to one actual process, closing reuse between
    # verification and kill. Never fall back to signalling an arbitrary PID.
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise Unavailable("PIDFD signalling unavailable")
    handle = os.pidfd_open(record["pid"])
    try:
        verify_process(record)
        signal.pidfd_send_signal(handle, sig)
    finally:
        os.close(handle)


def owned_gateway(parent, binary, deadline, proc=Path("/proc")):
    """Find exactly one matching descendant, never global pidof/process-name."""
    expected = binary.stat()
    while now() < deadline:
        if parent.poll() is not None:
            raise Unavailable("profiler exited before gateway identity")
        rows = {}
        for directory in proc.iterdir():
            if not directory.name.isdigit():
                continue
            try:
                rows[int(directory.name)] = parse_stat((directory / "stat").read_text())
            except (OSError, ValueError, Unavailable):
                continue
        def descendant(pid):
            seen = set()
            while pid in rows and pid not in seen:
                seen.add(pid)
                if rows[pid]["ppid"] == parent.pid:
                    return True
                pid = rows[pid]["ppid"]
            return False
        matching = []
        for pid in rows:
            if not descendant(pid):
                continue
            try:
                stat = (proc / str(pid) / "exe").stat()
                if (stat.st_dev, stat.st_ino) == (expected.st_dev, expected.st_ino):
                    matching.append(pid)
            except OSError:
                continue
        if len(matching) > 1:
            raise Unavailable("more than one gateway in owned profiler subtree")
        if matching:
            candidate = matching[0]
            record = identity(candidate, binary, proc)
            if record["start_ticks"] != rows[candidate]["start_ticks"]:
                raise Unavailable("descendant PID reused after ancestry snapshot")
            # Re-read the complete chain, not just the executable. Same-binary
            # PID reuse must not turn a host process into an owned descendant.
            cursor, seen = candidate, set()
            while cursor != parent.pid:
                if cursor in seen or cursor not in rows:
                    raise Unavailable("owned ancestry changed during identity capture")
                seen.add(cursor)
                current = parse_stat((proc / str(cursor) / "stat").read_text())
                if (current["start_ticks"], current["ppid"]) != (
                        rows[cursor]["start_ticks"], rows[cursor]["ppid"]):
                    raise Unavailable("owned ancestry changed during identity capture")
                cursor = current["ppid"]
            if parent.poll() is not None:
                raise Unavailable("owned profiler retired during identity capture")
            verify_process(record, proc)
            return record
        time.sleep(0.05)
    raise Unavailable("owned gateway identity deadline")


def sample_process(record):
    verify_process(record)
    root = Path("/proc") / str(record["pid"])
    result = {"t_ns": now(), "pid": record["pid"], "start_ticks": record["start_ticks"],
              "rss_kib": None, "pss_kib": None, "private_dirty_kib": None,
              "open_fds": None, "threads": None, "errors": []}
    for file, fields in (("status", {"VmRSS": "rss_kib", "Threads": "threads"}),
                         ("smaps_rollup", {"Pss": "pss_kib", "Private_Dirty": "private_dirty_kib"})):
        try:
            for line in (root / file).read_text().splitlines():
                key, _, value = line.partition(":")
                if key in fields:
                    result[fields[key]] = int(value.split()[0])
        except (OSError, ValueError):
            result["errors"].append(file + ":unavailable")
    try:
        result["open_fds"] = sum(1 for _ in (root / "fd").iterdir())
    except OSError:
        result["errors"].append("fd:unavailable")
    verify_process(record)
    return result


def collector_mapping(record, prefix, mode):
    verify_process(record)
    library = (prefix / "lib/heaptrack" / ("libheaptrack_preload.so" if mode == "launch"
                                          else "libheaptrack_inject.so")).resolve(strict=True)
    metadata = library.stat()
    rows = []
    for line in (Path("/proc") / str(record["pid"]) / "maps").read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 6 or not fields[4].isdigit():
            continue
        major, minor = (int(value, 16) for value in fields[3].split(":"))
        if (int(fields[4]), major, minor) == (metadata.st_ino, os.major(metadata.st_dev), os.minor(metadata.st_dev)):
            rows.append(line.replace(str(prefix), "<verified-profiler>"))
    verify_process(record)
    if not rows or len(rows) > 32:
        raise Unavailable("verified collector library mapping was not established")
    return {"library": str(library.relative_to(prefix)), "library_sha256": sha256(library),
            "actual_matching_maps": rows}


def extract_source(archive, destination):
    if sha256(archive, 16 * 1024 * 1024) != ARCHIVE_SHA256:
        raise Unavailable("heaptrack source checksum mismatch")
    with tarfile.open(archive, "r:xz") as source:
        members, total = source.getmembers(), 0
        if len(members) > 10000:
            raise Unavailable("source archive entry bound")
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or not path.parts
                    or path.parts[0] != "heaptrack-1.5.0" or len(path.parts) > 32
                    or not (member.isfile() or member.isdir())):
                raise Unavailable("unsafe source archive entry")
            total += member.size
            if total > 128 * 1024 * 1024:
                raise Unavailable("source archive expanded size bound")
        source.extractall(destination, members=members, filter="data")


def guarded_command(argv, log, timeout, maximum=MAX_LOG):
    """Bounded command, no shell and no ignored exit/timeout/output-cap."""
    with log.open("wb") as stream:
        process = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT,
                                   env=clean_environment(), start_new_session=True)
        deadline = now() + int(timeout * 1e9)
        cause = None
        while process.poll() is None:
            if log.stat().st_size > maximum:
                cause = "command output capacity exhausted"
                break
            if now() >= deadline:
                cause = "command deadline exceeded"
                break
            time.sleep(0.1)
        if cause:
            # Parent is owned and unreaped. Its private process group contains
            # only this command's descendants (compiler/interpreter), no gateway.
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            raise Unavailable(cause)
        if process.returncode or log.stat().st_size > maximum:
            raise Unavailable("command failed or final output exceeded capacity")


def tool_inventory(prefix):
    binaries = [prefix / "bin/heaptrack", prefix / "bin/heaptrack_print",
                prefix / "lib/heaptrack/libheaptrack_preload.so",
                prefix / "lib/heaptrack/libheaptrack_inject.so",
                prefix / "lib/heaptrack/libexec/heaptrack_interpret",
                prefix / "lib/heaptrack/libexec/heaptrack_env"]
    result = {"version": text_command([str(binaries[0]), "--version"]), "binaries": []}
    if result["version"] != "heaptrack " + VERSION:
        raise Unavailable("heaptrack version differs from pinned collector")
    if text_command([str(binaries[1]), "--version"]) != "heaptrack_print " + VERSION:
        raise Unavailable("heaptrack_print version differs from pinned parser")
    for file in binaries:
        result["binaries"].append({"path": str(file.relative_to(prefix)),
                                   "bytes": file.stat().st_size, "sha256": sha256(file)})
    result["linked_dependencies"] = {
        str(file.relative_to(prefix)): text_command(["ldd", str(file)])
        for file in (binaries[1], binaries[2], binaries[4])}
    result["linked_files"] = linked_file_evidence(result["linked_dependencies"])
    result["packages"] = []
    for package in PACKAGES:
        entry = {"package": package, "version": None, "copyright_sha256": None,
                 "license_fields": None}
        try:
            entry["version"] = text_command(["dpkg-query", "-W", "-f=${Version}", package])
            copyright_file = Path("/usr/share/doc") / package / "copyright"
            text = copyright_file.read_text()
            if len(text.encode()) > 1024 * 1024:
                raise Unavailable("dependency copyright capacity")
            entry["copyright_sha256"] = sha256(copyright_file, 1024 * 1024)
            entry["license_fields"] = sorted(set(re.findall(r"^License: (.+)$", text, re.M)))
        except (OSError, ValueError, Unavailable):
            entry["error"] = "primary package copyright/version unavailable"
        result["packages"].append(entry)
    return result


def linked_file_evidence(dependencies):
    paths = set()
    for text in dependencies.values():
        for line in text.splitlines():
            match = re.fullmatch(r"\s*(?:\S+\s+=>\s*)?(/\S+)\s+\(0x[0-9a-fA-F]+\)\s*", line)
            if match:
                paths.add(match[1])
            elif not re.fullmatch(r"\s*linux-vdso\.so\.\d+\s+\(0x[0-9a-fA-F]+\)\s*", line):
                raise Unavailable("unexpected/unresolved linked dependency record")
    if not paths or len(paths) > 64:
        raise Unavailable("linked dependency file capacity/identity unavailable")
    result = []
    for original in sorted(paths):
        file = Path(original).resolve(strict=True)
        entry = {"ldd_path": original, "canonical_path": str(file), "sha256": sha256(file),
                 "bytes": file.stat().st_size, "package": None, "package_version": None,
                 "copyright_sha256": None, "license_fields": None}
        try:
            ownership = text_command(["dpkg-query", "-S", original])
            owners = [row.partition(": ")[0] for row in ownership.splitlines()
                      if row.partition(": ")[2] == original]
            if len(owners) != 1 or not re.fullmatch(r"[a-z0-9.+-]+(?::[a-z0-9-]+)?", owners[0]):
                raise Unavailable("unambiguous library package owner unavailable")
            package = owners[0]
            entry["package"] = package
            entry["package_version"] = text_command(["dpkg-query", "-W", "-f=${Version}", package])
            copyright_file = Path("/usr/share/doc") / package.split(":")[0] / "copyright"
            entry["copyright_sha256"] = sha256(copyright_file, 1024 * 1024)
            entry["license_fields"] = sorted(set(re.findall(r"^License: (.+)$", copyright_file.read_text(), re.M)))
        except (OSError, ValueError, Unavailable):
            entry["license_error"] = "primary linked-library package copyright/version unavailable"
        result.append(entry)
    return result


def stable_profiler_inventory(inventory):
    """Ignore only ldd's mapped addresses; keep raw reports, paths and hashes."""
    if not isinstance(inventory, dict) or not isinstance(inventory.get("linked_dependencies"), dict):
        raise Unavailable("profiler inventory dependency schema unavailable")
    if any(not isinstance(name, str) or not isinstance(text, str)
           for name, text in inventory["linked_dependencies"].items()):
        raise Unavailable("profiler inventory dependency fields invalid")
    result = dict(inventory)
    pattern = re.compile(r"^[ \t]*(?:linux-vdso\.so\.\d+|/\S+|\S+[ \t]+=>[ \t]+/\S+)"
                         r"[ \t]+\((?P<address>0x[0-9a-fA-F]+)\)[ \t]*$")
    def stable(text):
        lines = []
        for line in text.splitlines(keepends=True):
            match = pattern.match(line.rstrip("\r\n"))
            if match:
                start, end = match.span("address")
                line = line[:start] + "<mapped-address>" + line[end:]
            lines.append(line)
        return "".join(lines)
    result["linked_dependencies"] = {name: stable(text) for name, text in inventory["linked_dependencies"].items()}
    return result


def prepare(prefix, output):
    report = {"schema_version": SCHEMA, "operation": "prepare_profiler", "result": "INCONCLUSIVE",
              "primary_sources": PRIMARY, "archive_sha256": ARCHIVE_SHA256, "tool_version": VERSION}
    try:
        if sys.platform != "linux":
            raise Unavailable("collector experiment requires Linux")
        if prefix.exists():
            raise Unavailable("profiler install prefix must be fresh")
        report["build_tools"] = {name: text_command([name, "--version"])
                                 for name in ("cmake", "g++", "gdb")}
        with tempfile.TemporaryDirectory(prefix="oxidase-heaptrack-source-") as temporary:
            root = Path(temporary)
            archive = root / "source.tar.xz"
            with urllib.request.urlopen(ARCHIVE_URL, timeout=30) as remote, archive.open("wb") as file:
                digest, size = hashlib.sha256(), 0
                download_deadline = now() + 120_000_000_000
                for data in iter(lambda: remote.read(65536), b""):
                    if now() >= download_deadline or STOP.is_set():
                        raise Unavailable("source download deadline/cancellation")
                    size += len(data)
                    if size > 16 * 1024 * 1024:
                        raise Unavailable("source download capacity exhausted")
                    file.write(data)
                    digest.update(data)
            if digest.hexdigest() != ARCHIVE_SHA256:
                raise Unavailable("downloaded source differs from pinned KDE checksum")
            extract_source(archive, root)
            source = root / "heaptrack-1.5.0"
            files = ("src/track/heaptrack.sh.cmake", "src/track/libheaptrack.cpp",
                     "src/track/heaptrack_preload.cpp", "src/track/heaptrack_inject.cpp",
                     "src/analyze/print/heaptrack_print.cpp")
            report["source_license_evidence"] = []
            for name in files:
                text = (source / name).read_text()
                if "SPDX-License-Identifier: LGPL-2.1-or-later" not in text[:1024]:
                    raise Unavailable("pinned component SPDX license could not be verified")
                report["source_license_evidence"].append(
                    {"path": name, "license": "LGPL-2.1-or-later", "sha256": sha256(source / name)})
            report["bundled_license_files"] = [{"path": file.name, "sha256": sha256(file)}
                                               for file in sorted((source / "LICENSES").iterdir())]
            args = ["cmake", "-S", str(source), "-B", str(root / "build"),
                    "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_INSTALL_PREFIX=" + str(prefix),
                    "-DHEAPTRACK_BUILD_GUI=OFF", "-DHEAPTRACK_BUILD_PRINT=ON",
                    "-DHEAPTRACK_BUILD_TRACK=ON", "-DHEAPTRACK_BUILD_INTERPRET=ON",
                    "-DCMAKE_DISABLE_FIND_PACKAGE_ZSTD=TRUE"]
            report["build_arguments"] = [item.replace(str(root), "<profiler-build>") for item in args]
            guarded_command(args, output / "profiler-configure.log", 120)
            guarded_command(["cmake", "--build", str(root / "build"), "--parallel", "2"],
                            output / "profiler-build.log", 600, 16 * 1024 * 1024)
            guarded_command(["cmake", "--install", str(root / "build")],
                            output / "profiler-install.log", 60)
        report["inventory"] = tool_inventory(prefix)
        report["result"] = "AVAILABLE"
    except (OSError, ValueError, Unavailable, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    json_write(output / "tool-preflight.json", report)
    return 0 if report["result"] == "AVAILABLE" else 2


class Fixture(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    payload = b""
    def do_GET(self):
        self.send_response(200 if self.path == "/proxy" else 404)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(self.payload)))
        self.end_headers()
        try:
            self.wfile.write(self.payload)
        except (BrokenPipeError, ConnectionResetError):
            pass
    def log_message(self, *_args):
        pass


def config_text(upstream):
    return f"""api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    fixture:
      protocol: http1
      endpoints:
        - http://127.0.0.1:{upstream}
  sites:
    files:
      root: assets
services:
  public:
    type: observe
    name: allocation-fixture
    service:
      type: route
      cases:
        - when:
            path: /proxy
          service:
            type: proxy
            cluster: fixture
      default:
        type: site
        site: files
listeners:
  - name: allocation
    bind: 127.0.0.1:0
    protocol: http
    service:
      ref: public
"""


def listen_address(log, process, deadline):
    while now() < deadline:
        if process.poll() is not None:
            raise Unavailable("gateway/profiler exited before listener readiness")
        if log.stat().st_size > MAX_LOG:
            raise Unavailable("gateway startup log capacity exhausted")
        text = log.read_text(errors="replace")
        matches = re.findall(r"listener allocation accepting HTTP/1\.1 on (127\.0\.0\.1):(\d+)", text)
        if len(matches) == 1:
            return matches[0][0], int(matches[0][1])
        time.sleep(0.1)
    raise Unavailable("gateway readiness deadline")


def load(address, payload, duration, concurrency):
    expected = hashlib.sha256(payload).hexdigest()
    until = now() + int(duration * 1e9)
    def worker(index):
        offered, completed, errors, total_duration = 0, 0, [], 0
        client, connection_requests = None, 0
        connects_started, connects_completed, connects_failed, closes = 0, 0, 0, 0
        def close():
            nonlocal client, closes, connection_requests
            if client is not None:
                client.close()
                closes += 1
                client = None
                connection_requests = 0
        try:
            while now() < until and len(errors) < 16 and not STOP.is_set():
                offered += 1
                started = now()
                deadline = started + 5_000_000_000
                response_socket = None
                def remaining():
                    interval = (deadline - now()) / 1e9
                    if interval <= 0:
                        raise Unavailable("absolute full response deadline exceeded")
                    socket = client.sock if client is not None and client.sock is not None else response_socket
                    if socket is not None:
                        socket.settimeout(interval)
                    return interval
                path = "/proxy" if (offered + index) % 2 else "/asset.bin"
                try:
                    if client is None:
                        client = http.client.HTTPConnection(*address, timeout=remaining())
                        connects_started += 1
                        try:
                            client.connect()
                            connects_completed += 1
                        except (OSError, http.client.HTTPException):
                            connects_failed += 1
                            raise
                    connection_requests += 1
                    remaining()
                    client.request("GET", path)
                    remaining()
                    response_socket = client.sock
                    response = client.getresponse()
                    remaining()
                    digest, count = hashlib.sha256(), 0
                    while True:
                        remaining()
                        data = response.read(65536)
                        remaining()
                        if not data:
                            break
                        count += len(data)
                        if count > len(payload):
                            raise Unavailable("response exceeded declared fixture size")
                        digest.update(data)
                    if response.status != 200 or count != len(payload) or digest.hexdigest() != expected:
                        raise Unavailable("response status/full-body oracle mismatch")
                    if response.getheader("Content-Type") != "application/octet-stream":
                        raise Unavailable("response metadata oracle mismatch")
                    if (response.getheader("Content-Length") != str(len(payload))
                            or response.getheader("Transfer-Encoding") is not None
                            or response.getheader("Trailer") is not None):
                        raise Unavailable("fixture framing metadata mismatch (no trailers fixture)")
                    completed += 1
                    # An entirely new operation may use a new connection. Never
                    # reuse sender 1001, retry a failed logical request, or change
                    # the gateway's configured request budget to hide retirement.
                    if response.will_close or connection_requests >= MAX_CONNECTION_REQUESTS:
                        close()
                except (OSError, http.client.HTTPException, Unavailable) as error:
                    errors.append({"operation": offered, "path": path, "error_type": type(error).__name__})
                    close()
                total_duration += now() - started
        finally:
            close()
        return {"worker": index, "offered": offered, "completed": completed,
                "failed": len(errors), "errors": errors, "duration_ns_sum": total_duration,
                "connections": {"started": connects_started, "connected": connects_completed,
                                "failed": connects_failed, "closed": closes}}
    started = now()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as workers:
        results = list(workers.map(worker, range(concurrency)))
    result = {"start_ns": started, "end_ns": now(), "workers": results}
    if any(row["offered"] != row["completed"] + row["failed"] for row in results):
        raise Unavailable("workload started/terminal accounting mismatch")
    if any(row["connections"]["started"] != row["connections"]["connected"] + row["connections"]["failed"]
           or row["connections"]["closed"] != row["connections"]["started"] for row in results):
        raise Unavailable("workload connection terminal accounting mismatch")
    return result


def scan_stream(stream, maximum, markers=FORBIDDEN):
    total, tail = 0, b""
    overlap = max(map(len, markers)) - 1
    for chunk in iter(lambda: stream.read(65536), b""):
        total += len(chunk)
        if total > maximum:
            raise Unavailable("trace expanded size exceeded declared bound")
        combined = tail + chunk
        if any(marker in combined for marker in markers):
            raise Unavailable("sensitive marker detected; evidence upload refused")
        tail = combined[-overlap:]
    return total


def safe_trace(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_TRACE:
        raise Unavailable("raw trace shape/size invalid")
    with gzip.open(path, "rb") as stream:
        decoded = scan_stream(stream, MAX_DECODED)
    if decoded == 0:
        raise Unavailable("empty collector trace")
    return {"bytes": path.stat().st_size, "decoded_bytes": decoded, "sha256": sha256(path, MAX_TRACE)}


def parse_profile(text):
    # Preserve exact output, including units, instead of inventing byte precision.
    fields = {}
    for name, pattern in {
        "runtime": r"^total runtime: (.+)$",
        "allocations": r"^calls to allocation functions: (\d+).*$",
        "peak_heap": r"^peak heap memory consumption: (.+)$",
        "peak_rss": r"^peak RSS .*?: (.+)$",
        "unfreed_at_end": r"^total memory leaked: (.+)$",
    }.items():
        match = re.search(pattern, text, re.M)
        fields[name] = match[1] if match else None
    if any(value is None for value in fields.values()) or int(fields["allocations"]) == 0:
        raise Unavailable("heaptrack_print summary could not be parsed")
    fields["unfreed_is_not_a_proven_leak"] = True
    return fields


def run(args):
    report = {"schema_version": SCHEMA, "result": "INCONCLUSIVE", "experiment": args.mode,
              "scope": "isolated HTTP/1 Proxy + Asset allocation stacks; not H/C/TLS/H2 qualification",
              "normal_release_qualification": False, "profiling": True, "allocator_replaced": False,
              "primary_sources": PRIMARY, "started_ns": now(), "clock": time.get_clock_info("monotonic").implementation,
              "parameters": {"duration_seconds": args.duration, "concurrency": args.concurrency,
                             "payload_bytes": args.payload_size, "trace_limit_bytes": MAX_TRACE,
                             "trace_decoded_limit_bytes": MAX_DECODED,
                             "connection_request_budget": MAX_CONNECTION_REQUESTS,
                             "socket_timeout_seconds": 5, "cooperative_response_deadline_seconds": 5},
              "environment": {"kernel": platform.release(), "python": sys.version,
                              "uid": os.getuid(), "effective_uid": os.geteuid(), "gid": os.getgid(),
                              "build_flags": {key: os.environ.get(key) for key in BUILD_FLAGS}},
              "perturbation": ["heaptrack malloc/free interposition and unwinding",
                               "collector/compressor/parser processes and memory",
                               "additional debug information if explicitly built",
                               "same gateway PID, no restart/trim/allocator substitution"],
              "gateway": None, "profile": None, "samples": [], "cleanup": {}}
    profiler = gateway = upstream = sampler = None
    gateway_identity = None
    sampled_stop = threading.Event()
    capture = SamplerCapture()
    logs = []
    private = tempfile.TemporaryDirectory(prefix="oxidase-attribution-private-")
    traces = tempfile.TemporaryDirectory(prefix="oxidase-attribution-trace-")
    try:
        if sys.platform != "linux":
            raise Unavailable("Linux /proc and collector required; no synthetic OS zeroes")
        if not 5 <= args.duration <= 600 or not 1 <= args.concurrency <= 16 or not 1 <= args.payload_size <= 4 * 1024 * 1024:
            raise Unavailable("experiment parameters outside fixed bounds")
        if re.search(r"[^a-zA-Z0-9_./-]", str(Path(traces.name))):
            raise Unavailable("upstream shell wrapper cannot safely represent trace path")
        binary = args.gateway.resolve(strict=True)
        report["gateway_binary"] = {"sha256": sha256(binary), "bytes": binary.stat().st_size}
        report["profiler"] = tool_inventory(args.tool_prefix.resolve())
        preflight = json.loads((args.output / "tool-preflight.json").read_text())
        if not isinstance(preflight, dict):
            raise Unavailable("profiler preparation record must be an object")
        if (preflight.get("result") != "AVAILABLE" or preflight.get("archive_sha256") != ARCHIVE_SHA256
                or stable_profiler_inventory(preflight.get("inventory", {})) != stable_profiler_inventory(report["profiler"])):
            raise Unavailable("installed profiler does not match this experiment's pinned preparation record")
        report["ptrace"] = {"scope": None, "cap_eff": None, "attach_attempted": False}
        try:
            report["ptrace"]["scope"] = int(Path("/proc/sys/kernel/yama/ptrace_scope").read_text())
            own_status = Path("/proc/self/status").read_text()
            report["ptrace"]["cap_eff"] = re.search(r"^CapEff:\s*(\w+)$", own_status, re.M)[1]
        except (OSError, AttributeError, ValueError):
            report["ptrace"]["error"] = "Yama/capability inspection unavailable"
        root = Path(private.name)
        payload = b"x" * args.payload_size
        Fixture.payload = payload
        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        upstream.daemon_threads = True
        server_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        server_thread.start()
        (root / "assets").mkdir()
        (root / "assets/site.oxsite").write_text("oxista: site/v1\n")
        (root / "assets/asset.bin").write_bytes(payload)
        config = root / "gateway.yaml"
        config.write_text(config_text(upstream.server_address[1]))
        report["fixture"] = {"secrets_generated": False, "certificates_generated": False,
                             "payload_sha256": hashlib.sha256(payload).hexdigest(),
                             "config_sha256": sha256(config), "config_uploaded": False,
                             "protocol": "HTTP/1.1", "trailers": "none; fixed Content-Length",
                             "unchanged_listener_default_max_requests_per_connection": MAX_CONNECTION_REQUESTS}
        collector_log = Path(traces.name) / "collector.log"
        gateway_log = Path(traces.name) / "gateway.log"
        trace_base = Path(traces.name) / "allocations"
        argv = [str(binary), "serve", str(config)]
        if args.mode == "launch":
            argv = [sys.executable, str(Path(__file__).resolve()), "limited-collector",
                    str(args.tool_prefix / "bin/heaptrack"), "--record-only", "-o", str(trace_base)] + argv
            with collector_log.open("wb") as stream:
                profiler = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT,
                                            env=clean_environment(), start_new_session=True)
            gateway_identity = owned_gateway(profiler, binary, now() + 30_000_000_000)
            address = listen_address(collector_log, profiler, now() + 30_000_000_000)
        else:
            with gateway_log.open("wb") as stream:
                gateway = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT,
                                           env=clean_environment(), start_new_session=True)
            gateway_identity = identity(gateway.pid, binary)
            address = listen_address(gateway_log, gateway, now() + 30_000_000_000)
            report["pre_attach_sample"] = sample_process(gateway_identity)
            report["pre_attach_load"] = load(address, payload, 2, args.concurrency)
            verify_process(gateway_identity)
            report["ptrace"]["attach_attempted"] = True
            with collector_log.open("wb") as stream:
                profiler = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "limited-collector",
                                             str(args.tool_prefix / "bin/heaptrack"), "--record-only",
                                             "-o", str(trace_base), "--pid", str(gateway.pid)],
                                            stdout=stream, stderr=subprocess.STDOUT,
                                            env=clean_environment(), start_new_session=True)
            deadline = now() + 30_000_000_000
            while now() < deadline:
                if profiler.poll() is not None:
                    raise Unavailable("runtime attach failed; policy was not bypassed")
                if "injection finished" in collector_log.read_text(errors="replace"):
                    break
                time.sleep(0.1)
            else:
                raise Unavailable("runtime attach deadline")
        report["gateway"] = gateway_identity
        report["collector_mapping"] = collector_mapping(gateway_identity, args.tool_prefix.resolve(), args.mode)
        report["file_capacity_guard"] = "64MiB RLIMIT_FSIZE inherited by collector process tree; no address-space limit on gateway"
        report["gateway_ready_ns"] = now()
        report["overhead_measurement"] = {
            "counterfactual": "unprofiled pre-attach sample/load" if args.mode == "attach" else None,
            "counterfactual_unavailable": args.mode == "launch",
            "gateway_rss_includes_injected_collector": True,
            "other_processes": "own profiler descendants, sampled separately from gateway",
            "not_a_performance_guarantee": True,
        }
        observed = {}
        def observe():
            while not sampled_stop.wait(0.5):
                try:
                    sample = sample_process(gateway_identity)
                    sample["profiler_processes"] = []
                    # The profiler is this helper's child; process-group members
                    # are its own compressor/interpreter, never a host pidof match.
                    if profiler.poll() is not None:
                        raise Unavailable("collector exited during Running measurement")
                    for directory in Path("/proc").iterdir():
                        if not directory.name.isdigit() or int(directory.name) == gateway_identity["pid"]:
                            continue
                        try:
                            pid = int(directory.name)
                            if os.getpgid(pid) != profiler.pid:
                                continue
                            stat = parse_stat((directory / "stat").read_text())
                            key = (pid, stat["start_ticks"])
                            if key not in observed:
                                if len(observed) >= 64:
                                    raise Unavailable("profiler process identity capacity")
                                observed[key] = identity(pid)
                            observation = sample_process(observed[key])
                            observation["exe_sha256"] = observed[key]["exe_sha256"]
                            sample["profiler_processes"].append(observation)
                        except (FileNotFoundError, ProcessLookupError):
                            continue
                    capture.append(sample)
                    for path in Path(traces.name).iterdir():
                        limit = MAX_TRACE if path.suffix == ".gz" else MAX_LOG
                        if path.is_file() and path.stat().st_size > limit:
                            raise Unavailable("profiler trace/log capacity exhausted")
                except (OSError, ValueError, Unavailable) as error:
                    capture.fail(str(error))
                    sampled_stop.set()
                    try:
                        safe_signal(gateway_identity, signal.SIGTERM)
                    except (OSError, Unavailable):
                        pass
                    break
        sampler = threading.Thread(target=observe, daemon=True)
        sampler.start()
        report["workload"] = load(address, payload, args.duration, args.concurrency)
        if STOP.is_set():
            raise Unavailable("experiment cancelled; no started request was silently relabelled success")
        if any(row["failed"] or row["completed"] == 0 for row in report["workload"]["workers"]):
            raise Unavailable("isolated workload had failed/incomplete responses")
        report["running_final_sample"] = sample_process(gateway_identity)
        report["gateway_binary_verified_at_running_end"] = identity(gateway_identity["pid"], binary)
        if report["gateway_binary_verified_at_running_end"] != gateway_identity:
            raise Unavailable("gateway binary/process identity changed during capture")
        settle_sampler(sampler, sampled_stop, capture, report, require=True)
        safe_signal(gateway_identity, signal.SIGTERM)
        report["cleanup"]["gateway_term_requested_ns"] = now()
        profiler.wait(timeout=20)
        if gateway:
            gateway.wait(timeout=5)
        report["cleanup"]["collector_exit"] = profiler.returncode
        report["cleanup"]["gateway_exit"] = gateway.returncode if gateway else None
        if profiler.returncode or gateway and gateway.returncode:
            raise Unavailable("collector/gateway unsuccessful retirement")
        trace = trace_base.with_suffix(".gz")
        report["trace"] = safe_trace(trace)
        parser_log = Path(traces.name) / "analysis.txt"
        # Child executes limits before exec, avoiding unsafe preexec_fn in this
        # multithreaded helper. Limits affect parser only, never the gateway.
        parser = [sys.executable, str(Path(__file__).resolve()), "limited-parser",
                  str(args.tool_prefix / "bin/heaptrack_print"), str(trace)]
        guarded_command(parser, parser_log, 120, MAX_LOG)
        with parser_log.open("rb") as stream:
            scan_stream(stream, MAX_LOG)
        text = parser_log.read_text()
        report["profile"] = parse_profile(text)
        # Rust symbols must actually exist before claiming source attribution.
        report["rust_symbols_observed"] = "oxidase_" in text or "oxidase::" in text
        if not report["rust_symbols_observed"]:
            raise Unavailable("allocation data parsed, but Oxidase source attribution unresolved")
        for source in (trace, parser_log, collector_log):
            if source.suffix != ".gz":
                with source.open("rb") as stream:
                    scan_stream(stream, MAX_LOG)
            shutil.copyfile(source, args.output / source.name)
            logs.append(source.name)
        report["published_artifacts"] = logs
        report["result"] = "CAPTURED"
    except (OSError, ValueError, EOFError, Unavailable, subprocess.SubprocessError) as error:
        report["error"] = str(error).replace(private.name, "<private-fixture>").replace(traces.name, "<private-trace>")
    finally:
        sampler_joined = settle_sampler(sampler, sampled_stop, capture, report)
        if gateway_identity:
            try:
                safe_signal(gateway_identity, signal.SIGTERM)
            except (OSError, Unavailable):
                pass
        for process in (gateway, profiler):
            if process and process.poll() is None:
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    # Owned, unreaped process-group leader; no unrelated PIDs.
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                    report["cleanup"]["forced_exit"] = True
                    report["result"] = "INCONCLUSIVE"
        if upstream:
            upstream.shutdown()
            upstream.server_close()
        # Failure logs may explain unavailable attach, but only bounded,
        # marker-checked public tool text is eligible for upload. Unsafe raw
        # traces stay outside upload directory and are removed, not redacted.
        for name in ("collector.log", "gateway.log"):
            source = Path(traces.name) / name
            if source.exists() and source.stat().st_size <= MAX_LOG:
                try:
                    with source.open("rb") as stream:
                        scan_stream(stream, MAX_LOG)
                    text = source.read_text(errors="replace").replace(private.name, "<private-fixture>")
                    (args.output / name).write_text(text)
                except (OSError, Unavailable):
                    report.setdefault("withheld_artifacts", []).append(name)
        # Safe partial traces and parser output are evidence even when symbols
        # or analysis fail. A truncated/oversize/unsafe trace is not silently
        # substituted by a numerical zero or uploaded without validation.
        for name in ("allocations.gz", "analysis.txt"):
            source = Path(traces.name) / name
            if source.exists():
                try:
                    if source.suffix == ".gz":
                        report.setdefault("trace", safe_trace(source))
                    else:
                        with source.open("rb") as stream:
                            scan_stream(stream, MAX_LOG)
                    shutil.copyfile(source, args.output / name)
                    if name not in logs:
                        logs.append(name)
                except (OSError, EOFError, Unavailable):
                    report.setdefault("withheld_artifacts", []).append(name)
        report["published_artifacts"] = logs
        private.cleanup()
        if sampler_joined:
            traces.cleanup()
        else:
            # A stopped-but-unacknowledged sampler retains this TemporaryDirectory
            # through its closure. Do not remove files while it may still read
            # them. Its frozen capture cannot mutate this receipt after return.
            report["cleanup"]["trace_cleanup_deferred"] = True
    report["ended_ns"] = now()
    json_write(args.output / "attribution.json", report)
    return 0 if report["result"] == "CAPTURED" else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preparation = commands.add_parser("prepare")
    preparation.add_argument("--tool-prefix", type=Path, required=True)
    preparation.add_argument("--output", type=Path, required=True)
    experiment = commands.add_parser("run")
    experiment.add_argument("--gateway", type=Path, required=True)
    experiment.add_argument("--tool-prefix", type=Path, required=True)
    experiment.add_argument("--output", type=Path, required=True)
    experiment.add_argument("--mode", choices=("launch", "attach"), default="launch")
    experiment.add_argument("--duration", type=int, default=60)
    experiment.add_argument("--concurrency", type=int, default=4)
    experiment.add_argument("--payload-size", type=int, default=1048576)
    limited = commands.add_parser("limited-parser")
    limited.add_argument("parser", type=Path)
    limited.add_argument("trace", type=Path)
    collector = commands.add_parser("limited-collector")
    collector.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command == "limited-parser":
        resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024 * 1024, 1536 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (110, 110))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG, MAX_LOG))
        os.execve(str(args.parser), [str(args.parser), str(args.trace), "--merge-backtraces", "false",
                                  "--peak-limit", "20", "--disable-builtin-suppressions",
                                  "--disable-embedded-suppressions"], clean_environment())
    if args.command == "limited-collector":
        if not args.argv:
            raise Unavailable("collector argv missing")
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_TRACE, MAX_TRACE))
        os.execve(args.argv[0], args.argv, clean_environment())
    args.output.mkdir(parents=True, exist_ok=True)
    def cancelled(_signum, _frame):
        STOP.set()
    signal.signal(signal.SIGTERM, cancelled)
    signal.signal(signal.SIGINT, cancelled)
    return prepare(args.tool_prefix, args.output) if args.command == "prepare" else run(args)


if __name__ == "__main__":
    sys.exit(main())
