"""Offline regression corpus; fake fixture results are not profiler campaigns."""

import argparse
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import socket
import threading
from pathlib import Path
import tarfile
import tempfile
import unittest
import warnings
from unittest.mock import patch, MagicMock


SPEC = importlib.util.spec_from_file_location(
    "probe_resource_attribution", Path(__file__).resolve().parents[1] / "probe_resource_attribution.py")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class Boundaries(unittest.TestCase):
    def test_readiness_uses_actual_hosted_cli_protocol_text_and_rejects_ambiguity(self):
        process = MagicMock()
        process.poll.return_value = None
        # Original Linux run 37203019994: the real gateway started, but the old
        # validator expected a lowercase `http` that this CLI does not print.
        actual = "listener allocation accepting HTTP/1.1 on 127.0.0.1:42099\n"
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "collector.log"
            log.write_text("heaptrack output will be written\n" + actual)
            with patch.object(PROBE, "now", return_value=10):
                self.assertEqual(PROBE.listen_address(log, process, 100), ("127.0.0.1", 42099))
            for invalid in (actual.replace("HTTP/1.1", "http"), actual + actual):
                log.write_text(invalid)
                with patch.object(PROBE, "now", side_effect=[10, 200]), patch.object(PROBE.time, "sleep"):
                    with self.assertRaisesRegex(PROBE.Unavailable, "readiness deadline"):
                        PROBE.listen_address(log, process, 100)

    def sampler_failure_experiment(self, *, stuck=False, late=False, signal_receipts=None):
        class OwnedProcess:
            pid = 424242
            returncode = None
            def poll(self):
                return self.returncode
            def wait(self, **_kwargs):
                self.returncode = 0
                return 0
        class InjectedThread:
            def __init__(self, target, **_kwargs):
                self.target = target
                self.sampler = getattr(target, "__name__", None) == "observe"
            def start(self):
                pass
            def join(self, **_kwargs):
                if self.sampler and late:
                    cells = {name: cell.cell_contents for name, cell in zip(
                        self.target.__code__.co_freevars, self.target.__closure__)}
                    if "capture" in cells:
                        cells["capture"].fail("injected late sampler failure")
                    else:
                        cells["failure"].append("injected late sampler failure")
            def is_alive(self):
                return self.sampler and stuck
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "gateway"
            binary.write_bytes(b"known binary fixture, not an executed profiler")
            inventory = {"version": "heaptrack 1.5.0", "binaries": [], "linked_dependencies": {}}
            (root / "tool-preflight.json").write_text(json.dumps({
                "result": "AVAILABLE", "archive_sha256": PROBE.ARCHIVE_SHA256, "inventory": inventory}))
            def process(argv, **_kwargs):
                with gzip.open(Path(argv[argv.index("-o") + 1]).with_suffix(".gz"), "wb") as file:
                    file.write(b"synthetic regression trace, not campaign evidence")
                return OwnedProcess()
            def parse(_argv, log, *_args):
                log.write_text("oxidase_server::synthetic\ntotal runtime: 1s.\n"
                    "calls to allocation functions: 1 (1/s)\npeak heap memory consumption: 1KB\n"
                    "peak RSS (including heaptrack overhead): 2KB\ntotal memory leaked: 0B\n")
            args = argparse.Namespace(mode="launch", duration=5, concurrency=1, payload_size=1024,
                                      gateway=binary, tool_prefix=root / "tool", output=root)
            server = MagicMock(server_address=("127.0.0.1", 12345))
            record = {"pid": 424242, "start_ticks": 123, "exe_sha256": "fixture"}
            with patch.object(PROBE.sys, "platform", "linux"), \
                    patch.object(PROBE, "tool_inventory", return_value=inventory), \
                    patch.object(PROBE.http.server, "ThreadingHTTPServer", return_value=server), \
                    patch.object(PROBE.subprocess, "Popen", side_effect=process), \
                    patch.object(PROBE.threading, "Thread", InjectedThread), \
                    patch.object(PROBE, "owned_gateway", return_value=record), \
                    patch.object(PROBE, "identity", return_value=record), \
                    patch.object(PROBE, "collector_mapping", return_value={"verified": "synthetic"}), \
                    patch.object(PROBE, "listen_address", return_value=("127.0.0.1", 12345)), \
                    patch.object(PROBE, "sample_process", return_value={"rss_kib": 1}), \
                    patch.object(PROBE, "safe_signal") as signals, \
                    patch.object(PROBE, "load", return_value={"workers": [{"completed": 1, "failed": 0}]}), \
                    patch.object(PROBE, "guarded_command", side_effect=parse):
                code = PROBE.run(args)
                if signal_receipts is not None:
                    signal_receipts.extend(call.args[1] for call in signals.call_args_list)
            return code, json.loads((root / "attribution.json").read_text())

    def test_normal_shutdown_uses_existing_cli_ctrl_c_signal_not_sigterm(self):
        signals = []
        code, report = self.sampler_failure_experiment(signal_receipts=signals)
        self.assertEqual(code, 0)
        self.assertEqual(report["cleanup"]["gateway_shutdown_signal"], "SIGINT")
        self.assertEqual(signals[0], PROBE.signal.SIGINT)
        self.assertEqual(report["cleanup"]["collector_exit"], 0)

    def test_late_sampler_failure_cannot_be_captured(self):
        code, report = self.sampler_failure_experiment(late=True)
        self.assertEqual(code, 2)
        self.assertEqual(report["result"], "INCONCLUSIVE")

    def test_unjoined_sampler_cannot_be_captured_or_race_trace_cleanup(self):
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always", ResourceWarning)
            code, report = self.sampler_failure_experiment(stuck=True)
        self.assertEqual(code, 2)
        self.assertEqual(report["result"], "INCONCLUSIVE")
        self.assertFalse(report["cleanup"]["sampler_joined"])
        self.assertTrue(report["cleanup"]["trace_cleanup_deferred"])

    def test_owned_descendant_cannot_change_start_or_ancestry_during_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sys/kernel/random").mkdir(parents=True)
            (root / "sys/kernel/random/boot_id").write_text("test-boot\n")
            (root / "20").mkdir()
            child = root / "42"
            child.mkdir()
            binary = child / "exe"
            binary.write_bytes(b"matching binary, but process ownership is separately required")
            def stat(pid, parent, start):
                return f"{pid} (fixture) " + " ".join(["S", str(parent)] + ["0"] * 17 + [str(start)])
            (root / "20/stat").write_text(stat(20, 1, 120))
            capture = PROBE.identity
            for replacement in (stat(42, 20, 124), stat(42, 99, 123)):
                (child / "stat").write_text(stat(42, 20, 123))
                def raced(*args, **kwargs):
                    (child / "stat").write_text(replacement)
                    return capture(*args, **kwargs)
                parent = MagicMock(pid=20)
                parent.poll.return_value = None
                with patch.object(PROBE, "identity", side_effect=raced):
                    with self.assertRaisesRegex(PROBE.Unavailable, "reused|ancestry"):
                        PROBE.owned_gateway(parent, binary, PROBE.now() + 1_000_000_000, root)

    def test_response_head_and_final_eof_cannot_bypass_absolute_deadline(self):
        for delayed in ("head", "eof"):
            clock, timeouts = [0], []
            payload = b"exact"
            class Socket:
                def settimeout(self, seconds):
                    timeouts.append(seconds)
            class Response:
                status = 200
                will_close = False
                reads = 0
                def isclosed(self):
                    return False
                def read(self, _size):
                    self.reads += 1
                    if self.reads == 1:
                        clock[0] = 4_000_000_000
                        return payload
                    clock[0] = 6_000_000_000
                    return b""
                def getheader(self, name):
                    return {"Content-Type": "application/octet-stream", "Content-Length": str(len(payload)),
                            "Transfer-Encoding": None, "Trailer": None}[name]
            class Connection:
                sock = None
                def __init__(self, *_args, **_kwargs):
                    pass
                def connect(self):
                    self.sock = Socket()
                def request(self, *_args):
                    pass
                def getresponse(self):
                    if delayed == "head":
                        clock[0] = 6_000_000_000
                    return Response()
                def close(self):
                    self.sock = None
            PROBE.STOP.clear()
            with patch.object(PROBE.http.client, "HTTPConnection", Connection), \
                    patch.object(PROBE, "now", side_effect=lambda: clock[0]):
                receipt = PROBE.load(("127.0.0.1", 12345), payload, 1, 1)
            row = receipt["workers"][0]
            self.assertEqual((row["offered"], row["completed"], row["failed"]), (1, 0, 1), delayed)
            if delayed == "eof":
                self.assertIn(1.0, timeouts)

    def test_inventory_ignores_only_mapped_aslr_addresses_not_identity_changes(self):
        old = {"version": "heaptrack 1.5.0", "binaries": [{"path": "bin/heaptrack", "sha256": "abc", "bytes": 12}],
               "packages": [{"name": "library", "version": "1.0", "copyright_sha256": "known"}],
               "linked_files": [{"ldd_path": "/lib/library-0x123.so", "canonical_path": "/usr/lib/library-0x123.so",
                                 "sha256": "library-one", "bytes": 17}],
               "linked_dependencies": {"bin/heaptrack": "linux-vdso.so.1 (0x123)\n"
                   "\tlibrary-0x123.so => /lib/library-0x123.so (0x456)\n\t/lib/loader.so (0x789)\n"}}
        new = copy.deepcopy(old)
        new["linked_dependencies"]["bin/heaptrack"] = old["linked_dependencies"]["bin/heaptrack"].replace(
            "(0x123)", "(0x987)").replace("(0x456)", "(0xabc)").replace("(0x789)", "(0xdef)")
        self.assertNotEqual(old, new)
        self.assertEqual(PROBE.stable_profiler_inventory(old), PROBE.stable_profiler_inventory(new))
        self.assertIn("library-0x123.so", PROBE.stable_profiler_inventory(new)["linked_dependencies"]["bin/heaptrack"])
        for mutate in (
                lambda value: value["linked_files"][0].update(sha256="different-library-bytes"),
                lambda value: value["binaries"][0].update(sha256="different-tool-bytes"),
                lambda value: value["packages"][0].update(version="2.0"),
                lambda value: value["linked_dependencies"].update({"bin/heaptrack":
                    value["linked_dependencies"]["bin/heaptrack"].replace("library-0x123.so", "library-0x999.so")})):
            mismatch = copy.deepcopy(new)
            mutate(mismatch)
            self.assertNotEqual(PROBE.stable_profiler_inventory(old), PROBE.stable_profiler_inventory(mismatch))

    def test_linked_library_is_hashed_by_actual_canonical_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "library-0x123.so"
            alias = root / "library.so"
            binary.write_bytes(b"actual runtime library bytes")
            alias.symlink_to(binary)
            ldd = {"profiler": f"\tlibrary.so => {alias} (0x123)\n"}
            with patch.object(PROBE, "text_command", side_effect=PROBE.Unavailable("no synthetic package claim")):
                before = PROBE.linked_file_evidence(ldd)
                binary.write_bytes(b"changed runtime library bytes")
                after = PROBE.linked_file_evidence(ldd)
            self.assertEqual(before[0]["canonical_path"], str(binary.resolve()))
            self.assertNotEqual(before[0]["sha256"], after[0]["sha256"])
            self.assertEqual(before[0]["bytes"], len(b"actual runtime library bytes"))
            self.assertIsNone(before[0]["license_fields"])
            self.assertIn("license_error", before[0])
            with self.assertRaises(PROBE.Unavailable):
                PROBE.linked_file_evidence({"profiler": "missing.so => not found\n"})

    def test_keep_alive_sender_retires_before_operation_1001_without_retry(self):
        payload = b"exact fixture bytes"
        connections, operations = [], []
        class Socket:
            def settimeout(self, _seconds):
                pass
        class Response:
            status = 200
            will_close = False
            def __init__(self):
                self.read_once = False
            def read(self, _size):
                if self.read_once:
                    return b""
                self.read_once = True
                return payload
            def getheader(self, name):
                return {"Content-Type": "application/octet-stream", "Content-Length": str(len(payload)),
                        "Transfer-Encoding": None, "Trailer": None}[name]
            def isclosed(self):
                return False
        class Connection:
            def __init__(self, *_args, **_kwargs):
                self.count = 0
                self.sock = None
                self.closed = False
                connections.append(self)
            def connect(self):
                self.sock = Socket()
            def request(self, method, path):
                self.count += 1
                operations.append((method, path))
                if self.count > 1000:
                    raise PROBE.Unavailable("retired gateway sender was reused")
            def getresponse(self):
                return Response()
            def close(self):
                self.closed = True
                self.sock = None
        def clock():
            return 2_000_000_000 if len(operations) >= 1001 else 0
        PROBE.STOP.clear()
        with patch.object(PROBE.http.client, "HTTPConnection", Connection), patch.object(PROBE, "now", clock):
            receipt = PROBE.load(("127.0.0.1", 12345), payload, 1, 1)
        row = receipt["workers"][0]
        self.assertEqual(row["offered"], 1001)
        self.assertEqual(row["completed"], 1001)
        self.assertEqual(row["failed"], 0)
        self.assertEqual([connection.count for connection in connections], [1000, 1])
        self.assertTrue(all(connection.closed for connection in connections))

    def test_actual_connection_close_at_1000_validates_full_body_before_retiring(self):
        payload = b"entire public test fixture, not a captured heap/body dump"
        seen, connections = [0], []
        class Handler(PROBE.http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def setup(self):
                super().setup()
                self.connection.settimeout(5)
                self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.on_connection = 0
                connections.append(self)
            def do_GET(self):
                self.on_connection += 1
                seen[0] += 1
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(payload)))
                if self.on_connection == 1000:
                    self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(payload)
            def log_message(self, *_args):
                pass
        server = PROBE.http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        # Actual thread/socket exit is joined; no daemon hides leftover I/O.
        server.daemon_threads = False
        controller = threading.Thread(target=server.serve_forever)
        controller.start()
        PROBE.STOP.clear()
        try:
            with patch.object(PROBE, "now", side_effect=lambda: 2_000_000_000 if seen[0] >= 1001 else 0):
                receipt = PROBE.load(server.server_address, payload, 1, 1)
        finally:
            server.shutdown()
            controller.join(timeout=3)
            server.server_close()
        self.assertFalse(controller.is_alive())
        row = receipt["workers"][0]
        self.assertEqual((row["offered"], row["completed"], row["failed"]), (1001, 1001, 0))
        self.assertEqual([handler.on_connection for handler in connections], [1000, 1])
        self.assertEqual(row["connections"], {"started": 2, "connected": 2, "failed": 0, "closed": 2})

    def test_proc_stat_comm_spaces_parentheses_and_start_identity(self):
        rest = ["S", "20"] + ["0"] * 17 + ["123456"]
        result = PROBE.parse_stat("42 (space ) unicode 字) " + " ".join(rest))
        self.assertEqual(result, {"pid": 42, "state": "S", "ppid": 20, "start_ticks": 123456})
        with self.assertRaises(PROBE.Unavailable):
            PROBE.parse_stat("42 (truncated) S 20")

    def test_pid_reuse_and_binary_change_never_become_a_matching_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sys/kernel/random").mkdir(parents=True)
            (root / "sys/kernel/random/boot_id").write_text("boot-one\n")
            process = root / "42"
            process.mkdir()
            binary = process / "exe"
            binary.write_bytes(b"known ELF fixture")
            rest = ["S", "20"] + ["0"] * 17 + ["123456"]
            (process / "stat").write_text("42 (fixture) " + " ".join(rest))
            record = PROBE.identity(42, binary, root)
            PROBE.verify_process(record, root)
            rest[-1] = "123457"
            (process / "stat").write_text("42 (fixture) " + " ".join(rest))
            with self.assertRaises(PROBE.Unavailable):
                PROBE.verify_process(record, root)
            rest[-1] = "123456"
            (process / "stat").write_text("42 (fixture) " + " ".join(rest))
            binary.write_bytes(b"different ELF fixture")
            with self.assertRaises(PROBE.Unavailable):
                PROBE.verify_process(record, root)

    def test_environment_excludes_credentials_and_allocator_tuning(self):
        with patch.dict(PROBE.os.environ, {"SECRET_TOKEN": "not-for-upload", "LD_PRELOAD": "other.so",
                                          "MALLOC_CONF": "alter", "GLIBC_TUNABLES": "alter"}):
            environment = PROBE.clean_environment()
        self.assertNotIn("SECRET_TOKEN", environment)
        self.assertNotIn("LD_PRELOAD", environment)
        self.assertNotIn("MALLOC_CONF", environment)
        self.assertNotIn("GLIBC_TUNABLES", environment)

    def test_sensitive_marker_across_chunk_boundary_refuses_upload(self):
        marker = PROBE.FORBIDDEN[0]
        data = b"x" * (65536 - 5) + marker + b"y"
        with self.assertRaisesRegex(PROBE.Unavailable, "sensitive marker"):
            PROBE.scan_stream(io.BytesIO(data), 100000)

    def test_trace_expansion_size_and_corruption_are_not_zero_profiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = Path(temporary) / "trace.gz"
            with gzip.open(trace, "wb") as stream:
                stream.write(b"x" * 100)
            with patch.object(PROBE, "MAX_DECODED", 99):
                with self.assertRaises(PROBE.Unavailable):
                    PROBE.safe_trace(trace)
            trace.write_bytes(b"not gzip")
            with self.assertRaises(OSError):
                PROBE.safe_trace(trace)
            with gzip.open(trace, "wb") as stream:
                stream.write(b"")
            with self.assertRaises(PROBE.Unavailable):
                PROBE.safe_trace(trace)

    def test_parser_preserves_actual_units_and_unfreed_is_not_claimed_leak(self):
        text = ("total runtime: 12.50s.\ncalls to allocation functions: 500 (40/s)\n"
                "peak heap memory consumption: 42.25MB\npeak RSS (including heaptrack overhead): 80.00MB\n"
                "total memory leaked: 1.00KB\n")
        report = PROBE.parse_profile(text)
        self.assertEqual(report["allocations"], "500")
        self.assertEqual(report["peak_heap"], "42.25MB")
        self.assertTrue(report["unfreed_is_not_a_proven_leak"])
        for invalid in ("", text.replace("500", "0"), text.replace("peak heap memory consumption", "unknown"),
                        text.replace("peak RSS", "unknown"), text.replace("total memory leaked", "unknown")):
            with self.assertRaises(PROBE.Unavailable):
                PROBE.parse_profile(invalid)

    def test_source_archive_checksum_paths_links_and_expansion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "source.tar.xz"
            for name, kind in (("../outside", "regular"), ("heaptrack-1.5.0/link", "link"),
                               ("heaptrack-1.5.0/file", "regular")):
                with tarfile.open(archive, "w:xz") as file:
                    entry = tarfile.TarInfo(name)
                    if kind == "link":
                        entry.type = tarfile.SYMTYPE
                        entry.linkname = "/outside"
                        file.addfile(entry)
                    else:
                        entry.size = 1
                        file.addfile(entry, io.BytesIO(b"x"))
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                with patch.object(PROBE, "ARCHIVE_SHA256", digest):
                    if name == "heaptrack-1.5.0/file":
                        PROBE.extract_source(archive, root)
                        self.assertEqual((root / name).read_bytes(), b"x")
                    else:
                        with self.assertRaises(PROBE.Unavailable):
                            PROBE.extract_source(archive, root)
            with patch.object(PROBE, "ARCHIVE_SHA256", "0" * 64):
                with self.assertRaises(PROBE.Unavailable):
                    PROBE.extract_source(archive, root)

    def test_non_linux_measurement_is_valid_json_inconclusive_without_zeroes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            arguments = argparse.Namespace(mode="launch", duration=5, concurrency=1, payload_size=1024,
                                           gateway=root / "missing", tool_prefix=root / "missing-tool", output=root)
            with patch.object(PROBE.sys, "platform", "unsupported"):
                code = PROBE.run(arguments)
            self.assertEqual(code, 2)
            document = json.loads((root / "attribution.json").read_text())
            self.assertEqual(document["result"], "INCONCLUSIVE")
            self.assertEqual(document["samples"], [])
            self.assertIsNone(document["profile"])
            self.assertFalse(document["normal_release_qualification"])
            self.assertFalse(document["allocator_replaced"])


if __name__ == "__main__":
    unittest.main()
