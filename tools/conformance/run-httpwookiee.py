#!/usr/bin/env python3
"""Run pinned HTTPWookiee while preserving its unittest result status."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

ALLOWED_BOUNDARY_DIVERGENCES = {
    # Oxidase rejects double separators with 400. This is stricter than the
    # pinned suite's expectation that a regular query be accepted.
    "httpwookiee.client.tests_first_line.TestSpaceFirstLineSeparators.test_double_space_location_separator": ("Unknown", "Err400"),
    "httpwookiee.client.tests_first_line.TestSpaceFirstLineSeparators.test_double_space_method_separator": ("Unknown", "Err400"),
    # Hyper applies RFC 9112 Transfer-Encoding precedence, removes Content-
    # Length, canonicalizes one chunked request upstream, and closes the
    # downstream connection. The in-tree wire regression proves that the
    # embedded second request remains body bytes; the pinned suite prefers an
    # outright error and reports this safe normalization as Minor.
    "httpwookiee.client.tests_chunks.TestChunks.test_2010_preflight_chunked_and_content_length": ("Minor", "Accepted"),
    "httpwookiee.client.tests_chunks.TestChunks.test_2011_chunked_and_wrong_content_length": ("Minor", "Accepted"),
    "httpwookiee.client.tests_chunks.TestChunks.test_2012_preflight_wrong_content_length_and_chunked": ("Minor", "Accepted"),
    "httpwookiee.server.tests_chunks.Test20ChunksProxy.test_2010_preflight_chunked_and_content_length": ("Minor", "Accepted"),
    "httpwookiee.server.tests_chunks.Test20ChunksProxy.test_2011_chunked_and_wrong_content_length": ("Minor", "Accepted"),
    "httpwookiee.server.tests_chunks.Test20ChunksProxy.test_2012_preflight_wrong_content_length_and_chunked": ("Minor", "Accepted"),
}

EXPECTED_SKIPS = {
    "httpwookiee.client.tests_host.TestHost_carriagereturn.test_5000_preflight_default_vhost_absolute",
    "httpwookiee.client.tests_host.TestHost_formfeed.test_5000_preflight_default_vhost_absolute",
    "httpwookiee.client.tests_host.TestHost_htab.test_5000_preflight_default_vhost_absolute",
    "httpwookiee.client.tests_host.TestHost_null.test_5000_preflight_default_vhost_absolute",
    "httpwookiee.client.tests_host.TestHost_space.test_5000_preflight_default_vhost_absolute",
    "httpwookiee.client.tests_host.TestHost_vtab.test_5000_preflight_default_vhost_absolute",
    "httpwookiee.server.tests_host.TestHostProxy_bell.test_5000_preflight_default_vhost_absolute",
    "httpwookiee.server.tests_host.TestHostProxy_carriagereturn.test_5000_preflight_default_vhost_absolute",
    "httpwookiee.server.tests_host.TestHostProxy_formfeed.test_5000_preflight_default_vhost_absolute",
    "httpwookiee.server.tests_host.TestHostProxy_htab.test_5000_preflight_default_vhost_absolute",
    "httpwookiee.server.tests_host.TestHostProxy_null.test_5000_preflight_default_vhost_absolute",
    "httpwookiee.server.tests_host.TestHostProxy_space.test_5000_preflight_default_vhost_absolute",
    "httpwookiee.server.tests_host.TestHostProxy_vtab.test_5000_preflight_default_vhost_absolute",
    "httpwookiee.client.tests_host.TestNonDefaultHost_space.test_5002_preflight_non_default_vhost",
    "httpwookiee.server.tests_host.TestNonDefaultHostProxy_space.test_5002_preflight_non_default_vhost",
    "httpwookiee.client.tests_host.TestNonDefaultHost_space.test_5003_preflight_non_default_vhost_absolute",
    "httpwookiee.server.tests_host.TestNonDefaultHostProxy_space.test_5003_preflight_non_default_vhost_absolute",
}


def main() -> int:
    if len(sys.argv) != 3:
        print(
            f"usage: {sys.argv[0]} HTTPWOOKIEE_SOURCE SUMMARY_JSON",
            file=sys.stderr,
        )
        return 64

    source = pathlib.Path(sys.argv[1]).resolve()
    summary_path = pathlib.Path(sys.argv[2])
    sys.path.insert(0, str(source))
    spec = importlib.util.spec_from_file_location(
        "httpwookiee_entry", source / "httpwookiee.py"
    )
    if spec is None or spec.loader is None:
        print("cannot load the pinned HTTPWookiee entrypoint", file=sys.stderr)
        return 1
    entry = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(entry)

    from httpwookiee.core.result import TextStatusResult
    from httpwookiee.core.testrunner import WookieeTestRunner

    file_filters = {"match": [], "exclude": [], "nums": []}
    unit_filters = {"match": [], "exclude": [], "nums": []}
    classes = entry.collectTestClasses(
        str(source / "httpwookiee"), file_filters, classNamePrefix="httpwookiee"
    )
    suite = entry.collectTestsSuites(classes, unit_filters)
    if not suite.countTestCases():
        print("HTTPWookiee selected no tests", file=sys.stderr)
        return 1
    runner = WookieeTestRunner(
        resultclass=TextStatusResult,
        verbosity=1,
        buffer=True,
        stream=sys.stderr,
    )
    result = runner.run(suite)
    # The pinned Python-2-era suite calls the removed Thread.isAlive alias from
    # __del__. Its server has already joined in run(); clear the dead reference
    # so Python 3 teardown does not add a misleading exception to the report.
    runner.server_thread = None
    failure_fingerprints = {
        test.id(): (test.getGravity(human=True), test.getStatus())
        for test, _ in result.failures
    }
    failures = sorted(failure_fingerprints)
    errors = sorted(test.id() for test, _ in result.errors)
    skipped = sorted(test.id() for test, _ in result.skipped)
    allowed = sorted(
        test_id
        for test_id, fingerprint in failure_fingerprints.items()
        if ALLOWED_BOUNDARY_DIVERGENCES.get(test_id) == fingerprint
    )
    unexpected = sorted(set(failures) - set(allowed))
    unexpected_skips = sorted(set(skipped) - EXPECTED_SKIPS)
    missing_skips = sorted(EXPECTED_SKIPS - set(skipped))
    summary = {
        "schema_version": "oxidase.conformance.httpwookiee/v1",
        "tests_run": result.testsRun,
        "skipped": skipped,
        "allowed_boundary_divergences": allowed,
        "failure_fingerprints": {
            test_id: {"gravity": gravity, "status": status}
            for test_id, (gravity, status) in sorted(failure_fingerprints.items())
        },
        "unexpected_failures": unexpected,
        "unexpected_skips": unexpected_skips,
        "missing_expected_skips": missing_skips,
        "errors": errors,
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, sort_keys=True))
    return 1 if result.testsRun != 243 or unexpected or errors or unexpected_skips or missing_skips else 0


if __name__ == "__main__":
    raise SystemExit(main())
