#!/usr/bin/env python3
"""Triage pinned h2spec findings against focused raw-frame regressions."""

from __future__ import annotations

import json
import pathlib
import sys
import xml.etree.ElementTree as ET


ALLOWED_FINDINGS = {
    (
        "http2/6.9.1",
        "Sends multiple WINDOW_UPDATE frames increasing the flow control window to above 2^31-1 on a stream",
    ): (
        "RST_STREAM Frame (Error Code: FLOW_CONTROL_ERROR)",
        "RST_STREAM Frame (length:4, flags:0x00, stream_id:1)",
    ),
    (
        "http2/5.1",
        "closed: Sends a HEADERS frame after sending RST_STREAM frame",
    ): (
        "GOAWAY Frame (Error Code: STREAM_CLOSED)",
        "RST_STREAM Frame (Error Code: STREAM_CLOSED)",
        "Connection closed",
        "DATA Frame (length:19, flags:0x01, stream_id:1)",
    ),
    (
        "http2/8.1",
        "Sends a second HEADERS frame without the END_STREAM flag",
    ): (
        "GOAWAY Frame (Error Code: PROTOCOL_ERROR)",
        "RST_STREAM Frame (Error Code: PROTOCOL_ERROR)",
        "Connection closed",
        "DATA Frame (length:19, flags:0x01, stream_id:1)",
    ),
    (
        "http2/8.1.2.1",
        "Sends a HEADERS frame that contains a pseudo-header field as trailers",
    ): (
        "GOAWAY Frame (Error Code: PROTOCOL_ERROR)",
        "RST_STREAM Frame (Error Code: PROTOCOL_ERROR)",
        "Connection closed",
        "DATA Frame (length:19, flags:0x01, stream_id:1)",
    ),
}


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} H2SPEC_XML SUMMARY_JSON", file=sys.stderr)
        return 64
    report_path = pathlib.Path(sys.argv[1])
    summary_path = pathlib.Path(sys.argv[2])
    try:
        root = ET.parse(report_path).getroot()
    except (OSError, ET.ParseError) as error:
        print(f"h2spec JUnit report is missing or invalid: {error}", file=sys.stderr)
        return 1

    total = 0
    skipped = 0
    known_findings: list[str] = []
    unexpected: list[str] = []
    for case in root.iter("testcase"):
        total += 1
        key = (case.get("package", ""), case.get("classname", ""))
        if case.find("skipped") is not None:
            skipped += 1
        errors = list(case.findall("error")) + list(case.findall("failure"))
        if errors:
            rendered = f"{key[0]}:{key[1]}"
            fingerprint = tuple(
                line.strip()
                for error in errors
                for line in (error.text or "").splitlines()
                if line.strip()
            )
            if ALLOWED_FINDINGS.get(key) == fingerprint:
                known_findings.append(rendered)
            else:
                unexpected.append(f"{rendered}:{' | '.join(fingerprint)}")

    summary = {
        "schema_version": "oxidase.conformance.h2spec/v1",
        "cases": total,
        "direct_passes": total - skipped - len(known_findings) - len(unexpected),
        "skipped": skipped,
        "known_protocol_findings": sorted(known_findings),
        "unexpected_failures": sorted(unexpected),
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, sort_keys=True))
    if total != 147 or skipped or unexpected:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
