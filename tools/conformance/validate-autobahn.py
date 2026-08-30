#!/usr/bin/env python3
"""Validate that Autobahn ran every selected transport case and summarize it."""

from __future__ import annotations

import collections
import json
import pathlib
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} INDEX_JSON SUMMARY_JSON", file=sys.stderr)
        return 64

    index_path = pathlib.Path(sys.argv[1])
    summary_path = pathlib.Path(sys.argv[2])
    try:
        report = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"Autobahn report is missing or invalid: {error}", file=sys.stderr)
        return 1

    behavior = collections.Counter()
    close_behavior = collections.Counter()
    failures: list[str] = []
    total = 0
    for agent, cases in sorted(report.items()):
        for case_id, case in sorted(cases.items()):
            total += 1
            observed = str(case.get("behavior", "MISSING"))
            observed_close = str(case.get("behaviorClose", "MISSING"))
            behavior[observed] += 1
            close_behavior[observed_close] += 1
            if observed not in {"OK", "NON-STRICT", "INFORMATIONAL"} or observed_close not in {
                "OK",
                "NON-STRICT",
                "INFORMATIONAL",
            }:
                failures.append(f"{agent}:{case_id}:{observed}:{observed_close}")

    summary = {
        "schema_version": "oxidase.conformance.autobahn/v1",
        "cases": total,
        "behavior": dict(sorted(behavior.items())),
        "close_behavior": dict(sorted(close_behavior.items())),
        "failures": failures,
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, sort_keys=True))
    if total != 247:
        print(f"expected 247 selected Autobahn cases, observed {total}", file=sys.stderr)
        return 1
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
