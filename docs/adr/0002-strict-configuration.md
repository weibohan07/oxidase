# ADR 0002: Strict YAML source boundary

- Status: Accepted
- Date: 2026-08-23

## Decision

Use the maintained `serde_yaml_ng` continuation as the YAML-to-source-AST boundary.
Every source structure denies unknown fields. A lexical validation pass runs before
deserialization to reject duplicate block-mapping keys, tab indentation, YAML merge
keys, anchors, aliases, and flow-style mappings.

Flow-style sequences remain allowed. Flow-style mappings are intentionally excluded
from the v1alpha1 source language so duplicate-key validation and diagnostics remain
deterministic without making YAML representation details part of domain types.
Users should use block mappings, Oxidase imports, and named Service references.

Parser errors retain the parser's line and column. Semantic diagnostics always
retain the file and field path; their line and column are initially the owning
document position when an exact scalar marker is not available.

## Consequences

The accepted language is a strict, portable YAML subset rather than every construct
permitted by the YAML specification. This prevents silent typo acceptance and
anchor/merge behavior from bypassing the compiler's reference and import graphs.
The parser remains isolated so a future span-rich frontend can replace it without
changing normalized Service IR.

