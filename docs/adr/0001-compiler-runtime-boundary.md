# ADR 0001: Compiler and runtime boundary

- Status: Accepted
- Date: 2026-08-23

## Decision

Maintain distinct source AST, normalized Service IR, and prepared runtime snapshot
types. Configuration compilation is the only route into a publishable snapshot.
The `check` command and reload both invoke this same pipeline; `check` stops before
publication.

Stable IDs are derived from source ownership paths rather than allocation order.
Diagnostics retain a source file, line, column, and field path whenever the parser
can supply them. Runtime nodes contain compiled patterns and templates and resolved
resource IDs, never source strings that need interpretation.

## Consequences

This uses more explicit conversion code, but prevents parse-only validation,
request-time compilation, and runtime dependence on inline versus imported source
organization. It also gives `explain` stable node identities.

