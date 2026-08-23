# ADR 0003: Atomic reload and listener lifecycle

- Status: Accepted
- Date: 2026-08-23

## Decision

Reload is a prepare/commit transaction. The compiler and resource preparer run
against the currently pinned snapshot without changing published state. Unchanged
Site and Cluster resources are selected by content fingerprint and retain their
`Arc` identity. The shared upstream client/pool lives at the data-plane boundary and
survives every snapshot publication.

The listener manager compares stable listener names and configured bind addresses.
It binds every added or changed socket before commit; any bind failure drops all
prepared sockets and retains the last-known-good snapshot. It then stops accept on
removed/changed listeners and waits for an accept-stopped acknowledgement, atomically
publishes the new snapshot, and starts prepared listeners. Retired connections drain
with the snapshot they pinned when their request began.

`serve --watch` polls the compiler dependency graph, including imported config,
Oxista files, and relevant site directories. A change is debounced and sent through
the same compile/prepare/listener transaction. A rejected reload is logged once for
that observed filesystem state and does not replace the current snapshot.

## Consequences

Listener names and bind addresses form lifecycle identity. A pure rename that tries
to reuse the exact still-bound address cannot be fully prebound on platforms without
safe port sharing; this release rejects that reload and retains the old version.
Callers can instead retain the name or perform an address transition.

Polling is portable and dependency-aware but not instantaneous. A future native
watch backend can feed the same transaction without changing its semantics.

