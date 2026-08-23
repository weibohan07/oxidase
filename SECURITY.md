# Security policy

Oxidase v0.2 is alpha software and should be deployed behind normal network and
process isolation. The exact implemented security boundary is tracked in
`docs/implementation-status.md`.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting or a private Security Advisory
for this repository. Include the affected commit, configuration, reproduction, and
impact. Do not open a public issue containing an active exploit, secret, private
path, or upstream credential.

The project will acknowledge a complete report, reproduce it on a supported commit,
and coordinate a fix and disclosure. No fixed response-time SLA is promised for the
alpha release.

## Current security invariants

- Configuration, Patterns, Expressions, OXR, and OXT compile before publication.
- Unknown/duplicate config keys, implicit cycles, and missing resources fail closed.
- Site source, backing, dot/private, denied, traversal, double-encoded, and symlink
  escape paths are not public assets.
- OXT has no filesystem, network, database, shell, plugin, or arbitrary-code
  capability. HTML interpolation autoescapes and resource limits are enforced.
- Redirect locations are restricted to local absolute paths; network-path and header
  injection forms fail.
- Proxy forwarding metadata is rebuilt from connection metadata, hop-by-hop headers
  are removed, native roots validate upstream TLS, and I/O has finite deadlines.
- Client-facing errors never contain internal paths, source text, secrets, or
  upstream diagnostic details.
- The management listener is disabled unless an operator explicitly supplies
  `--admin-bind`; bind it to loopback or a protected management network.
