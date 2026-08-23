# Operations

## Startup and validation

`oxidase check <config>` performs the same configuration and Oxista preparation as
serve/reload without binding sockets. `oxidase test <config>` then runs declarative
request expectations. Use both before deployment.

`oxidase serve <config>` prepares every resource and listener before accepting
traffic. Any initial bind failure prevents partial startup.

## Reload

Use `oxidase serve <config> --watch` for the portable dependency watcher. Candidate
configuration, imports, templates, response documents, assets, and resources are
fully prepared first. New listener sockets are prebound. A failed candidate is
logged and the last-known-good snapshot remains active.

Requests pin one snapshot through Service execution. Removed listeners stop accepting
before publication and existing connections drain with a bounded deadline.

## Health and metrics

The management listener is opt-in and independent from user traffic:

```bash
oxidase serve config.yaml --watch --admin-bind 127.0.0.1:7590
```

It serves:

- `/health/live`: process/event-loop liveness;
- `/health/ready`: a prepared snapshot with at least one user listener;
- `/metrics`: Prometheus text with fixed outcome, status-class, latency, active
  request, and reload counters.

Do not expose the admin bind directly to an untrusted network. Metric labels are
intentionally bounded and never contain raw URLs, headers, user IDs, or Service
source values.

## Logging

Set `RUST_LOG`, for example `RUST_LOG=oxidase=debug`. Access events correlate a
request ID, config version, listener, bounded outcome/status, and latency. Internal
failure details go to structured logs; clients receive only safe generic errors.
