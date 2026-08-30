# v0.4 security-conformance audit

This report records the local audit performed on the first v0.4 milestone branch,
based on public `main` commit `05aedd119e89b7dbdb06f251e028387ab00317c6`.
It distinguishes in-tree regression tests, actual external campaigns, tool-specific
triage, and Hosted workflow status. It is not a production-readiness statement.

## Confirmed findings and fixes

No P0 was confirmed. The following P1 issues were reproduced and fixed before the
branch was eligible for review:

| Finding | Fix | Regression evidence |
| --- | --- | --- |
| Duplicate/empty/missing HTTP/1 Host and request-target forms did not have one explicit ingress policy. | Reject ambiguous/missing forms before Service execution; reject CONNECT/unsupported authority-form for HTTP/1.0 and HTTP/1.1. | Raw HTTP/1 Host/target corpus. |
| Absolute-form and H2 `:authority` could coexist with a conflicting Host visible to expressions. | Canonicalize the Host field to the selected authority before constructing `RequestMetadata`; duplicate H2 Host fails. | HTTP/1 and H2 expression-level assertions. |
| HTTP/1 had no conservative field-count, decoded-head, or request-target cap independent of parser allocation. | Apply fixed 100-field, 64 KiB decoded-head, and 8 KiB target defaults in the Hyper boundary. | Exact boundary and limit-plus-one wire cases. |
| Request trailers were not carried/validated as one declared frame set, late auth/representation/forwarding identity fields were allowed, and undeclared H2 trailers could disappear at an H1 upstream encoder. | Preserve normalized declarations; validate actual frames; reject routing, auth, cookie, forwarding identity, conditional, response-control, representation, framing, and connection fields; require declarations at an H1 egress. | H1 chunked and H2-to-H1 black-box request trailer tests plus request/response guard tests. |
| Malformed downstream chunk framing could surface through the upstream Hyper client as `UpstreamProtocol` and a 502. | Preserve a private `DownstreamRequestBodyError` through the body adapter and return safe 400 before an upstream response head. | Invalid chunk/overflow wire tests and HTTPWookiee rerun. |
| Certificate prepare accepted expired/not-yet-valid chains and did not validate leaf-first adjacent links or issuer constraints. | Hard-fail activation-time validity; require adjacent issuer names/signatures, issuer `CA=true`, and `keyCertSign` when Key Usage is present; retain key/leaf proof. | Expired, future, reversed, same-subject/wrong-key, non-CA intermediate, and non-signing intermediate tests. |
| Active-health failure could overwrite a concurrent passive ejection; expired-ejection cleanup could erase a new ejection; policy-changing old/new supervisors could write shared health state. | Serialize health transitions, preserve passive-ejection precedence, isolate health generations on policy changes, and keep admission shared across generations. | Deterministic stale-observation, expiry/new-failure, policy-generation, and old-permit tests. |

Concurrency tests also prove coherent snapshot publication/pinning, bounded Cluster
and endpoint admission, one-winner retry/supervisor state, and exact concurrent
release of body, H2 connection/stream, and tunnel guards. No additional confirmed
race required a production-code change.

## External campaigns actually run locally

The source archives and direct Python wheels were downloaded from their canonical
locations and matched every SHA-256 in `tools/conformance/versions.env`. These runs
used loopback only.

### h2spec v2.6.0

```text
cases: 147
direct passes in final run: 146
skipped: 0
unexpected failures: 0
known protocol findings in final run: 1
```

Pinned h2spec can report three protocol divergences when response DATA is already
queued before an invalid follow-up HEADERS block is processed: closed-stream reuse,
a second non-terminating trailer block, and a pseudo-header in trailers. Under some
schedules Hyper does not emit the rejection before the tool timeout, so these are
recorded as known divergences rather than described as guaranteed eventual errors.
The in-tree raw-frame regression proves the bounded safety property that none of the
invalid follow-ups executes a second Service request and that a fresh connection
remains healthy. A fourth tool-specific finding can occur for stream window overflow:
an independent raw-wire regression proves the emitted RST carries
`FLOW_CONTROL_ERROR`, while pinned h2spec can render only the generic RST as its
actual result. The validator admits only the exact pinned XML fingerprint of these
four findings; a different error is fatal.

### tlsfuzzer

```text
malformed ClientHello probes: 5/5
TLS 1.3 sanity: 1/1
TLS version/record boundaries: 6/6
total selected: 12/12
```

The selection is fixed by name. Obsolete draft-fallback and RSA key-exchange probes
are excluded because rustls intentionally exposes only its safe TLS 1.2/1.3 policy;
they are not counted as passes.

### Autobahn Testsuite 25.10.1

```text
cases: 247
OK: 234
NON-STRICT: 10
INFORMATIONAL: 3
FAILED: 0
close OK: 244
close INFORMATIONAL: 3
```

The immutable Linux/amd64 image ran an echo server behind the real Oxidase trusted
HTTP/1 Upgrade tunnel. Performance/compression families 9, 12, and 13 are excluded
because Oxidase neither negotiates nor interprets those WebSocket application
features.

### HTTPWookiee

```text
tests run: 243
skipped by the pinned suite: 17
unexpected failures: 0
errors: 0
allowed boundary divergences: 8
```

The first full run had 12 findings. Four chunk-size-overflow cases exposed the
downstream-body 502 misclassification described above; after the fix they pass with
a safe 400. The remaining eight exact divergences are retained in the machine
summary:

- two double-space request-line cases where Oxidase is stricter and returns 400;
- six CL/TE cases where Hyper gives Transfer-Encoding precedence, Oxidase removes
  Content-Length, emits one canonical chunked upstream request, and closes the
  downstream connection.

The raw CL/TE test embeds a complete second request after the chunk terminator and
proves it is never executed or re-emitted as a second upstream message. No other
HTTPWookiee failure is allowlisted.

## Hosted boundary

At the time this local report was written, the manual Hosted conformance workflow
had not yet run for the eventual PR head. The checked-in workflow is a per-suite
matrix with pinned Action commits, immutable source/image identities, environment
capture, raw artifacts, and real aggregate exit status. A future run ID must be
recorded separately; this local evidence must not be described as Hosted success.
