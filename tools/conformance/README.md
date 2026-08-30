# External protocol conformance

These tools are deliberately separate from ordinary unit CI. They download pinned
third-party source archives, verify SHA-256 before extraction, run only against
loopback fixtures, and preserve unedited reports as workflow artifacts. A fetched or
compiled tool is not a passing campaign, and a raw tool result is not a release gate
until every finding is triaged against `docs/security/protocol-boundaries.md`.

Pinned inputs are in `versions.env`:

- h2spec v2.6.0 commit `70ac2294010887f48b18e2d64f5cccd48421fad1`;
- Autobahn Testsuite v25.10.1 commit `6ed6f439dc7ed0d7432fe2cf7481b110905ecc5c`
  and the immutable Linux/amd64 image digest recorded there;
- tlsfuzzer commit `5eebc4464e5197a7f7392fb9acda99cfc32441f7`;
- tlslite-ng `0.9.0b2`, ECDSA `0.19.0`, six `1.17.0`, and termcolor `3.1.0`, using the exact
  archives/wheels and SHA-256 values used by the fetcher;
- HTTPWookiee commit `f9908e3934fdbcdfc5eaff934f7ad531079bb06f`.

The source archives are retained in the workflow artifact along with command output,
the Oxidase server log, and the tested commit. The manual workflow accepts `all` or
one suite name. It uses fixed loopback ports on an isolated GitHub runner; ordinary
workspace tests continue to use ephemeral ports and do not require Internet,
Docker, Go, Python packages, or these external suites.

## Boundary-specific interpretation

- h2spec targets the TLS/ALPN H2 Listener and validates the Hyper-facing server
  boundary. Its RFC 7540-era strict expectations require manual comparison with
  current HTTP/2 errata. v2.6.0 has four narrowly triaged findings: three cases in
  which a valid response DATA frame can already be queued before invalid follow-up
  HEADERS are processed, plus one flow-control case where the raw wire contains the
  correct `FLOW_CONTROL_ERROR` code but the pinned tool renders only the generic
  RST frame as its actual result. `validate-h2spec.py` allows only the exact pinned
  XML fingerprints. `run-h2spec.sh` first runs raw-frame regressions that prove the
  invalid HEADERS never execute a second Service request, a fresh connection remains
  healthy, and stream window overflow carries `FLOW_CONTROL_ERROR`; they do not
  claim deterministic reproduction of tool frame ordering. Every other h2spec
  failure remains fatal.
- Autobahn runs a real echo server behind Oxidase. It validates that the trusted
  HTTP/1 Proxy Upgrade tunnel preserves WebSocket bytes; Oxidase itself is not a
  WebSocket application implementation. Compression/performance families are
  excluded because Oxidase neither negotiates nor interprets those extensions.
- tlsfuzzer exercises malformed ClientHello and TLS version negotiation. It does
  not validate certificate issuance policy or future mTLS authorization. The
  runner selects fixed named probes: the suite's broad draft-version fallback
  matrix and RSA key-exchange sanity case are not applicable to rustls safe
  TLS 1.2/1.3 defaults and are not counted as Oxidase failures.
- HTTPWookiee runs both client and controlled backend on loopback to examine reverse-
  proxy message-boundary behavior. Its severity labels are advisory and can contain
  false positives; never point this runner at a public host. The wrapper allows only
  eight named boundary divergences: two stricter double-space rejections and six
  CL/TE cases where Hyper applies TE precedence, Oxidase removes CL, forwards one
  canonical chunked message, and closes the downstream connection. In-tree raw-wire
  tests prove that the embedded request remains body bytes. The wrapper additionally
  requires the exact pinned set of 17 skipped preflights and binds every allowed
  failure to its observed status and gravity. Every other failure, skip, fingerprint,
  or error is fatal and appears in the JSON summary.

## Local preparation

```bash
tools/conformance/fetch.sh /tmp/oxidase-conformance-tools
cargo build --workspace --release --locked
target/release/oxidase serve tools/conformance/fixture/oxidase.yaml
```

Run only a suite whose dependencies are installed, and store its output in a new
result directory. Do not reuse an old report as evidence for a new commit.
