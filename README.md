# Oxidase

English | [简体中文](README.zh.md)

Oxidase is a declarative HTTP Service program compiler and runtime written in Rust.

Gateway configuration is treated as source code. Oxidase resolves imports and
references, validates the complete program, compiles patterns, expressions,
templates, and Oxista sites, prepares shared resources, then publishes an immutable
runtime snapshot. Each listener binds network traffic to any root Service.

## The model

- **Listener** owns transport metadata and points to a root Service.
- **Service Program** composes terminal (`Respond`, `Redirect`, `Site`, `Proxy`),
  wrapper (`Transform`, `Observe`, `Timeout`, `Recover`), and composition (`Route`,
  `Fallback`, `Reenter`) nodes.
- **Resource Registry** owns reusable state such as compiled Site snapshots and
  Cluster definitions. Resources are not Services.
- **Router DSL** is optional source syntax lowered to ordinary Service IR before
  execution; the runtime has no privileged Router.
- **Oxista** compiles `.oxsite`, `.oxr`, and `.oxt` sources into an immutable Site
  index. Request handling never parses these files.

Every Service returns one of `Handled(response)`, `Declined`, or `Failed(error)`.
Fallback advances only on `Declined`; HTTP 404 and 500 responses are still handled
responses. Request overlays and route bindings are lexical, so a declined branch
cannot leak captures or rewrites into its siblings.

## Current v0.2 alpha

The runnable HTTP/1.1 slice supports every current Service node, including streaming
Proxy over pooled HTTP/1.1, HTTPS, and upstream HTTP/2 connections. Assets are
streamed from async files and support quality-weighted identity/Brotli/gzip
selection, representation-specific ETags, correct validator precedence, If-Range,
and single byte ranges. Range applies only to GET: a valid single bytes range uses
identity when acceptable, while HEAD, unknown/malformed units, multipart requests,
and an identity-excluded range fall back to the normal full-representation path.

Listener programs share one immutable `ServiceGraph`; normal requests do not clone
the graph or collect explain traces. Every handled response passes through one
framing finalizer, and Gateway/Oxista source cannot set hop-by-hop or framing
headers. HEAD, informational, 204, 205, and 304 body rules are covered by wire
tests.

`Observe` is a production wrapper rather than explain-only syntax. It records a
bounded, structured service-to-response-head scope for handled, declined, failed,
timeout, and nested executions without enabling full traces. A separate streaming
body adapter records emitted bytes, completion, errors, idle timeouts, and downstream
cancellation. Metric labels come only from configured Observe names and fixed enums;
request URLs, queries, and Header values are never labels.

Oxista response headers execute in source order (global defaults, logical extension,
profiles, then local OXR). Ordinary and OXR-backed assets share extension defaults.
External OXT files inherit Site output/autoescape defaults; custom 404 templates are
validated as zero-argument calls and retain their effective metadata. Template
budget failures are classified separately for `Recover` without exposing details to
clients.

OXT includes have typed call contracts:
`{% include "_templates/card.oxt" with item=item only %}`. Arguments are ordinary
compiled expressions, required/unknown/constant-type errors fail preparation, and
dynamic values are checked before rendering. Normal include inherits caller locals;
`only` keeps the read-only `request`, `bindings`, `site`, `resource`, and `page`
roots while dropping caller template/loop/with scopes. Render budgets are charged
before each expression, loop body, include, and output write, so exactly the stated
limit is allowed and the next operation does not execute.

Correctness identities use complete SHA-256 digests with domain-separated,
length-prefixed structured encoding. Strong Asset validators are
`"sha256-<64 lowercase hex>"` over the selected representation bytes. One
`SiteSourceIndex` scan supplies Site reuse identity, representation ETags, cached
Oxista source text, and compilation metadata; large Asset bytes are not retained.
Gateway and Oxista semantic diagnostics carry exact byte and line/column ranges,
secondary labels, related definitions, and import/include reference chains. Every
compiling CLI command accepts `--diagnostic-format human|json`; JSON uses the
versioned `oxidase.diagnostics/v1` envelope and keeps stdout machine-readable.
Request expression views are frame-local and lazy, so effective Headers, query
values, bindings, and the request namespace are built once per unchanged frame.

Inbound TLS/HTTP/2 and OXT `extends`/`block` are not yet implemented. Atomic
last-known-good reload is available with `serve --watch`; health and bounded metrics
are available on an explicit separate `--admin-bind`. See
[`docs/implementation-status.md`](docs/implementation-status.md) for exact status.
This release remains `0.2.0-alpha` and is not described as production-ready.

## Try the vertical slice

```bash
cargo run -p oxidase-cli -- check examples/basic-gateway/oxidase.yaml
cargo run -p oxidase-cli -- test examples/basic-gateway/oxidase.yaml
cargo run -p oxidase-cli -- explain examples/basic-gateway/oxidase.yaml \
  --request examples/basic-gateway/requests/home.yaml
cargo run -p oxidase-cli -- serve examples/basic-gateway/oxidase.yaml
cargo run -p oxidase-cli -- serve examples/basic-gateway/oxidase.yaml --watch
cargo run -p oxidase-cli -- serve examples/basic-gateway/oxidase.yaml --watch \
  --admin-bind 127.0.0.1:7590
```

The example demonstrates:

- `/`: compiled OXT page;
- `/about.html`: sibling asset governed by OXR headers;
- `/old-page`: Oxista redirect;
- `/feed.json`: structured JSON response;
- `/legacy`: Service-level redirect;
- a missing resource declining from Site into an explicit Respond 404;
- an outer response Transform applied to every handled branch.

The `/api/*` route proxies to an upstream on `127.0.0.1:3000`. Without that fixture
upstream it returns a safe 502; `explain` can inspect the rewrite and Cluster
selection without making the network request.

## Configuration sketch

```yaml
api_version: oxidase.dev/v1alpha1
kind: gateway

services:
  public:
    type: transform
    response:
      headers:
        set:
          X-Content-Type-Options: nosniff
    service:
      type: fallback
      services:
        - type: site
          site: web
        - type: respond
          status: 404
          body:
            text: Not Found

listeners:
  - name: public-http
    bind: 127.0.0.1:7589
    service:
      ref: public
```

The v1alpha1 YAML boundary is shared by Gateway and every Oxista format. Unknown or
duplicate keys, anchors, aliases, merge keys, custom tags, tab indentation, and flow
mappings fail; flow sequences and literal/folded block scalars are allowed. Imports/
references are cycle checked, and parsed-but-inert field values are rejected with
migration guidance. `check` and `serve` use the same compiler and Site preparation
path.

## CLI

```text
oxidase check <config>
oxidase serve <config>
oxidase explain <config> --request <request-file> [--listener <name>]
oxidase compile <config> --output <manifest.json>
oxidase test <config>
```

Append `--diagnostic-format json` to `check`, `compile`, `test`, `serve`, or a
failing `explain` invocation for deterministic machine-readable diagnostics. See
[`docs/diagnostics.md`](docs/diagnostics.md) for the alpha schema and position
conventions.

`compile` currently writes a deterministic inspection manifest, not a self-contained
binary runtime snapshot.

`serve --watch` watches imported configuration and compiled Site dependencies.
Reload compiles and prepares the complete candidate, prebinds new listeners, reuses
unchanged resources, and atomically commits only on success. Blocking preparation
runs off Tokio workers. Failed-candidate imports remain watched, and retired HTTP/1
connections receive graceful shutdown: idle keep-alive closes promptly while active
requests drain on their pinned snapshot. Failed Site candidates also retain scanned
OXT/OXR/assets, missing declared paths, template roots, precompressed candidates,
and their parent directories in the watcher dependency set.

## Development

```bash
cargo +1.88.0 check --workspace --all-targets --all-features --locked
cargo +1.88.0 test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo deny check
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
cargo build --workspace --release --locked
```

The HTTP end-to-end tests bind ephemeral loopback ports. Sandboxed environments may
need permission to run those tests.

Architecture starts at [`ARCHITECTURE.md`](ARCHITECTURE.md). The v0.1 prototype is
described in [`docs/legacy/v0.1.md`](docs/legacy/v0.1.md) and remains available in
Git history.

Oxidase is licensed under the [MIT License](LICENSE).
