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
streamed from async files and support single byte ranges, ETag/Last-Modified
conditionals, and precompressed representation selection.

Inbound TLS/HTTP/2, management endpoints, and OXT `extends`/`block` are not yet
implemented. Atomic last-known-good reload is available with `serve --watch`. See
[`docs/implementation-status.md`](docs/implementation-status.md) for exact status.

## Try the vertical slice

```bash
cargo run -p oxidase-cli -- check examples/basic-gateway/oxidase.yaml
cargo run -p oxidase-cli -- test examples/basic-gateway/oxidase.yaml
cargo run -p oxidase-cli -- explain examples/basic-gateway/oxidase.yaml \
  --request examples/basic-gateway/requests/home.yaml
cargo run -p oxidase-cli -- serve examples/basic-gateway/oxidase.yaml
cargo run -p oxidase-cli -- serve examples/basic-gateway/oxidase.yaml --watch
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

The v1alpha1 YAML boundary is strict: unknown and duplicate keys fail, aliases and
merge keys are unsupported, and imports/references are cycle checked. `check` and
`serve` use the same compiler and Site preparation path.

## CLI

```text
oxidase check <config>
oxidase serve <config>
oxidase explain <config> --request <request-file> [--listener <name>]
oxidase compile <config> --output <manifest.json>
oxidase test <config>
```

`compile` currently writes a deterministic inspection manifest, not a self-contained
binary runtime snapshot.

`serve --watch` watches imported configuration and compiled Site dependencies.
Reload compiles and prepares the complete candidate, prebinds new listeners, reuses
unchanged resources, and atomically commits only on success. Existing requests drain
on their pinned snapshot.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
```

The HTTP end-to-end tests bind ephemeral loopback ports. Sandboxed environments may
need permission to run those tests.

Architecture starts at [`ARCHITECTURE.md`](ARCHITECTURE.md). The v0.1 prototype is
described in [`docs/legacy/v0.1.md`](docs/legacy/v0.1.md) and remains available in
Git history.

Oxidase is licensed under the [MIT License](LICENSE).
