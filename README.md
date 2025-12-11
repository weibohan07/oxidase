# Oxidase

English | [简体中文](README.zh.md)

Oxidase is a lightweight HTTP gateway built on Rust / Tokio / Hyper, supporting route matching, rewrites, reverse proxying, and static file serving.

## CS 128 Honors Project

> **Group Name**: Oxidase (group-15)
>
> **Group Members**: albertw5, vtyou2

## TL;DR

With just a handful of lines of config you can spin up the following!

- **Static service (`Static`)**: Safely launch a static site or file server from any folder. Evil paths get filtered automatically! Options include directory strategy, `index` / `404` pages, and more.
- **Reverse proxy service (`Forward`)**: Forward requests to upstream HTTP(S) and return whatever the upstream returns. Options like `pass_host` strategy, `X-Forwarded` controls, etc.
- **Programmable routing pipeline service (`Router`)**:
  - The whole pipeline is rule-driven, and each rule can capture variables from headers while matching (see **Pattern**).
  - After a rule matches, you can branch based on the captured header variables.
  - Leaf nodes of the branch tree can edit headers (and can use captured variables, see **Template**), return an error page directly, or delegate to other services.
  - You can set a fallback service that takes over when rules are exhausted.

We also have these exciting features:

- **Config imports**: Any field that needs a `Service` object can read that service from another file via `import: ./foo.yaml`.
- **Multiple instances**: A config can contain multiple `HttpServer` objects. If a `name` field is provided, you can start one by name with `--pick`.
- **Live config watching**: Use the `--watch` flag to watch config changes in real time.

## Quick start

```bash
cargo build --release
./target/release/oxidase -c config.yaml
```

Say we want to start a service on one port; we can specify an `HttpServer` object in the config file.

An `HttpServer` object has `bind`, `service`, and an optional `name` field—`bind` is a string for the bound port; `service` is the bound service, a `Service` object; `name` assigns a name so you can start it individually with `--pick`.

```yaml
# config.yaml
bind: "127.0.0.1:7589"
service:
  handler: static
  source_dir: "./public"
```

When the config grows more complex, consider splitting some `Service` objects into separate files.

```yaml
# main.yaml
bind: "127.0.0.1:7589"
service:
  import: "./service.yaml"

# service.yaml
handler: static
source_dir: "./public"
```

We can also list multiple `HttpServer` objects directly in the config file; by default, all of them start.

```yaml
# config.yaml
servers:
  - name: web
    bind: "0.0.0.0:7589"
    service:
      import: "./service_web.yaml"
  - name: api
    bind: "0.0.0.0:7588"
    service:
      handler: forward
      target:
        scheme: http
        host: "localhost"
        port: 3000
```

## CLI options

- `-c, --config <FILE>`: Start one or more services from a full config file.
- `-f, --service-file <FILE>`: Start a service from a config file that only contains `Service`, together with `--bind`.
- `-i, --service-inline <YAML/JSON>`: Start a service from inline `Service` config, together with `--bind`.
- `-b, --bind <ADDR>`: Bind address/port when only a `Service` config is provided (default `127.0.0.1:7589`).
- `-p, --pick <NAME>`: From multiple `HttpServer` objects in the config file, start the one with the specified name.
- `-v, --validate-only`: Validate config only; do not start services.
- `-w, --watch`: Watch config changes and restart services automatically.

## Config structure

- **HttpServer**
  ```yaml
  name?: (string)
  bind: (string)
  tls?: (TlsConfig) # WIP
  service: (ServiceRef)
  ```
- **ServiceRef**
  ```yaml
  # Inline
  handler: static | forward | router
  ... # options for the specific service

  # Or import from another file
  import: (./path/to/service.yaml)
  ```
- **Service**
  - **Router**
    ```yaml
    handler: router
    rules: ([RouterRule...])
    next?: (ServiceRef)
    max_steps?: (u32)
    ```
  - **Forward**
    ```yaml
    handler: forward
    target:
      scheme: http | https
      host: (host)
      port: (u16)
      path_prefix: (path)
    pass_host: incoming | target | custom{(host)}
    x_forwarded?: bool
    tls?: ... # WIP
    timeouts?: ... # WIP
    http_version?: ... # WIP
    ```
  - **Static**
    ```yaml
    handler: static
    source_dir: (string)
    file_index: (string)
    file_404?: (string)
    file_500?: (string) # WIP
    evil_dir_strategy?:
      if_index_exists?: serve_index | redirect{(u16)} | not_found
      if_index_missing?: redirect{(u16)} | not_found
    index_strategy?: serve_index | redirect{(u16)} | not_found
    ```
- **RouterRule**
  ```yaml
  when?: (RouterMatch)
  ops: ([RouterOp...])
  on_match?: stop | continue | restart
  ```
- **RouterMatch**
  ```yaml
  scheme?: http | https
  host?: (pattern)
  path?: (pattern)
  methods?: ([(GET | POST | ...)])
  headers?:
    - { name: (string), pattern: (pattern), not?: (bool) }
    - ...
  queries?:
    - { key: (string), pattern: (pattern), not?: (bool) }
    - ...
  cookies?:
    - { name: (string), pattern: (pattern), not?: (bool) }
    - ...
  ```
- **RouterOp**
  - Request header rewrites:
    - `set_scheme`
    - `set_host`
    - `set_port`
    - `set_path`
    - `header_set/add/delete/clear`
    - `query_set/add/delete/clear`
  - Control flow:
    - `branch { if, then, else }`
    - `internal_rewrite`
  - Final actions:
    - `redirect { status, location }`
    - `respond { status, body?, headers? }`
    - `use { (ServiceRef) }`

## Patterns (`Pattern`) and templates (`Template`)

For example, suppose we're configuring a `Router` service and want to rewrite a friendly URL like `https://docs.example.com/rust/oxidase-web-server.html` into `http://192.168.12.34:5678/index.php?blog=docs&category=rust&post=oxidase-web-server` and forward it to an upstream PHP service.

We can write the config below:

```yaml
# config.yaml
bind: "0.0.0.0:443"
service:
  handler: router
  rules:
    - when:
        scheme: https
        host: '<blog_name:label>.example.com'
        path: '/<category_slug:slug>/<post_slug:slug>.html'
      ops:
        - set_scheme: http
        - set_host: "192.168.12.34"
        - set_port: 5678
        - set_path: 'index.php?blog=${blog_name|url_encode}&category=${category_slug|url_encode}&post=${post_slug|url_encode}'
    - ... # other rules
  next:
    handler: forward
    target:
      scheme: http
      host: "192.168.12.34"
      port: 5678
```

HTTPS-related functionality is still under development, so real-world use can't handle HTTPS requests yet—this is just a demo.

In this case you can see that with the powerful pattern and template engines, it's easy to capture variables from the request headers and use them in subsequent header rewrites.

### Pattern syntax

- **Context**: `host` / `path` / `value`, matches the whole field, no substring search.
- **Placeholders**:
  - Structural: `<:label>/<:labels>` (DNS label), `<:seg>` (single path segment), `<:any>` (greedy match of the rest).
  - Types: `<:uint/int/slug/hex/uuid>`.
  - Custom: `<:regex(...)>` (restricted subset to avoid catastrophic backtracking).
  - If there's a name before the colon, a capture is created and can be referenced in templates.
- **Restricted regex notes**: Only safe literals/character classes/finite quantifiers and non-capturing groups are allowed, with whole-field anchoring by default; compiled per context (e.g., label rules under host).

### Template syntax

- **Form**: `${var | filter(...) | filter2}`, filters applied left to right.
- **Variables**: `method/scheme/host/port/path`, `header.<Name>` (case-insensitive), `query.<key>`, `cookie.<name>`, plus named captures from patterns.
- **Filters**: `default(x)`, `lower/upper`, `url_encode`, `trim_prefix(x)/trim_suffix(x)`, `replace(a,b)`; missing variables expand to an empty string.

## Runtime and concurrency

Oxidase runs on a multi-threaded Tokio runtime.

## Development

- Tests: `cargo test` (or module-level like `cargo test cli`).
- Main modules:
  - `config` (parsing / validation / `import`)
  - `build` (runtime construction)
  - `handler` (`router` / `forward` / `static`)
  - `pattern`
  - `template`
  - `cli`

## Roadmap

- [ ] HTTPS support.
- [ ] Better hot reload support.
- [ ] Forward upstream HTTPS/HTTP2, TLS.
- [ ] Better observability and logging (structured logs, metrics).

## Contributing

This project is open-sourced under the [MIT License](LICENSE).

This project uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

Please write tests when contributing.
