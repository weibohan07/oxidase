# Oxista architecture

Oxista is the compiled Site Service and response-document subsystem.

- `.oxsite` is the one root manifest for a site resource.
- `.oxr` defines the HTTP response for one public logical resource.
- `.oxt` is a pure body-template module with no direct public URL.

Site preparation canonicalizes the root, validates the manifest and typed inputs,
scans assets and sources once, compiles response documents and templates, checks
their static dependency graph, and publishes an immutable `SiteSnapshot`. Requests
perform an indexed lookup; they do not parse YAML, discover candidate files, or
compile templates.

Gateway and all three Oxista formats use the same strict source parser. The accepted
subset allows block mappings and flow sequences, including quoted template text,
but rejects duplicate keys, anchors, aliases, merge keys, custom tags, tab
indentation, and flow mappings with line/column diagnostics. A parsed field must
either have implemented semantics or be rejected. In particular, this alpha only
accepts canonical trailing-slash behavior and 404 error templates; redirect query
replacement, JSON OXT output, and unsupported deny-glob shapes fail with migration
guidance.

The public index excludes manifests, response sources, templates, dotfiles,
underscore-private directories, denied paths, and symlink escapes. When an OXR and
sibling asset coexist, only the OXR-controlled logical resource is public; the asset
remains an indexed backing object so range and conditional response paths can stay
streaming.

An `AssetPlan` contains complete identity, Brotli, and gzip
`AssetRepresentation` records. Each representation owns its path, byte length,
content-derived ETag, and modification time; compressed validators are never made by
suffixing an identity ETag. Request processing selects the representation first,
then applies its metadata, then evaluates validators, and only then handles
If-Range/Range. `If-None-Match` uses weak comparison and takes precedence over
`If-Modified-Since`. A 304 retains ETag, Last-Modified, Vary, Cache-Control, and the
selected Content-Encoding while sending no body.

`Accept-Encoding` supports `br`, `gzip`, `identity`, `*`, and q-values. Equal
qualities use the stable preference Brotli, gzip, identity. Malformed parameters
make that coding unacceptable. A Range request selects identity; single, suffix,
and open-ended ranges plus ETag/date If-Range are supported. Multipart ranges are
explicitly rejected with 416 and `Content-Range: bytes */length`.

Templates receive typed, read-only namespaces (`request`, `bindings`, `site`, and
`page`). Includes are static and resolved at compile time. HTML output autoescapes
ordinary strings. Oxista has no network, database, shell, arbitrary filesystem, or
Service-dispatch capability.

OXT `output: html` defaults to HTML autoescape and
`text/html; charset=utf-8`; `output: text` defaults to no autoescape and
`text/plain; charset=utf-8`. Dynamic external-template arguments are evaluated and
validated against the declared parameter contract immediately before rendering.
The `url` type means an absolute URL. `safe_html` is rejected until the shared Value
model can carry trusted provenance; arbitrary strings never bypass autoescape.
Structured OXR JSON is the supported JSON output path.
