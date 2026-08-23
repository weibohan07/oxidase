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
plus literal/folded block scalars with chomping or indentation indicators. Scalar
contents are opaque to the strict feature scan. The subset rejects duplicate keys,
anchors, aliases, merge keys, custom tags, tab indentation, and flow mappings with
line/column diagnostics. A parsed field must
either have implemented semantics or be rejected. In particular, this alpha only
accepts canonical trailing-slash behavior and 404 error templates; redirect query
replacement, JSON OXT output, and unsupported deny-glob shapes fail with migration
guidance.

The public index excludes manifests, response sources, templates, dotfiles,
underscore-private directories, denied paths, and symlink escapes. `visibility.deny`
is compiled into exactly three case-sensitive forms: an exact relative path (which
also denies that directory subtree), `**/name` for a complete matching path
component and its subtree, and `**/*.ext` for a final filename ending in that exact
extension. Absolute paths, `..`, empty components, backslashes, and other glob
syntax are rejected. When an OXR and
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
make that coding unacceptable. Single, suffix, and open-ended bytes ranges plus
ETag/date If-Range are supported for GET. Multipart ranges are
ignored, as are unknown units and malformed bytes ranges. HEAD ignores Range and
If-Range but still negotiates the complete representation and validators. A valid
single range selects identity only when acceptable; with `identity;q=0`, Range is
ignored so an acceptable complete compressed representation can be selected. Only
a valid but unsatisfiable single bytes range returns 416 with
`Content-Range: bytes */length`.

Response policy preserves layer order: global defaults, logical extension defaults,
profiles in declaration order, then local OXR. Each layer runs remove, set, add.
Ordinary assets and OXR-backed assets use the same logical extension (never `.br`,
`.gz`, or `.oxr`) for `defaults.by_extension`.

Templates receive typed, read-only namespaces (`request`, `bindings`, `site`, and
`page`). Includes are static and resolved at compile time. HTML output autoescapes
ordinary strings. Oxista has no network, database, shell, arbitrary filesystem, or
Service-dispatch capability.

OXT `output: html` defaults to HTML autoescape and
`text/html; charset=utf-8`; `output: text` defaults to no autoescape and
`text/plain; charset=utf-8`. An omitted external OXT output/autoescape inherits the
Site template defaults before the output-derived fallback is applied; explicit OXT
metadata wins. A configured 404 template must be callable with no required
arguments, renders with an empty page namespace plus normal request/site/bindings
context, uses its effective Content-Type, and receives `defaults.response` headers
without extension policy. Dynamic external-template arguments are evaluated and
validated against the declared parameter contract immediately before rendering.
The `url` type means an absolute URL. `safe_html` is rejected until the shared Value
model can carry trusted provenance; arbitrary strings never bypass autoescape.
Structured OXR JSON is the supported JSON output path.

Template rendering returns structured limit, evaluation, missing-value, and
argument errors. Only output, loop, include-depth, expression-step, and render-time
budget failures become the public `TemplateLimit` Service error class; other Site
render failures remain `InvalidState`, and clients receive a generic safe error.
