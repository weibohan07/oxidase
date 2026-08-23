# Oxista architecture

Oxista is the compiled Site Service and response-document subsystem.

- `.oxsite` is the one root manifest for a site resource.
- `.oxr` defines the HTTP response for one public logical resource.
- `.oxt` is a pure body-template module with no direct public URL.

Site preparation canonicalizes the root and builds one `SiteSourceIndex` before
compilation. Each ordinary or precompressed file is streamed through SHA-256 once;
the index retains canonical/source path, kind, length, modification metadata, and
digest. `.oxsite`, `.oxr`, and `.oxt` text is retained for compilation, while large
Asset bytes are not. The same digest records drive Site reuse and representation
ETags, so compilation never re-reads a file already indexed. The compiler then
validates typed inputs, compiles response documents and templates, checks their
static dependency graph, and publishes an immutable `SiteSnapshot`. Requests perform
an indexed lookup; they do not parse YAML, discover candidate files, or compile
templates.

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
content-derived ETag, and modification time. Strong tags use
`"sha256-<64 lowercase hex>"` over exactly that representation's bytes; weak mode
adds the standard `W/` prefix. Equal bytes at different paths therefore have equal
validators, while identity, Brotli, and gzip bytes are independent. Compressed
validators are never made by
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

Templates receive typed, read-only public roots (`request`, `bindings`, `site`,
`resource`, and `page`) plus persistent lexical scopes for external arguments,
`for`, `with`, and include arguments. Public roots cannot be shadowed. Includes use
this static grammar:

```django
{% include "_templates/card.oxt" %}
{% include "_templates/card.oxt" with item=item show_author=true %}
{% include "_templates/card.oxt" with item=item only %}
```

The path is a compile-time quoted string, argument names are bindings, values are
normal Expressions, duplicates are rejected, and `only` is optional and trailing.
Preparation resolves the target DAG and rejects missing/unknown arguments, missing
required parameters, constant type mismatches, and cycles. Runtime evaluates dynamic
arguments, validates their actual types, and pushes a child-only scope. A normal
include inherits caller lexical scopes before the explicit argument scope; `only`
starts again from public roots. Either form drops the child scope on return, and the
child uses its own effective output/autoescape settings. HTML output autoescapes
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
One shared `RenderBudget` is used across nested includes. An expression or loop body
is charged before execution, include depth is checked before entry, and output size
is checked before append. At limit N exactly N operations/bytes are allowed; N+1
fails without executing or writing the extra operation. Cooperative render-time
checkpoints run at every corresponding boundary.

The shared YAML parser retains original text and key/value byte ranges. Gateway
semantic lowering, OXR Header policy, and OXT interpolation/tag/include diagnostics
render exact ranges, including CRLF and Unicode columns; include-cycle diagnostics
list the source position of each resolved edge. Some other deeper Oxista
front-matter semantic errors still report the containing source rather than an exact
scalar and remain an alpha diagnostic limitation.
