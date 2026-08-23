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

The public index excludes manifests, response sources, templates, dotfiles,
underscore-private directories, denied paths, and symlink escapes. When an OXR and
sibling asset coexist, only the OXR-controlled logical resource is public; the asset
remains an indexed backing object so range and conditional response paths can stay
streaming.

Templates receive typed, read-only namespaces (`request`, `bindings`, `site`, and
`page`). Includes are static and resolved at compile time. HTML output autoescapes
ordinary strings. Oxista has no network, database, shell, arbitrary filesystem, or
Service-dispatch capability.

