# Oxidase v0.2 vision

Oxidase is a declarative HTTP Service program compiler and runtime written in Rust.
Users build a request-processing graph from terminal, wrapper, and composition
Services. Listeners attach network traffic to graph roots. A separate resource
registry owns reusable sites, clusters, connection pools, certificates, and future
shared capabilities.

Configuration is source, not a data structure interpreted on every request. The
compiler resolves imports and references, rejects invalid programs, compiles all
executable expressions, lowers convenient Router syntax, prepares resources, and
produces an immutable and explainable `RuntimeSnapshot`. Publication is atomic.

The first release concentrates on the Service algebra and Oxista: a compiled,
side-effect-free site and response-document system. It deliberately excludes a web
UI, distributed control plane, arbitrary scripts, native plugins, HTTP/3, and full
v0.1 compatibility.

