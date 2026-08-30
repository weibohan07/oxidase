# ADR 0011: Portable Oxidase Bundle

- Status: Accepted
- Date: 2026-08-30

## Context

Oxidase currently starts from strict Gateway and Oxista source files. Runtime
preparation deliberately creates process-local objects such as compiled regular
expressions, rustls configurations, Hyper clients, listener sockets, health
supervisors, semaphores, and file handles. Serializing those objects would couple a
deployment artifact to crate internals, platform details, dependency versions, and
memory layout. Requiring source YAML at the deployment host, however, also makes it
hard to review one exact candidate, sign it offline, transfer it safely, or activate
it atomically.

The Bundle boundary must preserve the existing compiler/runtime boundary: source is
parsed and lowered by the build command, while a runtime loading a Bundle rebuilds
only process-local compiled objects from a stable intermediate representation. It
must not reread Gateway or Oxista YAML. Secret bytes and private keys must never be
captured in the artifact.

## Decision

### Versioned, deterministic container

The portable artifact uses the `.oxb` suffix and declares schema
`oxidase.bundle/v1`. It is a purpose-built binary container, not Rust `bincode`, a
tar/zip archive, or a dump of a `RuntimeSnapshot`. Its fixed header identifies the
format version and lengths. The manifest and signature envelope use canonical JSON:

- object keys are ordered;
- floating-point values use an explicit IEEE-754 bit-pattern tag rather than a
  JSON number, preserving signed zero and non-finite payloads exactly;
- integer and string representations are deterministic;
- decoding and re-encoding must produce the original bytes;
- duplicate, out-of-order, truncated, trailing, and digest-mismatched content is
  rejected.

Determinism is defined over normalized semantic inputs, not bytes alone. When an
Oxista Site enables `assets.last_modified`, each selected representation's mtime is
part of the stable Site plan so Bundle serving preserves `Last-Modified`; build
systems seeking bit-for-bit output must fix or preserve those mtimes. With
`last_modified: false`, filesystem mtime is excluded from both the Site fingerprint
and Bundle. The build wall clock is never injected implicitly.

The fixed header is encoded in network byte order:

```text
magic             8 bytes: OXB\0\r\n\x1a\n
format_version    u16: 1
flags             u16
unsigned_length   u64
signature_length  u64
content_digest    32-byte SHA-256
```

The header is followed by the canonical manifest and raw blob payload, then an
independently canonical signature envelope. Unknown format versions or flags are
rejected. Every variable-length region is length-delimited and covered by explicit
aggregate limits before allocation. Blob payloads are raw byte ranges ordered by
their SHA-256 digest. The complete canonical unsigned content has a 32-byte SHA-256
`BundleDigest`, domain-separated with `oxidase.bundle.content/v1\0`. Bundle identity
does not depend on a checkout path, map insertion
order, wall-clock time, or random identifier. Build metadata records the Oxidase
tool version, source commit when supplied, and Gateway/Oxista schema versions, but
reproducible builds do not insert the current time.

`source_commit` is nullable for an ordinary local binary because Oxidase does not
invent provenance it cannot prove. Reproducible release/packaging workflows should
inject the actual 7-64 character lowercase hexadecimal commit through
`OXIDASE_BUILD_COMMIT`; safe inspection exposes either that verified value or null.

The stable manifest DTO contains only explicit string-tagged schemas and enums. It
does not encode Rust enum ordinals. It includes:

- build and schema metadata;
- required feature names and optional metadata;
- named stable sections containing the normalized Service program, Listener and
  Resource plans, compiled Pattern/Expression/Template representations, and Oxista
  metadata;
- source-origin records for diagnostics;
- public certificate chains;
- Asset descriptors and a content-addressed blob table;
- redacted runtime references for Secrets and certificate private keys.

The Gateway transport/resource section uses `oxidase.gateway-config/v1`. It stores
Listener HTTP/TLS/SNI/client-auth plans, Certificate/Secret/Trust Store references,
Cluster endpoints and every health/retry/admission/timeout policy, plus the expected
Site Resource IDs. Socket addresses, URLs, methods, status ranges, protocol names,
SNI rules, and resource references are text or integers and are reparsed and
cross-checked on load. Service graphs and Site snapshots have their own versioned
sections. The expected Site IDs must match those decoded Site sections exactly;
missing and unreferenced sections both fail.

Compiler-owned filesystem references are encoded as an explicit `absolute` or
`deployment_root` path reference. Source-relative references are normalized against
the supplied source root at build time and rebound only against an explicit
deployment root at load time; neither conversion consults the process current
directory. Source-origin paths use the same normalized display-root rule, which
keeps equivalent builds independent from an absolute checkout directory.

The loader recreates regular expressions, template evaluators, rustls settings,
connection pools, and all other process-local state during candidate preparation.
It never treats serialized Hyper, rustls, regex, pointer, or operating-system state
as trusted input.

### Source policy and imports

Gateway source may contain one packaging policy across the complete import graph:

```yaml
bundle:
  assets:
    mode: embed
```

`bundle.assets.mode` accepts exactly `embed` or `reference`. If the entire `bundle`
block is absent, the effective mode is `embed`. Multiple blocks in imported files
are rejected with both source locations; they are not merged by import order.
Unknown fields and values fail compilation. The effective mode and its source span
are compiled into Gateway IR and consumed by `oxidase bundle build`, so the field is
not accepted-but-inert.

### Assets

In `embed` mode, each final Asset representation is streamed into the writer and
addressed by its SHA-256 content digest. Equal bytes share one blob regardless of
logical path. The manifest records the blob digest and exact length. Blob bytes are
stored uncompressed so the normal Asset path can seek and stream a range directly
from the Bundle without loading or decompressing the whole archive. Container
metadata is small and bounded; large Asset bytes are never collected in one
allocation. Path-based Bundle reads and writes use fixed 64 KiB buffers. The owned
byte-vector parse/build APIs are intended for bounded small artifacts, unit tests,
and fuzzing, not the production large-file path.

In `reference` mode, the manifest records either an absolute path or a path relative
to an explicit deployment root, its expected SHA-256 digest, and length. Portable
paths use `/` separators. A deployment-root path must be nonempty and normalized;
`.`, `..`, a leading root, a platform prefix, backslash, and NUL are rejected.
Candidate preparation resolves the path without allowing traversal outside the
selected base, requires a regular file, streams the file digest, and refuses
activation on any mismatch. A reference is an integrity-checked deployment
dependency, not permission to fetch a URL or interpret an arbitrary URI.
Every unique verified reference is copied into an anonymous temporary spool used by
the published snapshot, so later path replacement and same-inode writes cannot
change served bytes. This trades artifact size for temporary disk proportional to
the referenced representations kept by the snapshot.

Both modes preserve identity, Brotli, and gzip as distinct representations with
their own digest, length, and HTTP validator metadata. Neither mode introduces
default full-body buffering.

### Sensitive and public TLS material

Secret contents and certificate private-key bytes are forbidden in every Bundle
section and blob. The manifest carries only typed runtime references:

```text
Secret      -> configured file reference plus bounded-read policy
Private key -> configured runtime file reference
```

Inspection redacts those paths by default, and no digest of Secret contents is
stored. Candidate preparation rereads and validates sensitive files through the
existing Secret/Certificate resource boundaries. Their failure preserves
last-known-good.

Certificate chains and CA certificates are public material and are included in
stable resource sections. Their source paths are omitted from executable stable IR
because the loader never rereads those files; normalized source spans remain for
diagnostics. A private key is still matched to the included leaf at load time before
activation. Bundles therefore do not become key-delivery or Secret distribution
containers.

### Capability negotiation

The manifest includes `minimum_runtime_version`, a set of named required features,
and versioned stable sections. A runtime rejects:

- an unknown Bundle schema;
- a runtime version below the declared minimum;
- any unknown required feature;
- any required section whose schema it cannot rebuild.

Both the declared minimum and the loader's runtime version are parsed as strict
semantic versions before comparison. Invalid text fails with
`bundle.invalid_runtime_version`; a valid but older runtime fails with
`bundle.runtime_too_old` before executable sections are rebuilt.

Unknown optional metadata may be ignored. This is intentionally asymmetric:
optional inspection annotations may evolve, but executable semantics may never be
silently dropped. Enum and feature names are stable strings rather than ordinal
positions.

### Signatures

Signing is detached from the unsigned canonical payload. A signature envelope has
schema `oxidase.bundle.signatures/v1` and contains one or more key-identified
Ed25519 signatures over `oxidase.bundle.signature/v1\0` followed by the complete
canonical `BundleDigest`. The signature section is not itself part of that digest,
so additional trusted signatures can be attached without rewriting the deployment
identity.

### Decoder limits

The v1 default limits are:

| Region or model | Limit |
| --- | ---: |
| Bundle file and aggregate blob bytes | 8 GiB |
| Manifest | 32 MiB |
| Signature envelope | 4 MiB |
| One blob | 4 GiB |
| Blob records | 100,000 |
| Asset records | 1,000,000 |
| Source-origin records | 1,000,000 |
| Stable sections | 4,096 |
| Sensitive references | 100,000 |
| Canonical JSON depth | 128 |
| Canonical JSON nodes | 1,000,000 |
| One JSON string | 16 MiB |

All length additions and conversions are checked before allocation or seek. These
are parser safety ceilings, not recommendations for normal artifact size.

The signing private key is read only by the offline `oxidase bundle sign` command.
It is never embedded in the Bundle or made a Gateway Resource. Verification accepts
multiple public keys for rotation and succeeds only when the configured policy is
satisfied by a recognized valid signature. Corrupt, non-canonical, unknown-key, or
invalid signatures fail before candidate preparation. Whether an unsigned Bundle is
accepted is an explicit runtime policy; the secure management control plane will
require a valid signature by default.

The standalone CLI is also fail-closed by default: activation requires at least one
trusted `--bundle-key`. `--allow-unsigned-bundle` is an explicit development-only
escape hatch and cannot be combined with trusted keys.

Key files are bounded to 4 KiB. An Ed25519 private key is a raw 32-byte seed, a raw
64-byte keypair, or the corresponding lowercase hexadecimal encoding. A verification
key is raw 32 bytes or 64 lowercase hexadecimal characters. If no key ID is supplied,
Oxidase derives one from the first 32 hexadecimal characters of the public-key
SHA-256 digest. This identifier selects a trust key; it is not a second signature.

### Loading and atomic activation

Open, structural validation, limit checks, canonical validation, content hashing,
signature verification, reference verification, and process-local reconstruction
all occur before publication. An immutable verified backing file remains pinned
while embedded Asset slices are served. For path-backed input, verification
streams the complete artifact into an anonymous temporary spool; the snapshot pins
that spool rather than the mutable source inode. This bounds memory and isolates
both atomic path replacement and same-inode rewriting, at the cost of temporary
disk space up to the encoded Bundle size. Production deployment still places a
Bundle at an immutable content-digest path for provenance and cleanup. Reference
mode additionally needs temporary disk equal to the unique referenced
representations retained by the snapshot. Activation uses the existing
prepare-before-commit transaction. A failed or partially written Bundle cannot
replace the current snapshot. Listener socket reuse, Cluster state compatibility,
old-snapshot pinning, and drain semantics remain unchanged.

Bundle creation writes a sibling temporary file, flushes it, and atomically renames
it into place only after final verification. The control plane applies its own
fsync, storage quota, and staging rules in addition to these format guarantees.
Before creating that sibling, the CLI rejects outputs under any Site root or aliases
of source dependencies, public Assets, Certificate/Trust files, Secrets, and private
keys.

## Consequences

- Operators can review, verify, sign, transfer, and activate one content-addressed
  candidate without shipping its Gateway/Oxista source tree.
- The stable representation is deliberately more work than serializing current IR,
  but crate refactors and dependency upgrades no longer define the artifact format.
- Embedded Assets produce a self-contained artifact and direct streaming reads;
  referenced Assets keep artifacts small but require an integrity-checked deployment
  root.
- Sensitive runtime files remain operational dependencies. A Bundle is portable
  only across deployments that provide those references.
- Bundle compatibility is explicit and fail-closed rather than best-effort.

## Rejected alternatives

- Rust `bincode`, `postcard`, or serde output of current IR would accidentally make
  crate layout and enum order a public wire format.
- Zip or tar would add archive traversal and decompression-bomb concerns and would
  not provide the exact seekable blob layout needed by streaming Assets.
- Embedding Secrets or private keys would turn every artifact copy, cache, and
  inspection tool into a secret store.
- Signing only the manifest would leave Asset blobs replaceable.
- Recompiling YAML while loading would make source dependencies and compiler drift
  part of runtime behavior and defeat reproducible artifact review.

## Current limitations

`oxidase.bundle/v1` is alpha and only targets runtime versions that explicitly
advertise all required features. There is no encrypted Bundle, remote Asset fetch,
delta/patch format, hardware-backed signer integration, transparency log, portable
executable snapshot, or promise that a Bundle works on a platform missing its
referenced files and supported runtime capabilities.
