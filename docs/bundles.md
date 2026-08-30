# Portable Bundles

An Oxidase Bundle (`.oxb`) is a deterministic deployment artifact with schema
`oxidase.bundle/v1`. It contains stable program/resource metadata and, optionally,
Asset bytes. It is not a serialization of the Rust runtime and it never contains a
Secret value or certificate private key.

This feature remains alpha. Keep the original source and build provenance, verify
every artifact before activation, and do not assume that future alpha runtimes can
load a Bundle with capabilities they do not advertise.

## Select the Asset mode

The optional top-level source policy is:

```yaml
bundle:
  assets:
    mode: embed
```

The mode is `embed` when the complete `bundle` block is absent. The accepted values
are:

| Mode | Artifact | Load-time dependency |
| --- | --- | --- |
| `embed` | Asset representations are content-addressed blobs inside the `.oxb` | Bundle file only, plus sensitive runtime references |
| `reference` | Asset descriptors contain a path, expected SHA-256 digest, and length | Every referenced Asset must exist and match |

Only one `bundle` block may occur across a Gateway import graph. Unknown fields,
unknown modes, and duplicate blocks are compile errors with source spans.

Embedded blobs are stored as raw seekable byte ranges. Equal bytes are deduplicated,
and ordinary Asset responses remain streaming, including single-range requests.
Identity, Brotli, and gzip representations remain separate descriptors with their
own bytes and validators. Building a Bundle does not collect an ordinary large
Asset into one allocation. Path-based readers and writers use fixed 64 KiB buffers;
the owned in-memory parser/builder is reserved for bounded small artifacts, tests,
and fuzzing.

Referenced paths are either absolute or relative to an explicit deployment root.
They are never URLs. Loading verifies the regular file, expected length, and full
SHA-256 content digest before activation. A mismatch rejects the whole candidate and
leaves last-known-good active.

Each unique reference representation is streamed into its own anonymous verified
spool before activation. Replacing the source path or rewriting its original inode
therefore cannot change a live snapshot. Reference mode keeps the artifact small but
needs temporary disk for the referenced bytes while that snapshot is alive; use
`embed` when the artifact itself must carry those bytes.

## Build, inspect, and verify

The Bundle CLI provides:

```bash
oxidase bundle build oxidase.yaml --output gateway.oxb
oxidase bundle inspect gateway.oxb
oxidase bundle verify gateway.oxb
oxidase bundle diff old.oxb new.oxb
oxidase serve --bundle gateway.oxb --bundle-key release-2026.pub
```

Standalone activation is fail-closed when no trusted key is configured. Local
development may opt into an unsigned artifact explicitly with
`oxidase serve --bundle gateway.oxb --allow-unsigned-bundle`; that flag conflicts
with `--bundle-key` and is not a production policy.

`build` compiles Gateway and Oxista source once and writes a temporary sibling
artifact before atomically renaming the verified result. It records schema/tool
metadata, normalized program sections, diagnostic origins, public certificate
material, typed sensitive references, and Asset descriptors. It does not preserve
runtime-only sockets, connection pools, tasks, file handles, rustls configurations,
or Hyper values.

The output is rejected before a temporary file is created if it would overwrite a
Gateway/import dependency, public Asset, Certificate/Trust file, Secret or private
key reference. Output anywhere under a Site root is also rejected, preventing a
later build or source serve from ingesting the artifact as public content.

`inspect` reports schema, digest, capabilities, section and Asset summaries, build
metadata, and public resource information. Default output redacts Secret and
private-key reference paths. A verbose mode may expose non-secret deployment paths,
but never sensitive bytes.

`source_commit` is null for a normal local binary unless its build supplied a
proven 7-64 character lowercase hexadecimal `OXIDASE_BUILD_COMMIT`. Release and
packaging workflows should inject the real commit; Oxidase does not fabricate one
when provenance is unavailable.

`verify` checks the header, bounded lengths/counts, canonical encoding, aggregate and
blob digests, required capabilities, Asset references when applicable, and the
configured signature policy. Verification success does not mean referenced Secret
or private-key files are authorized for a later host; candidate preparation still
opens and validates them.

`diff` compares stable identities and reports changed sections, Assets, public
resources, and runtime-reference identities. It never reads or prints Secret bytes.

JSON diagnostics are available through the same global diagnostic-format option as
other CLI operations.

## Format and identity

The container starts with magic `OXB\0\r\n\x1a\n`, format version 1, flags, unsigned
and signature lengths, and a 32-byte domain-separated SHA-256 content digest, all fixed-width numeric
fields in network byte order. The canonical manifest uses ordered JSON with a
restricted stable value model.
Floating-point values use an explicit tagged IEEE-754 bit representation instead
of raw JSON numbers; unknown executable semantics are not accepted. Blob
records are sorted by 32-byte SHA-256 digest. The complete unsigned canonical
container has one `BundleDigest`, rendered as 64 lowercase hexadecimal characters.

The manifest declares:

- `oxidase.bundle/v1`;
- the minimum compatible runtime;
- Gateway and Oxista schema versions;
- required features;
- optional metadata;
- versioned program/resource sections;
- content-addressed Assets;
- source origins;
- typed sensitive runtime references.

Listener and non-Site Resource plans live in the stable
`oxidase.gateway-config/v1` section. The loader reparses socket addresses, endpoint
URLs, HTTP methods and statuses, protocol policy, SNI, client authentication,
durations, and cross-resource references before it creates compiler IR. Service
graphs and Site snapshots are independent sections, and the Site section identities
must exactly match the Gateway section's expected `site_ids`.

Filesystem references carry an explicit `absolute` or `deployment_root` base.
Source-root-relative paths use normalized `/` components and are rebound only to a
deployment root supplied by the loader. The current working directory is never an
implicit path base. Empty paths, `.`, `..`, backslashes, NUL, roots, and prefixes in
a deployment-root reference are rejected.

A runtime must fail when it does not understand a required feature or required
section. It may ignore unknown optional metadata. This prevents a new Service,
policy, or security requirement from becoming accepted-but-inert on an older
runtime. Minimum and actual runtime versions use strict semantic-version parsing;
invalid version text and an older runtime are distinct verification failures.

The bundle digest is deterministic for the same normalized inputs. It does not
include the build wall clock, random values, checkout-root paths, Secret contents,
or private keys. Source-origin display paths are normalized for reproducibility
rather than recording an absolute temporary build directory.

Filesystem modification time is a deliberate input only when a Site enables
`assets.last_modified` (the current default), because the Bundle must preserve the
wire `Last-Modified` validator. Reproducible builders must therefore normalize or
preserve Asset mtimes as well as bytes. Set `last_modified: false` when content-only
identity is desired; then mtime is omitted from the Site plan and fingerprint.

## Signing and key rotation

Signatures use an `oxidase.bundle.signatures/v1` envelope. Each record contains a
key identifier, the Ed25519 algorithm name, and a signature over
`oxidase.bundle.signature/v1\0` followed by the complete canonical Bundle digest.
The signing key is an
offline file argument, not a Gateway Secret Resource and not Bundle content.

Typical operations are:

```bash
oxidase bundle sign gateway.oxb --key release-signing-key
oxidase bundle verify gateway.oxb --key release-2026.pub
```

Verification may be configured with several public keys during rotation. Attaching
another valid signature does not change the unsigned deployment digest. Unknown
keys do not count as trusted signatures, and malformed or invalid signatures reject
the candidate. The secure Admin API requires a trusted signature by default;
standalone local use must make any unsigned policy explicit.

Signing-key files are limited to 4 KiB and contain a raw 32-byte Ed25519 seed, raw
64-byte keypair, or lowercase hexadecimal equivalent. Verification keys are raw 32
bytes or 64 lowercase hexadecimal characters. The current CLI derives the key ID as
the first 32 hexadecimal characters of the public-key SHA-256 digest. Verification
accepts any recognized valid key during an intentional multi-key rotation.

Keep the signing private key outside the source tree, Bundle output directory, and
runtime host whenever possible. Oxidase does not provide a software-key vault or
hardware-security-module integration in this alpha.
`bundle sign --output` rejects the signing-key path and any symlink alias before it
opens the output; omitting `--output` still permits the intended atomic in-place
replacement of the Bundle itself.

## Secrets, keys, and certificates

The artifact carries public certificate chains and CA material directly. Their
source filesystem paths are not executable Bundle fields; only normalized source
spans remain for diagnostics. It carries a typed runtime file reference only for:

- Secret Resources;
- certificate private keys.

The referenced files are reopened during candidate preparation, bounded and type
checked through the same Resource implementation as source startup. A missing,
oversized, invalid, or mismatched sensitive file rejects activation. No Secret
content digest is available through inspect, diff, diagnostics, logs, or metrics.

Candidate preparation also compares every public Site Asset representation with
every Secret and certificate private-key file. Canonical paths are checked on all
platforms, and Unix device/inode identity additionally catches symlink and hardlink
aliases. A file cannot be both a sensitive runtime reference and an identity,
Brotli, or gzip Site representation; the diagnostic names only the resource and
Site, never the sensitive path, digest, or bytes.

Consequently, copying an `.oxb` alone is not enough to move a gateway that depends
on TLS keys or Secrets. Provision those files separately with least privilege and
the same atomic-rotation discipline described in the operations guide.

## Loading and activation

Loading is a candidate operation:

1. validate the fixed header and all declared bounds before allocation;
2. validate canonical metadata and complete content digest;
3. verify the signature policy;
4. negotiate every required capability and section schema;
5. verify referenced Asset content;
6. load sensitive runtime references;
7. rebuild process-local compiled objects;
8. prepare listeners and resources without publication;
9. atomically commit the immutable snapshot.

Failure at any step leaves the current snapshot untouched. Existing requests,
streams, and tunnels keep their pinned snapshot; new work observes the newly
activated one only after commit. A path-backed load streams the verified complete
Bundle into an anonymous temporary spool and pins that handle for embedded Asset
slices. Replacing the input path or modifying its original inode after verification
therefore cannot alter a live snapshot. This keeps memory bounded but requires up to
the encoded Bundle size in temporary disk space. In `reference` mode, add the total
size of the unique referenced representations copied into snapshot-owned spools;
those copies remain allocated for the snapshot lifetime. Production activation
should still store artifacts by immutable content digest for auditability and
cleanup.

## Limits and untrusted input

A Bundle must be treated as untrusted input even when it has a familiar filename.
The default v1 ceilings are 8 GiB for the file and aggregate blob bytes, 32 MiB for
the manifest, 4 MiB for signatures, 4 GiB for one blob, 100,000 blobs, 1,000,000
Assets, 1,000,000 origins, 4,096 stable sections, and 100,000 sensitive references.
Canonical JSON is additionally limited to depth 128, 1,000,000 nodes, and 16 MiB per
string. The loader rejects truncation, trailing data, duplicate blobs, length
overflow, digest mismatch, non-canonical metadata, and unknown required semantics
before publication.

A signature authenticates the signed digest and key policy; it does not make
referenced filesystem paths safe by itself. Continue to use a trusted deployment
root, safe file ownership, and the Admin candidate-store restrictions.

## Known limitations

This alpha has no encrypted Bundle, remote registry/fetch protocol, incremental
delta format, archive compression, online key service, HSM integration,
transparency log, or cross-version migration promise beyond declared capability
negotiation. A Bundle is not a portable executable snapshot and cannot preserve
live connections, Cluster health, rate-limit buckets, or other process state.
