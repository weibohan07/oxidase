# Secret resources

Oxidase v0.4 introduces a narrow file-backed Secret Resource. This is an alpha
interface and does not by itself provide a Secret manager or an authorization
system.

## Configuration

```yaml
api_version: oxidase.dev/v1alpha1
kind: gateway

resources:
  secrets:
    admin-token:
      file: /run/secrets/oxidase-admin-token
      max_bytes: 64KiB
```

`file` is required. Relative paths resolve from the source file that declares the
Resource. `max_bytes` is optional, defaults to `64KiB`, and must be greater than
zero. Inline secret values are not supported.

The file contents are exact opaque bytes. Oxidase does not trim a final newline,
decode text, or normalize whitespace. If another system writes a token with a final
newline, that newline is part of the Secret and comparisons must include it.

## Preparation and reload

Every candidate snapshot checks that the path is a readable regular file and reads
at most `max_bytes + 1` bytes to detect concurrent growth. A missing path,
non-regular file, read failure, or size overflow rejects the candidate. The current
last-known-good snapshot remains active.

On Unix, Oxidase opens file-backed resources nonblocking and verifies the file type
both before and after open. A FIFO/device or a path swapped to one during preparation
therefore fails instead of blocking the reload compiler worker. Symlink-based atomic
file rotation remains supported.

The declared path participates in reload dependency tracking. A content change is
prepared as a new Secret; unchanged validated bytes can reuse the current prepared
Resource. The live runtime `ConfigVersion` does not contain the deterministic Secret
fingerprint. It uses an opaque per-prepared-Secret token so a low-entropy Secret
cannot be tested against a published version digest.

On Unix, a mode that permits group or other access produces a warning. Use ownership
appropriate to the Oxidase process and mode `0600` (or a stricter equivalent) when
possible. Permission checks are advisory because non-Unix platforms have different
access-control models.

## Redaction and memory handling

Prepared Secret Debug, Display, and Serialize output is always `<redacted>`. Secret
contents and paths are omitted from inspection-safe snapshot summaries; contents are
not emitted through diagnostics, metrics, or tracing. The path remains present in
the operator-authored configuration and in the private watcher dependency set.

Clones share a single allocation. The final owner zeroizes that allocation on drop,
and partial read buffers are zeroizing from their first byte. This is best-effort
memory hygiene only. Oxidase cannot erase copies in the operating system,
filesystem cache, allocator, swap, crash dumps, or code outside the Secret wrapper.

The comparison API avoids data-dependent early exit for equal-length inputs; input
length is observable. Do not describe this as a general-purpose cryptographic
protocol or as protection against every timing channel.

## Current scope

Secret resources are deliberately not ordinary expression or template values. This
prevents accidental interpolation into Headers, responses, logs, or metric labels.
The current alpha establishes the file-backed Resource and redaction/rotation
boundary; future control-plane consumers must use purpose-specific APIs.

Not implemented: inline Secrets, environment-variable Secrets, cloud/KMS providers,
encrypted Secret files, automatic token generation, or portable cross-platform
permission enforcement.
