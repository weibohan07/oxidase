# Diagnostics

Oxidase diagnostics are emitted at the CLI boundary after configuration and
resource preparation. The machine-readable schema is currently alpha, but every
document includes the explicit version `oxidase.diagnostics/v1`.

Select the renderer consistently on commands that compile or prepare source:

```bash
oxidase check config.yaml --diagnostic-format human
oxidase check config.yaml --diagnostic-format json
oxidase compile config.yaml --output manifest.json --diagnostic-format json
oxidase test config.yaml --diagnostic-format json
oxidase serve config.yaml --diagnostic-format json
```

`human` is the default. It writes failures to standard error and keeps the existing
human success output on standard output. `json` writes one complete diagnostic
document to standard output, never ANSI or human progress. Operational tracing and
non-fatal reload rejection remain on standard error. A command that reports an
error still exits nonzero.

The JSON envelope is:

```json
{
  "schema_version": "oxidase.diagnostics/v1",
  "diagnostics": [
    {
      "code": "service.reference",
      "severity": "error",
      "message": "referenced Service does not exist",
      "primary": {
        "file": "oxidase.yaml",
        "file_encoding": "utf-8",
        "field_path": "listeners[0].service.ref",
        "start": { "byte": 120, "line": 7, "column": 12 },
        "end": { "byte": 127, "line": 7, "column": 19 }
      },
      "labels": [],
      "related": [],
      "notes": [],
      "help": null,
      "reference_chain": []
    }
  ]
}
```

Byte positions are zero-based and end-exclusive. Lines and columns are one-based;
columns count Unicode scalar values rather than UTF-8 bytes. Paths under the input
configuration directory are rendered relative to it and use `/` separators. Other
paths remain explicit. `file_encoding` is `utf-8` unless a platform path required a
lossy display conversion, in which case it is `utf-8-lossy`.

Diagnostics are sorted by rendered file, start byte, end byte, code, and message.
Secondary labels, related definitions, and reference-chain edges retain compiler
order so an import or include chain remains readable. Compilation and preparation
carry this structure internally; they do not encode related locations into the
message string.

Successful `check`, `compile`, and `test` commands in JSON mode emit the same
envelope with an empty `diagnostics` array. Successful `explain` continues to emit
its explain document; only its failures use the selected diagnostic renderer. A
long-running `serve` emits operational events on standard error and emits a single
diagnostic envelope on terminal success or failure.
