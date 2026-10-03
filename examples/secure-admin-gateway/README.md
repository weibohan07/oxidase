# Authenticated local control-plane example

This example is alpha software. Every token and signing key here is **test-only,
publicly known, and unsuitable for production**. The operator key is the Ed25519
RFC 8032 test vector, supplied solely to make the signed example reproducible.

Create the private parent directory before serving. It must belong to the server
account and must not be group/world writable. Replace the fixed example paths
and credentials when adapting this configuration to a deployment.

```sh
mkdir -m 700 /tmp/oxidase-admin-example
cargo run -p oxidase-cli --locked -- serve examples/secure-admin-gateway/oxidase.yaml
```

In another terminal, use the compiled binary (or prepend `cargo run -p
oxidase-cli --locked --` to each command):

```sh
target/debug/oxidase ctl --unix /tmp/oxidase-admin-example/admin.sock \
  --token-file examples/secure-admin-gateway/tokens/test-only-admin.token status

target/debug/oxidase bundle build examples/secure-admin-gateway/candidate-a.yaml \
  --output /tmp/oxidase-admin-example/a.oxb
target/debug/oxidase bundle sign /tmp/oxidase-admin-example/a.oxb \
  --key examples/secure-admin-gateway/keys/test-only-operator.key

target/debug/oxidase ctl --unix /tmp/oxidase-admin-example/admin.sock \
  --token-file examples/secure-admin-gateway/tokens/test-only-admin.token \
  --idempotency-key example-stage-a stage /tmp/oxidase-admin-example/a.oxb
```

Use the stage response's `digest` for `validate`, `activate`, and `rollback`.
Build and sign `candidate-b.yaml` in the same way. Then execute:

```sh
target/debug/oxidase ctl --unix /tmp/oxidase-admin-example/admin.sock \
  --token-file examples/secure-admin-gateway/tokens/test-only-admin.token validate DIGEST
target/debug/oxidase ctl --unix /tmp/oxidase-admin-example/admin.sock \
  --token-file examples/secure-admin-gateway/tokens/test-only-admin.token \
  --idempotency-key example-activate-a activate DIGEST
target/debug/oxidase ctl --unix /tmp/oxidase-admin-example/admin.sock \
  --token-file examples/secure-admin-gateway/tokens/test-only-admin.token history
target/debug/oxidase ctl --unix /tmp/oxidase-admin-example/admin.sock \
  --token-file examples/secure-admin-gateway/tokens/test-only-admin.token operation status OPERATION_ID
target/debug/oxidase ctl --unix /tmp/oxidase-admin-example/admin.sock \
  --token-file examples/secure-admin-gateway/tokens/test-only-admin.token rollback DIGEST
target/debug/oxidase ctl --unix /tmp/oxidase-admin-example/admin.sock \
  --token-file examples/secure-admin-gateway/tokens/test-only-admin.token reload-source
target/debug/oxidase ctl --unix /tmp/oxidase-admin-example/admin.sock \
  --token-file examples/secure-admin-gateway/tokens/test-only-admin.token drain
```

`ctl` normally reads the current revision ETag before a mutation. For an operator
without `read` permission, supply the complete, quoted ETag explicitly:

```sh
target/debug/oxidase ctl --unix /tmp/oxidase-admin-example/admin.sock \
  --token-file examples/secure-admin-gateway/tokens/test-only-admin.token \
  --if-match '"runtime-EPOCH-REVISION"' --idempotency-key CONTROLLED_KEY \
  --connect-timeout 5s --timeout 60s activate DIGEST
```

Keep the original ETag and idempotency key after a lost response. A proven replay
returns that operation's committed revision alongside the current revision;
it does not silently refresh a stale precondition or republish an old snapshot.

The Admin bootstrap remains fixed while A/B data-only Bundles replace the data
plane. History exposes retained artifacts, and rollback revalidates external
Secret/private-key files. Drain leaves Admin available and readiness false.

The automated, actual CLI/server demonstration uses ephemeral addresses and
temporary credentials:

```sh
cargo test -p oxidase-cli --test admin_ctl_real_server --locked -- --nocapture
```

That test runs build/sign/stage/validate, A/B activation, history, rollback,
operation query, source reload, drain, and explicit-revision mutations without
read permission. It does not depend on this example's fixed data port.
