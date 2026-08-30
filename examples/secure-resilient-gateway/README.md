# Secure resilient gateway example

This example compiles an HTTPS Listener with HTTP/2 and HTTP/1.1 ALPN, a
weighted Cluster with active/passive health, bounded admission, explicit safe
retry, an observed route, and an Oxista Site.

Validate both configurations without binding sockets:

```bash
cargo run -p oxidase-cli --locked -- \
  check examples/secure-resilient-gateway/oxidase.yaml
cargo run -p oxidase-cli --locked -- \
  test examples/secure-resilient-gateway/oxidase.yaml
cargo run -p oxidase-cli --locked -- \
  check examples/secure-resilient-gateway/fixture-upstream.yaml
```

The files under `certs/` are test-only, publicly known certificate material.
They are committed solely so validation and examples are reproducible. Never use
this certificate or private key for a real service.

`fixture-upstream.yaml` describes two local H2-only HTTPS fixture listeners. To
exercise live proxying on a disposable test machine, map `rsa.example.test` to
`127.0.0.1` and trust the test certificate only in that isolated environment.
Run the fixture and gateway in separate processes. This repository does not modify
host resolution or trust stores automatically.
