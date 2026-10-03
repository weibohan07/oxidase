# Local dynamic-discovery example

These alpha examples separate fixed HTTP/TLS identity from DNS-controlled physical
addresses. `oxidase.yaml` selects A/AAAA; `srv.yaml` selects SRV. Both import the
same observed Proxy, HTTPS/H2 Listener and test-only Trust Store. The copied,
publicly known RSA private key and `certs/test-only-rsa-ca.pem` are **test-only**;
never use them in production or install this trust anchor system-wide.

## Offline validation

From the repository root:

```sh
cargo run -p oxidase-cli --locked -- \
  check examples/dynamic-discovery-gateway/oxidase.yaml
cargo run -p oxidase-cli --locked -- \
  check examples/dynamic-discovery-gateway/srv.yaml
cargo run -p oxidase-cli --locked -- \
  test examples/dynamic-discovery-gateway/oxidase.yaml
cargo run -p oxidase-cli --locked -- \
  test examples/dynamic-discovery-gateway/srv.yaml
cargo run -p oxidase-cli --locked -- \
  explain examples/dynamic-discovery-gateway/srv.yaml \
  --request examples/dynamic-discovery-gateway/request.yaml
```

These commands do not send DNS questions, bind a Listener or choose a real
upstream. Explain's leaf response is symbolic: its status is not proof that an
upstream returned 200. The example nameserver `127.0.0.1:53530` and A/AAAA port
8444 are illustrative inputs, not required open test ports. Do not run the YAML
expecting an upstream to exist there.

The logical authority remains `rsa.example.test:8443`, with `/base/` as the base
path. SNI/verification remains `rsa.example.test` and trust is explicit. An A/AAAA
address, SRV target or SRV port cannot replace any of those identities. Loopback is
explicitly permitted **only for this local example**; the normal policy denies
loopback and link-local business targets. Each lease dials its approved numeric
address directly, without resolving the logical TLS/HTTP name again.

All attempts share `pre_response_total: 20s`, beginning before admission. Retry,
DNS generation changes and different addresses never restart that clock. Upload
and response-body idle clocks apply when the corresponding body is demanded;
the final chosen response head ends the pre-response total, not a long gRPC body.

## Real isolated DNS and upstream fixtures

The validation-only tool starts the **actual CLI gateway**, local UDP/TCP DNS and
TLS upstream fixtures as separate processes. It generates disposable TLS/signing
material and a bearer token, chooses ephemeral ports and writes its matching
`gateway.yaml`; it does not rely on the illustrative ports above, `/etc/hosts`,
public DNS, Docker, curl or OpenSSL. Run on Unix; Linux additionally supplies
gateway-PID RSS/FD samples. Choose fresh output subdirectories:

```sh
cargo build -p oxidase-cli -p oxidase-soak --release --locked
discovery_results=$(mktemp -d /tmp/oxidase-discovery-example.XXXXXX)
target/release/oxidase-discovery-soak run \
  --gateway target/release/oxidase --campaign discovery \
  --duration 10m --concurrency 8 --seed 600601 --reload-interval 3s \
  --payload-size 32768 --warm-up 30s --cooldown 120s --sample-interval 1s \
  --output "$discovery_results/address"
target/release/oxidase-discovery-soak run \
  --gateway target/release/oxidase --campaign protocol \
  --duration 2m --concurrency 6 --seed 600602 --reload-interval 3s \
  --payload-size 32768 --warm-up 30s --cooldown 120s --sample-interval 1s \
  --output "$discovery_results/protocol"
```

The address workload rotates A/B addresses, order, CNAME and UDP/TCP responses,
TTL zero, negative answers and transient failure while switching signed Bundles
and exercising health/retry. The SRV protocol workload supplies primary A at
priority 0 and backup B at priority 1, reverses answer order, uses target CNAME
chains and explicitly withdraws with target `.`. Health eligibility—not a full
admission queue—permits backup priority. Within one priority, SRV weights apply
to targets before the configured address-level load-balancing policy; multiple
IPs do not multiply one target's weight.

Both workloads retain raw results. The protocol proof holds old gRPC/Upgrade
work across member withdrawal and signed Bundle activation while new streams
must use the surviving actual peer. It verifies opaque DATA, gRPC trailers and
Upgrade bytes, then completes terminal drain through the existing authenticated
Admin operation. A campaign failure is an unsuccessful observation, not a reason
to discard its logs or claim a passing run. These commands document how to run;
actual run IDs, tested revisions and measurements live in the
[acceptance ledger](../../docs/verification/discovery-acceptance.md) and
[qualification procedure](../../docs/verification/discovery-qualification.md).

## Expiration, Bundle startup and publication

An A/AAAA family retains its own absolute expiry; SRV membership uses the minimum
of the service record, target address and intervening CNAME expirations. Only the
closed transient failure allowlist (timeout/network/SERVFAIL/REFUSED) can use an
already approved member until its original expiry plus `stale_if_error`. A new
failure cannot slide that deadline. NXDOMAIN withdraws the name; NODATA withdraws
the affected family; SRV target `.` withdraws the service. Policy rejection,
malformed or oversized results do not authorize stale resurrection.

Build and inspect either policy without any running fixture:

```sh
bundle_results=$(mktemp -d /tmp/oxidase-discovery-bundle.XXXXXX)
cargo run -p oxidase-cli --locked -- bundle build \
  examples/dynamic-discovery-gateway/srv.yaml \
  --output "$bundle_results/gateway.oxb"
cargo run -p oxidase-cli --locked -- bundle inspect "$bundle_results/gateway.oxb"
cargo run -p oxidase-cli --locked -- bundle verify "$bundle_results/gateway.oxb" \
  --deployment-root examples/dynamic-discovery-gateway
```

This unsigned offline verification checks structure/capabilities, not a trusted
signature. The test private key's bytes remain an external runtime reference,
never Bundle content. The explicit deployment root binds that reference at load
time. The live tool signs, verifies, stages, validates, activates and rolls
back artifacts through the normal control plane with its generated test key.
Bundle metadata includes fixed DNS/origin/TLS/address/timeout policy and required
capabilities, never live answers, health, pools, generation or an old expiry.
Restart is cold and waits for newly authorized resolution; it cannot trust an IP
that happened to be present at build time.

DNS changes never amend PublishedRuntime ETag, RuntimeOrigin, permissions,
CandidateStore history or durable recovery fencing. They cannot reopen a drained
Listener. Existing requests pin their program; removal prevents new leases and new
streams on an old member's pooled H2 connection. Explicit source reload, activation
or rollback remains subject to the fifth-stage authentication/CAS/publication
contract. This example does not introduce a DNS-cache mutation API or a new
publisher, and does not change workspace or API versions.
