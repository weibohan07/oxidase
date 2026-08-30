# Service algebra

A Service is a program node with an independent request-processing boundary. Its
result is exactly one of:

- `Handled(response)`: a response was deliberately produced, regardless of status.
- `Declined`: the Service does not apply and consumed no irreversible request state.
- `Failed(error)`: the Service was applicable but could not complete.

Terminal Services are `Respond`, `Redirect`, `Site`, and `Proxy`. Wrapper Services
are `Transform`, `Observe`, `Timeout`, `RequestBodyLimit`, `ConcurrencyLimit`,
`RateLimit`, and `Recover`. Composition Services are `Route`, `Fallback`, and the
explicitly budgeted `Reenter` operation. Router is a source-level convenience
lowered into these nodes, never a privileged executor.

The compiled node table is one immutable `ServiceGraph` shared by every listener
program view through `Arc`. A request copies only its entry ID and shared graph
handle; graph cost is not proportional to the total node count. Inline Service and
Route identities are derived from a compiler-owned canonical source-file identity
plus semantic field path, so equal paths in separate imports cannot collide.
Duplicate generated IDs are compiler errors rather than map overwrites.
Generated inline Service/Route IDs are deterministic inspection identities within
one compiled source program. The source ordinal can change when the import set
changes, so these alpha IDs are not durable API keys, long-lived metric labels,
stable configuration references, or control-plane protocol identifiers.

`Fallback` tries the next candidate only after `Declined`. `Recover` is the only
generic mechanism that turns selected failures into another Service execution.
`Route` evaluates predicates into local captures, commits the complete match into a
child lexical scope, and discards that scope on exit.

Each execution frame combines immutable original request metadata, a scoped request
overlay, lexical bindings, explicit body state, and frame-local lazy views. Unchanged
frame clones share cached effective Headers, decoded query, request namespace, and
visible bindings. `with_bindings` replaces only the bindings/evaluation cache;
opening a mutable Transform overlay gives the child a new request-view cache. A
declined or failed child therefore cannot publish cached mutations back to its
parent. Scheme, authority, and
path-and-query replacements are parsed into `http` typed values. Only `http` and
`https` schemes are accepted; authorities reject userinfo and invalid ports; paths
must remain origin-form. Constant rewrites fail during compilation and dynamic
rewrites fail as `InvalidState` before a child runs. Consequently these programs
are different:

```text
Fallback(Transform(A, Site), Proxy)
Transform(A, Fallback(Site, Proxy))
```

In the first form a declined Site cannot leak `A` into Proxy. In the second, `A`
intentionally applies to both candidates. Response transformations run after child
execution and therefore wrap every handled descendant.

Normal execution uses a no-op trace sink and does not allocate explain event/detail
strings per Service node. Explain and declarative tests explicitly select the
structured collector while executing the same graph and leaf boundary.

Production observation is a separate executor boundary. Only an explicit `Observe`
wrapper starts an `ExecutionObserver` scope. The scope ends when its child returns
`Handled` (including status class), `Declined`, or `Failed` (including error class),
and nested wrappers preserve depth. Its latency is service-to-response-head: it does
not claim to measure delivery of a streaming body. Timeout cancellation closes the
scope through an RAII guard. The server independently wraps the final `GatewayBody`
to count emitted bytes and classify completion, body error, idle timeout, or client
cancellation without collecting the stream.

The three ingress-governance wrappers preserve the same outcome algebra:

- `RequestBodyLimit` carries an immutable lexical byte ceiling to its descendant;
  nested wrappers take the minimum. A known oversized Content-Length produces a
  handled 413 before the child. A body-consuming leaf enforces unknown-length bodies
  as DATA frames flow. The limit is not committed into `RequestFrame`, so a Declined
  or Failed branch cannot expose it to a Fallback sibling. A post-response-head
  overflow terminates the stream instead of fabricating a new response.
- `ConcurrencyLimit` acquires before child execution and body consumption. Saturated,
  full-queue, or queue-timeout admission produces its configured handled rejection;
  it never becomes `Declined`. For `Handled`, the permit becomes part of the
  server-local response-body or trusted-tunnel plan and remains held through the
  streaming lifecycle. Every other outcome releases on scope exit.
- `RateLimit` evaluates a prepared bounded token bucket before child execution. Its
  only keys are the normalized transport peer IP or a named lexical scalar binding.
  Rejection is a handled 429 with bounded `Retry-After`; missing/invalid keys and
  exhausted key-map capacity fail closed rather than creating a global/unbounded
  identity map. Actual keys are neither Service identity nor metric labels.

Concurrency and rate state live in the snapshot's governance registry, separate from
the immutable node graph. Concurrency state reuses its compiler-owned Service
identity across compatible reloads so active old-snapshot bodies/tunnels remain
counted. Rate state additionally requires an identical key/rate/burst/capacity/idle
policy. Listener connection admission has a different lifetime and belongs to the
retained socket; it is not another Service outcome or hidden graph node.

After the root returns `Handled`, a single protocol finalizer removes hop-by-hop and
untrusted framing metadata, derives safe lengths, and enforces body rules for HEAD,
1xx, 204, 205, and 304. A response status such as 404 remains handled; finalization
does not change the `Handled`/`Declined`/`Failed` algebra.

Site template output/loop/include-depth/expression-step/render-time budget failures
enter the algebra as `Failed(TemplateLimit)` and can be selected by `Recover`.
Template evaluation, argument-contract, and response-metadata failures are
`Failed(InvalidState)`; concrete asset file I/O remains `Failed(SiteIo)`. Internal
detail stays in diagnostics and is never copied into the safe client response.

Root failures use a fixed public mapping; the internal detail is logged but never
rendered into the client body:

| Error class | Default HTTP status | Safe client body |
| --- | ---: | --- |
| `UpstreamConnect`, `UpstreamProtocol` | 502 | `Bad Gateway` |
| `UpstreamUnavailable`, `UpstreamOverloaded` | 503 | `Service Unavailable` |
| `Timeout` | 504 | `Gateway Timeout` |
| all other classes | 500 | `Internal Server Error` |

`Recover` may intercept any of these classes before the root mapping. Cluster
selection with no eligible endpoint uses `UpstreamUnavailable`; exhausted
cluster/endpoint concurrency capacity uses `UpstreamOverloaded`. Those two
conditions are distinct from a selected endpoint failing to connect or violating
the upstream protocol.

Proxy remains one terminal Service even when its Cluster applies load balancing,
health eligibility, bounded admission, or retry. Those are runtime properties of a
prepared Resource, not extra Service outcomes or hidden fallback branches. A retry
can occur only before the downstream response head and under the Cluster's explicit
method/cause/body contract; it never turns into `Declined`. Exhausting eligible
endpoints yields `Failed(UpstreamUnavailable)`, while admission exhaustion yields
`Failed(UpstreamOverloaded)`.

Predicates in v0.3 inspect only the request head. A body-consuming Service marks the
body irreversible; Fallback after such a candidate remains rejected. Explicit
bounded Proxy replay is scoped to retries inside that Proxy leaf and does not make
the body globally replayable or allow Fallback to advance.
