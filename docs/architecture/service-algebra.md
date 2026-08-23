# Service algebra

A Service is a program node with an independent request-processing boundary. Its
result is exactly one of:

- `Handled(response)`: a response was deliberately produced, regardless of status.
- `Declined`: the Service does not apply and consumed no irreversible request state.
- `Failed(error)`: the Service was applicable but could not complete.

Terminal Services are `Respond`, `Redirect`, `Site`, and `Proxy`. Wrapper Services
are `Transform`, `Observe`, `Timeout`, and `Recover`. Composition Services are
`Route`, `Fallback`, and the explicitly budgeted `Reenter` operation. Router is a
source-level convenience lowered into these nodes, never a privileged executor.

`Fallback` tries the next candidate only after `Declined`. `Recover` is the only
generic mechanism that turns selected failures into another Service execution.
`Route` evaluates predicates into local captures, commits the complete match into a
child lexical scope, and discards that scope on exit.

Each execution frame combines immutable original request metadata, a scoped request
overlay, lexical bindings, and explicit body state. Consequently these programs are
different:

```text
Fallback(Transform(A, Site), Proxy)
Transform(A, Fallback(Site, Proxy))
```

In the first form a declined Site cannot leak `A` into Proxy. In the second, `A`
intentionally applies to both candidates. Response transformations run after child
execution and therefore wrap every handled descendant.

Predicates in v0.2 inspect only the request head. A body-consuming Service marks the
body irreversible; fallback after such a candidate requires a future explicit
replay plan and is rejected in the meantime.

