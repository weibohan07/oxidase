# Migrating from Oxidase v0.1

v0.2 intentionally does not preserve the v0.1 source schema. The old `Static`,
`Forward`, and privileged `Router` handlers become ordinary Service composition and
separate resources.

| v0.1 concept | v0.2 form |
| --- | --- |
| `HttpServer.bind` | `listeners[].bind` |
| root handler | `listeners[].service` |
| `Static` | compiled Site resource plus `type: site` Service |
| `Forward.target` | Cluster resource plus `type: proxy` Service |
| Router `use` | nested or referenced child Service |
| Router `next` | Route `default` or `Fallback` |
| Router `respond` | `type: respond` |
| Router `redirect` | `type: redirect` |
| Router `set_*` | wrapper `type: transform` |
| Router `restart` | explicit budgeted `type: reenter` |
| `${value | filter}` | `{{ expression | filter }}` |
| shared captures | lexical `bindings.*` |

There is no automatic converter yet. Start by defining shared Site and Cluster
resources, translate terminal handlers, then rebuild routing from the outside in so
response Transform placement is explicit. Run `oxidase check`, add declarative
config tests, and inspect representative requests with `oxidase explain` before
serving traffic.

The v0.1 source remains available in Git history at and before public baseline
`cb9e86ab7b5ae0424c6cad0b0b3788ae54ca501a`.
