# Inbound HTTP versions

Oxidase has one Hyper data plane for cleartext HTTP/1.1 and TLS ALPN-selected
HTTP/1.1 or HTTP/2. Services and immutable runtime snapshots are shared by both
drivers; HTTP/2 is not a second execution model.

## Version selection

A cleartext listener defaults to HTTP/1.1:

```yaml
listeners:
  - name: public-http
    bind: 0.0.0.0:8080
    protocol: http
    http:
      versions: [http1]
    service:
      ref: public
```

Cleartext `h2` is rejected with `listener.h2c_unsupported`; h2c and HTTP/1.1 Upgrade
to h2 are not implemented.

An HTTPS listener defaults to `[h2, http1]` and advertises enabled versions through
ALPN in configured order:

```yaml
listeners:
  - name: public-https
    bind: 0.0.0.0:8443
    protocol: https
    tls:
      default_certificate: public
    http:
      versions: [h2, http1]
      http1:
        header_read_timeout: 30s
      http2:
        max_concurrent_streams: 256
        max_header_list_size: 64KiB
        keep_alive_interval: 30s
        keep_alive_timeout: 10s
    service:
      ref: public
```

`versions: [h2]` and `versions: [http1]` are supported for HTTPS. At least one
version is required; duplicates fail compilation. A settings block for a disabled
version is rejected instead of being silently ignored.

Defaults are:

| Setting | Default |
| --- | ---: |
| `http1.header_read_timeout` | `30s` |
| `http2.max_concurrent_streams` | `256` |
| `http2.max_header_list_size` | `64KiB` |
| `http2.keep_alive_interval` | `30s` |
| `http2.keep_alive_timeout` | `10s` |

Counts, byte sizes, and durations are validated before publication.

## Snapshot and connection lifecycle

The TLS handshake captures one immutable transport plan for the connection. Service
execution does not pin that connection to one old runtime snapshot: each HTTP/1
request or HTTP/2 stream pins the snapshot current when the request begins. An
already-started request keeps its snapshot, while a later stream on a retained
connection can observe a successfully reloaded Service program.

Listener retirement stops accepts and requests graceful shutdown. HTTP/1 idle
keep-alive closes promptly. HTTP/2 receives Hyper graceful shutdown/GOAWAY, stops
admitting new streams, and gives accepted streams the configured drain window.
Remaining connection and stream tasks are aborted only after that deadline.

## Metadata and telemetry

`request.http_version` is `"1.1"` or `"2"`. TLS requests also expose the negotiated
ALPN (`"http/1.1"` or `"h2"`) through `request.tls.alpn`.

The management metrics endpoint exports bounded series keyed by the statically
configured `listener` name and fixed result/protocol enums for:

- accepted and active connections with `protocol="http1|h2"`;
- TLS handshake result and duration;
- ALPN result from a fixed `http1|h2|none|other` set;
- active HTTP/2 streams;
- graceful or forced HTTP/2 shutdown.

An H2-only Listener classifies a client that omits ALPN as `alpn_required` and an
incompatible ALPN negotiation as `alpn_mismatch`; it never falls back to HTTP/1.1.

Request paths, query strings, SNI names, peer IPs, Header values, and certificate
paths are not labels.

## Current protocol limits

Request and response bodies remain streaming and are not collected merely because
HTTP/2 is selected. This alpha does not yet expose request/response trailers, basic
gRPC proxying, RFC 8441 extended CONNECT, HTTP/2 WebSocket, h2c, or HTTP/3. HTTP/1
generic Upgrade/WebSocket is also deferred to the protocol-bridging phase.
