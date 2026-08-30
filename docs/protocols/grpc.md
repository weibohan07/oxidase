# Transparent gRPC proxying

Oxidase supports basic transparent gRPC when the downstream uses HTTP/2 and the
selected Cluster uses `protocol: h2`. Proxy forwards HTTP headers, DATA frames, end
of stream, and terminal trailers such as `grpc-status` and `grpc-message` without
parsing protobuf or rewriting gRPC message frames.

```yaml
resources:
  clusters:
    grpc:
      protocol: h2
      endpoints:
        - name: grpc-a
          url: https://grpc-a.example.test:8443

services:
  grpc:
    type: proxy
    cluster: grpc
```

The same streaming body adapters serve unary and server-streaming calls. Trailer
frames are not counted as body bytes. An upstream error after the response head is
a stream/body error; Oxidase cannot replace an already committed response with a
synthetic 502 and will not retry it.

Protocol-aware sanitization rejects HTTP/2 connection-specific headers. `TE` is
preserved only when its value is exactly `trailers`. User Gateway/Oxista headers
cannot bypass this rule.

Cross-version trailer behavior is explicit:

- H2 to H2 request and response trailers are preserved;
- HTTP/1 chunked request trailers can cross to H2;
- H2 response trailers can cross to an HTTP/1 client only when the request allows
  `TE: trailers` and the initial trusted upstream head declared every trailer name;
- an unsafe or undeclared late trailer ends the stream with a protocol error rather
  than being silently discarded.

Oxidase does not implement gRPC-Web, protobuf inspection, gRPC-aware routing,
message-level retries, service reflection, or special translation between
`grpc-status` and HTTP status.
