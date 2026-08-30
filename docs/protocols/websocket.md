# HTTP/1 Upgrade and WebSocket proxying

Oxidase transparently carries WebSocket and other validated HTTP/1.1 Upgrade
traffic through a `Proxy` Service. It validates the downstream handshake, forwards
it through the HTTP/1 upstream pool, requires a matching upstream `101 Switching
Protocols`, then copies upgraded bytes bidirectionally without parsing WebSocket
frames.

The capability is private to the server data plane. `Respond`, OXR, and Transform
cannot create a trusted 101 or preserve Upgrade headers. Both sides must name one
valid matching Upgrade protocol and include `Connection: upgrade`; arbitrary
CONNECT is rejected.

Once upgraded, the connection task owns the tunnel, its byte counters, and the
request's pinned snapshot. A normal reload retains the tunnel. Listener retirement
allows it to continue within the configured drain window, then aborts it at the
deadline. Closing either peer cancels the opposite copy direction, and active
counts are released on completion, error, cancellation, or forced drain.

The same path works over a cleartext or TLS HTTP/1 downstream. Upstream Upgrade is
forced through the reusable HTTP/1 pool regardless of the Cluster's normal auto
policy.

Metrics expose only configured Listener names and fixed directions/termination
reasons. Upgrade protocol strings, paths, peer addresses, and application bytes are
not labels.

HTTP/2 extended CONNECT (RFC 8441), HTTP/2 WebSocket, arbitrary CONNECT tunneling,
h2c Upgrade, and WebTransport are not implemented.
