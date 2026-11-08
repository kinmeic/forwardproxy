# UDP integration tests

Run with a Go workspace that includes both this module and the Caddy checkout
with all three patches applied (or use `scripts/build-udp-caddy.sh`):

```
GOWORK=/absolute/path/to/go.work go test -race ./integration
```

The test starts an actual HTTP/3 server with the pinned sagernet QUIC library.
It exercises the forwardproxy handler through Caddy's ResponseWriter wrapper.
Authentication, target ACL and quotas are part of the request path. Unlike a
Capsule-only test, a successful echo here requires working QUIC DATAGRAM frames.

`kinmeic/naiveproxy`'s `tests/udp.py` additionally tests the full compiled naive
client and patched Caddy executable, including TCP/Naive padding coexistence.
Linux CI executes both suites. On macOS, the old non-UDP tests require additional
127.x loopback aliases and may time out without them; the UDP suites use dynamic
ports and the normal loopback address.
