# UDP over QUIC

This branch implements authenticated MASQUE CONNECT-UDP over HTTP/3 with RFC
9297 HTTP Datagrams carried in RFC 9221 QUIC DATAGRAM frames. Each target has an
independent request stream and connected UDP socket; targets share the existing
QUIC connection. Business packets are not retransmitted in HTTP DATA streams.

## Build

Requires Git, Go 1.26+ and Linux or macOS. Run:

```
./scripts/build-udp-caddy.sh /absolute/path/to/caddy
```

The script checks out `CADDY_VERSION`, applies the BBR, read-idle-timeout and
CONNECT-UDP patches, builds a single Caddy executable and runs the Go race tests (the UDP subset on macOS, which lacks the legacy
127.x loopback aliases)
against that same source. Ordinary `xcaddy` without these patches does not enable
the required HTTP/3 datagram interface. To run tests in an existing patched source
checkout, put both modules in a temporary Go workspace and set `GOWORK` to it.

## Configuration

```
{
    order forward_proxy first
}
:443 {
    tls /path/to/fullchain.pem /path/to/key.pem
    forward_proxy {
        basic_auth user password
        udp
        hide_ip
        hide_via
        probe_resistance
        ports 53 443
    }
    file_server
}
```

`udp` is off by default and requires `basic_auth`. Existing ACL and `ports` rules
apply to UDP, including DNS results. `upstream` chaining is rejected when UDP is
enabled. Requests with invalid credentials follow existing probe-resistance
behavior before inspecting UDP capabilities.

For tuning, the handler's JSON `udp` object supports:

| Property | Default | Meaning |
| --- | --- | --- |
| `idle_timeout` | `120000000000` (120 s in nanoseconds) | Bidirectional business-packet inactivity; at least two minutes |
| `max_sessions` | 1024 | Active sessions in one handler, at most 4096 |
| `max_sessions_per_user` | 128 | Active sessions for one configured credential |
| `packets_per_second` | 2000 | Shared bidirectional packet rate per active user; burst equals this value |

There is also a process-wide 4096-session cap and a handler-wide setup limiter
of 100 sessions/second with burst 200. Quotas include requests still resolving
DNS. On close, debug logs contain duration, packet/drop counts and the reason;
credentials and UDP payloads are never included in those logs.

Both IPv4 and IPv6 targets are supported. Domains resolve at the server with a
bounded, cancelable lookup. The selected IP is checked and dialed directly, so
there is no second lookup between ACL validation and dial. Connected UDP accepts
only replies from that target. Source IP/port changes at a target are not relayed.

## Client

Use the corresponding `kinmeic/naiveproxy` `codex/udp-over-quic` branch:

```json
{
  "listen": "socks://127.0.0.1:1080",
  "proxy": "quic://user:password@proxy.example:443",
  "masque-udp": true
}
```

The local application must support SOCKS5 UDP ASSOCIATE. Ordinary HTTP proxy
configuration does not capture UDP. The SOCKS TCP control connection must stay
open while exchanging packets through the returned UDP endpoint.

## Packet size, compatibility and lifecycle

The peers negotiate Extended CONNECT and HTTP/3 DATAGRAM before sending UDP.
The client waits for handshake confirmation and for the successful tunnel
response. HTTP/2, HTTP/1.1, multi-hop UDP and 0-RTT UDP forwarding are excluded;
there is no silent direct or reliable-stream fallback. The server can parse
bounded peer Capsules for standards compatibility, but never sends business
packets as Capsules. Unknown Context IDs are discarded.

The available payload depends on outer QUIC packet size and path MTU. Oversized
packets are dropped without closing a healthy tunnel. The proxy configures DF /
no-fragment sockets on Linux and macOS. A 1200-byte inner QUIC Initial requires
more than 1200 bytes of outer capacity: not every path can carry it. There is no
application fragmentation extension. Datagram padding is not enabled; TCP Naive
padding remains independent. DATAGRAM capability advertisement changes the
connection's observable profile and does not establish browser equivalence.

FIN/RESET, cancellation, UDP socket errors and inactivity all close the socket,
cancel all relay tasks and release quotas. A disconnected client rebuilds a
per-target flow on a subsequent packet; queued data is not replayed on a new flow.

## Tests

`integration/udp_test.go` uses a real QUIC connection and DATAGRAM API, checks
empty payloads, multiple flows, auth/ACL rejection, credential casing quotas and
RESET cleanup. Core tests cover packet/URI boundaries, admission and socket DF.
The paired naive repository contains a real SOCKS UDP / Caddy integration runner.
