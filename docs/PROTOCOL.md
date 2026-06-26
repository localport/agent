# Localport Wire Protocol

Binary control protocol between the agent and an edge server. The same framed
messages ride over one of two TLS 1.2+ carriers, both terminating on the edge
HTTPS port (`:443`) and selected by ALPN after a single TLS handshake:

- **`localport-raw/1`** — framed bytes flow directly inside the TLS stream.
  Lowest overhead.
- **`localport-ws/1`** — framed bytes ride inside binary WebSocket frames
  (HTTP/1.1 upgrade at `/v1/control`). Traverses DPI and HTTPS-inspecting proxies.

The agent connects with SNI `connect.<edge-domain>`; the edge routes that SNI to
its agent handler and all other SNIs to tunnel traffic. The wire format below is
identical on either carrier.

## Frame format

```
[length:4 big-endian uint32][type:1 byte][payload:N bytes JSON]
```

- `length` covers the type byte plus the payload (`length = 1 + len(payload)`).
- `type` is a single `MessageType` byte (see the table below).
- `payload` is JSON-encoded. A frame with no body has `length=1`.
- Maximum frame size is **1 MiB**.

## Message types

| Name            | ID  | Direction | Purpose                          |
| --------------- | --- | --------- | -------------------------------- |
| Register        | 1   | C → E     | Authenticate and attach a tunnel |
| RegisterAck     | 2   | E → C     | Registration result              |
| NewConnection   | 3   | E → C     | Open a data channel              |
| ConnectionReady | 4   | C → E     | Data channel handshake complete  |
| Heartbeat       | 5   | both      | 30s keepalive                    |
| HeartbeatAck    | 6   | both      | Reply to Heartbeat               |
| SetActive       | 7   | E → C     | Active-role update               |
| Shutdown        | 8   | both      | Graceful disconnect              |
| Error           | 9   | E → C     | Server-side error                |
| Redirect        | 10  | E → C     | Reconnect to a different edge    |

## Payloads

### Register (1)

```json
{
  "token": "tok_xxx",
  "protocol": "http",
  "client_id": "agent-a1b2c3d4e5f6",
  "client_name": "hostname",
  "timestamp": 1711357200,
  "nonce": "hex32",
  "subdomain": "optional"
}
```

### RegisterAck (2)

```json
{
  "success": true,
  "tunnel_id": "tun_xxx",
  "tunnel_name": "my-api",
  "region": "eu",
  "public_url": "https://foo.tunnel.localport.dev",
  "urls": [
    "https://foo.tunnel.localport.dev",
    "http://foo.tunnel.localport.dev"
  ],
  "subdomain": "foo",
  "port": 0,
  "mode": "shared",
  "protocol": "http",
  "error": "",
  "error_code": "",
  "retryable": null,
  "limit_type": "",
  "mtls": {
    "enabled": true,
    "ca_fingerprint": "sha256:a1b2c3..."
  }
}
```

The `mtls` field is optional. When present with `enabled: true`, inbound
connections to the tunnel must present a client certificate signed by the tunnel's CA.
The agent prints the `ca_fingerprint` at connect time so consumers can verify the CA out of band.

### NewConnection (3)

```json
{ "connection_id": "conn_xxx", "remote_addr": "203.0.113.7:54321" }
```

`remote_addr` is the L4 peer (host:port) of the inbound connection as seen by the
edge. Agents surface it as the originating address in their live-connections view.

### ConnectionReady (4)

```json
{ "connection_id": "conn_xxx" }
```

### Heartbeat / HeartbeatAck (5, 6)

```json
{ "timestamp": 1711357200 }
```

### SetActive (7)

```json
{ "active": true }
```

### Shutdown (8)

```json
{
  "reason": "bandwidth limit exceeded",
  "code": "BL007",
  "retryable": false,
  "limit_type": "bandwidth"
}
```

`limit_type` values:

| Value                | Meaning                                          | Retryable |
| -------------------- | ------------------------------------------------ | --------- |
| `""`                 | Unspecified; fall back to the `code` field       | depends   |
| `bandwidth`          | Team hit its monthly bandwidth cap               | no        |
| `client_connections` | Too many concurrent clients across the team      | no        |
| `tunnel_count`       | Team hit its max tunnel count                    | no        |
| `no_plan`            | Team has no active paid or trialing subscription | no        |
| `blocked`            | Access blocked for this tunnel or team           | no        |

### Error (9)

```json
{ "code": "PR001", "message": "invalid protocol" }
```

### Redirect (10)

```json
{
  "edge_addr": "eu.localport.dev:4443",
  "edge_id": "edge-eu-1",
  "reason": "rebalance"
}
```

## Lifecycle

```
Agent                              Edge
  |---- TCP/TLS connect ---------->|
  |---- Register ----------------->|
  |<--- RegisterAck (or Redirect)--|
  |                                |
  |---- Heartbeat (every 30s) ---->|
  |<--- HeartbeatAck --------------|
  |                                |
  |<--- NewConnection -------------|
  |---- [new socket dial] -------->|
  |---- ConnectionReady ---------->|
  |<==== bidirectional data =====>|
  |                                |
  |<--- Shutdown ------------------|   (or initiated by the agent)
  |---- close --------------------->|
```

A data connection always rides its own freshly dialed socket; only the
initial control frame on that socket carries the matching `connection_id`.

## Error codes

The `error_code` (in `RegisterAck`) and `code` (in `Shutdown` / `Error`) fields
carry an **opaque, server-defined token**. The agent does NOT interpret it and
must not build behavior on specific values. It is surfaced verbatim so a user
can read it back to support: in the TUI it appears as a bottom-right border
capsule (`└────[ AT001 ]─┘`), and in `--noui` mode it is appended to the log
line as `[AT001]`. The set of codes and their internal meaning is private to
the server.

The authoritative, human-readable explanation is the sanitized `error` /
`reason` / `message` string the edge supplies, together with the structured
`retryable` and `limit_type` fields. Messages never reveal server internals.
Infrastructure problems are always reported generically as
`"service temporarily unavailable"` — the agent learns only that the service is
unavailable, never why.

Public message families an agent may surface:

| Situation                 | Example message                                | Retryable |
| ------------------------- | ---------------------------------------------- | --------- |
| Service unavailable       | service temporarily unavailable                | yes       |
| Invalid token             | authentication token is invalid                | no        |
| Invalid certificate       | client certificate is invalid                  | no        |
| Certificate required      | this tunnel requires a client certificate      | no        |
| Access denied             | access denied                                  | no        |
| Rate limited              | too many connection attempts, retry shortly    | yes       |
| Bandwidth limit           | bandwidth limit reached for this billing cycle | no        |
| Plan limit                | plan limit reached — upgrade to continue       | no        |
| Resource limit            | resource limit reached                         | no        |
| Client limit              | client connection limit reached                | no        |
| Tunnel limit              | tunnel limit reached                           | no        |
| Tunnel terminated/deleted | tunnel terminated by an administrator          | no        |
| Protocol / clock          | protocol error — update the agent ...          | no        |

Certificate / mTLS failures on a data connection surface at the TLS handshake
layer, not as control-plane frames: a consumer either presents an acceptable
client certificate or the connection is refused.

### Retry policy

1. The `retryable` field on `RegisterAck` / `Shutdown` is authoritative.
2. When `retryable` is unset, the agent retries a `Shutdown` and gives up on
   a failed `RegisterAck`.
3. Unknown / opaque codes never change behavior; the agent relies on
   `retryable` and `limit_type` only.
4. Backoff is exponential (1.5×), capped at 30 s, with ±25 % jitter.

### Redirect

The edge may answer a `Register` with a `Redirect` pointing at another edge.
The agent follows up to 5 hops before giving up.
