# Localport Wire Protocol

Binary control protocol between the agent and an edge server. The same framed
messages ride over one of two TLS 1.2+ carriers, both terminating on the edge
HTTPS port (`:443`) and selected by ALPN after a single TLS handshake:

- **`localport-raw/1`** carries the framed bytes directly inside the TLS stream.
  Lowest overhead.
- **`localport-ws/1`** wraps the framed bytes in binary WebSocket frames
  (HTTP/1.1 upgrade at `/v1/control`). Traverses DPI and HTTPS-inspecting proxies.

The **multiplexed data plane** is not a third ALPN. The agent opens a second
connection over whichever carrier above the control connection already
established, sends a `MuxBind` frame as its first message, and from there the
connection speaks HTTP/2: the edge opens one stream per inbound visitor
connection instead of asking the agent to dial back. Because it reuses the
working carrier, it survives the same firewalls the tunnel does. It is an
optimisation: an edge that does not accept the bind, or `--no-mux`, leave the
tunnel working over dial-back.

The agent runs one tunnel per config endpoint, and each tunnel opens its own
control connection and its own mux, bound to that tunnel's session. A mesh set up
as several same-token endpoints therefore gets one connection pair per device, so
the devices stay independent, rather than sharing a single connection across
every tunnel.

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
| MuxBind         | 11  | C → E     | Attach a multiplexed data conn   |
| MuxBindAck      | 12  | E → C     | Mux bind result                  |

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
  "subdomain": "optional",
  "resume_session_id": "optional"
}
```

`resume_session_id` echoes the `session_id` from this tunnel's previous
`RegisterAck`. When it matches a live session on the edge, that stale session
is replaced in place, so a reconnect after a network drop is instant on
every tunnel kind. It is held in memory only (empty on first connect and after an
agent restart) and ignored by older edges. On single tunnels a valid
registration without a resume match still replaces the sole existing client
(newest-wins); shared/mesh tunnels never replace without a resume match.

### RegisterAck (2)

```json
{
  "success": true,
  "tunnel_id": "tun_xxx",
  "tunnel_name": "my-api",
  "region": "eu",
  "region_name": "Europe",
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
  },
  "session_id": "hex32"
}
```

`region_name` is the server-supplied display name for the region; when empty
(older edges) the agent falls back to a built-in mapping, then the uppercased
slug. New regions therefore render correctly without an agent update.

`session_id` is an edge-minted secret for this session; present it as
`resume_session_id` on the next `Register` for this tunnel to reclaim the
slot immediately on reconnect. A session replaced this way receives a
non-retryable `Shutdown` with code `TU012`, so two agents sharing one token
cannot kick each other in a loop (the replaced one stops).

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

Both sides send a heartbeat every 30 s on the control connection and ack the
peer's. The edge treats a control connection with NO inbound frame for ~75 s
(two missed heartbeats plus margin) as dead and deregisters the client, so a
silently dropped link (wifi loss, sleep, NAT rebind) is reaped within ~75 s
even though the socket never errors. A live agent's own 30 s heartbeat (or
its ack of the edge's) always resets that window.

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
  "edge_addr": "e1.eu.localport.dev",
  "edge_id": "edge-eu-1",
  "reason": "rebalance"
}
```

`edge_addr` is a per-edge hostname (served by the platform's own NS); port
defaults to 443 when omitted. The agent dials the new address verbatim and
derives the SNI from the TARGET's zone (see Redirect under Reconnect Policy).

### MuxBind (11) / MuxBindAck (12)

```json
{
  "token": "<tunnel token>",
  "session_id": "<session_id from RegisterAck>",
  "client_id": "<same client id as Register>",
  "timestamp": 1735689600,
  "nonce": "<32 hex chars>"
}
```

Sent as the first frame on a second connection to the edge, over the SAME
carrier the control connection used (raw or WebSocket). No dedicated ALPN: the
frame type is what tells the edge this connection is a mux rather than a control
or data connection. It attaches that connection to a session already registered
on the control connection; the edge then opens one HTTP/2 stream per inbound
visitor connection instead of asking the agent to dial back.

The bind is authenticated in its own right, because it is dialed separately from
the control connection:

- `timestamp` and `nonce` are checked against the same replay window and the
  same store a Register uses, so neither frame can be replayed as the other.
- `token` proves which tunnel.
- `session_id` names which live client the streams belong to, compared in
  constant time.

All three are required. The token identifies a tenant but not which of its
clients; the session id on its own is a bearer credential.

A bind never takes over a session, never mints a new one and never registers a
tunnel. It attaches to a live session or is refused. Refusals are counted
against the same limiter as failed registrations and carry only a generic
reason, so the frame cannot be used to probe tokens or session ids.

```json
{ "success": false, "error": "...", "code": "..." }
```

A refusal is not fatal. The agent keeps serving over dial-back, which is also
what happens when the edge does not accept the bind, or when the connection
later dies. Because the mux reuses the control connection's carrier rather than
a carrier of its own, it reaches the edge on exactly the networks the tunnel
already reaches it on. `--no-mux` skips the attempt entirely.

Streams carry opaque bytes, exactly as a dialed-back connection did, so the same
mechanism serves every tunnel type: http, tcp, tls, and both the primary and the
secondaries of a shared tunnel. The visitor's address travels in the
`Localport-Visitor-Addr` header on each stream, replacing the field NewConnection
carried.

An agent that does not bind a mux connection is fully supported and receives
NewConnection for every inbound connection as before. The edge decides per
connection: a stream when the agent has a live mux, a dial-back otherwise. So an
older agent, `--no-mux`, a refused bind and a mux that dies mid-session all keep
working, and a mux that dies is simply not used for the next connection.

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
`"service temporarily unavailable"`. The agent learns only that the service is
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
| Plan limit                | plan limit reached, upgrade to continue        | no        |
| Resource limit            | resource limit reached                         | no        |
| Client limit              | client connection limit reached                | no        |
| Tunnel limit              | tunnel limit reached                           | no        |
| Tunnel terminated/deleted | tunnel terminated by an administrator          | no        |
| Session replaced          | replaced by a newer session for this tunnel    | no        |
| Protocol / clock          | protocol error, update the agent ...           | no        |

Certificate / mTLS failures on a data connection surface at the TLS handshake
layer, not as control-plane frames: a consumer either presents an acceptable
client certificate or the connection is refused.

### Retry policy

1. The `retryable` field on `RegisterAck` / `Shutdown` is authoritative.
2. When `retryable` is unset, the agent retries a `Shutdown` and gives up on
   a failed `RegisterAck`.
3. Unknown / opaque codes never change behavior; the agent relies on
   `retryable` and `limit_type` only.
4. Backoff is exponential (1.5×), capped at 30 s, with ±25 % jitter. The
   per-transport dial budget also escalates with consecutive failures
   (2 s doubling to 16 s) so high-latency links (2G, satellite) can
   complete the TLS handshake; an explicit dial-timeout setting is used
   verbatim.
5. Dead-link detection is symmetric: the agent treats a control connection
   with no inbound frame for ~75 s (the edge heartbeats every 30 s) as dead
   and reconnects, even when the socket never returns an error.
   A detected host network change (interface or address churn) additionally
   fires an immediate probe heartbeat; if nothing arrives within ~5 s of the
   probe the session reconnects, so a connection orphaned by a network
   switch recovers in seconds. TCP connections cannot survive an address
   change, so in-flight proxied connections on the old network close and
   visitors retry over the re-established tunnel.
   Wake from sleep is detected the same way via a wall-clock jump check
   (~10 s cadence): after sleep the socket is presumed stale even when the
   address set is unchanged, so the wake fires the same probe and a
   suspended laptop's tunnel is serving again within seconds of lid-open.
6. When a previously assigned edge address keeps failing for ~90 s, the
   agent falls back to the originally configured connect host, which
   resolves to healthy edges only. A routine edge restart finishes well
   inside that window and restores the session (and any assigned port) on
   the same edge; a permanently lost edge costs at most that window before
   the tunnel returns on a replacement edge.

### Redirect

The edge may answer a `Register` with a `Redirect` pointing at another edge -
a per-edge hostname like `e1.eu.localport.dev` (tunnels are pinned to one edge
inside a shared region zone). The agent follows up to 5 hops before giving up,
and only to hosts under the platform base domain.

SNI is derived per dial from the address being dialed: the original connect
host is used verbatim; a redirect target (`e1.eu.localport.dev`) gets the
target zone's connect host, i.e. the target's first label replaced with the
configured connect label (`connect.eu.localport.dev`). Post-redirect
reconnects and data dial-backs present the same derived SNI. An explicit
`--server-name` override always wins. Reasons:

1. The edge demuxes agent traffic by SNI: only `connect.<region-zone>` (and
   `connect.<its-own-hostname>`) reach the agent handler; any other SNI is
   treated as tunnel traffic. A cross-region redirect therefore needs the
   target zone's connect host, not the original one (which the target edge
   would treat as unknown tunnel traffic and close).
2. The edge serves the region-zone wildcard cert (`*.<region-zone>`), which
   covers `connect.<region-zone>` but NOT `connect.<per-edge-hostname>` (two
   labels deep), so the derived SNI must sit one label under the target
   zone. The dial address itself stays the per-edge hostname, which resolves
   directly to the pinned edge (no extra DNS indirection).
