# Localport Wire Protocol

Binary control protocol between the agent and an edge server. The same framed
messages ride over one of two TLS 1.3 carriers, both terminating on the edge
HTTPS port (`:443`) and selected by ALPN after a single TLS handshake:

- **`localport-raw/1`** carries the framed bytes directly inside the TLS stream.
  Lowest overhead. The agent tries it first.
- **`localport-ws/1`** wraps the framed bytes in binary WebSocket frames
  (HTTP/1.1 upgrade at `/v1/control`). Traverses DPI and HTTPS-inspecting
  proxies.

The **multiplexed data plane** is not a third ALPN. The agent opens a second
connection over whichever carrier above the control connection already
established, sends a `MuxBind` frame as its first message, and from there the
connection speaks HTTP/2: the edge opens one stream per inbound visitor
connection instead of asking the agent to dial back. Because it reuses the
working carrier, it passes the same firewalls the tunnel does. An edge that
does not accept the bind, or `--no-mux`, leaves the tunnel working over
dial-back. This connection is the port mux. A device with a session capability
opens a second one, the session mux, for browser and CLI sessions (see
[Session mux](#session-mux)).

Each tunnel in a config file and each device enrolled on the machine opens its
own control connection and its own port mux, bound to its own session; a
device's session mux binds to the same session.

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
- The first frame on a connection (`Register`, `MuxBind` or `ConnectionReady`)
  must be at most **16 KiB**. A larger first frame closes the connection.

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
| PortsUpdate     | 13  | E → C     | A device's new allowed ports     |
| PortsAck        | 14  | C → E     | The port version now served      |

## Payloads

### Register (1)

```json
{
  "token": "tok_xxx",
  "kind": "tunnel",
  "protocol": "http",
  "client_name": "hostname",
  "timestamp": 1711357200,
  "nonce": "hex32",
  "subdomain": "optional",
  "agent_version": "1.4.2",
  "agent_os": "darwin/arm64",
  "resume_session_id": "optional",
  "allowed_ports": [{ "from": 502, "to": 502 }, { "from": 8000, "to": 8100 }]
}
```

`kind` is `tunnel` or `device`; absent reads as `tunnel`. A **tunnel** publishes
one local service, authenticates with `token` and names its `protocol` (`http`,
`tcp`, `tls`). Sending the wrong kind for the token is refused with `PR009`. A
**device** sends no token and no protocol, and serves the ports the dashboard
allows on it. It authenticates with its device certificate, presented as the
TLS client certificate of the connection (see
[Device registration](#device-registration)); a device Register on a
connection without one is refused.

A device also reports what its local config enables. The agent enforces it;
the API's session mint also refuses a kind whose capability or desktop
protocol is not reported:

```json
{ "capabilities": ["terminal", "files", "desktop"], "logins": ["pi"], "desktop": ["rdp", "vnc"] }
```

`allowed_ports` is a device's optional port ceiling (`--allow-ports`): up to 64
inclusive ranges of ports 1 to 65535. Absent means no ceiling. The edge refuses
a stream to an open port outside it and logs `blocked_by_device`; the agent
refuses it as well. A tunnel that sends `allowed_ports` is refused.

A registering client asserts nothing that access depends on. A device's name
and address come from its certificate, never from `client_name`. Whether it may
be reached is decided server-side.

The agent sends no client id. The edge mints one per session and returns it in
`RegisterAck.client_id`.

`agent_version` and `agent_os` describe the binary, not the client. They are
stored with the connection's server-side record for support. Both are
self-asserted and optional, and nothing on the server gates on either.
`agent_version` is the build's version string; `agent_os` is `GOOS/GOARCH`.

`resume_session_id` echoes the `session_id` from this tunnel's previous
`RegisterAck`. When it matches a live session on the edge, that stale session is
replaced in place, so a reconnect after a network drop is instant on every
tunnel kind. It is held in memory only (empty on first connect and after an
agent restart). On single tunnels a valid registration without a resume match
still replaces the sole existing client (newest-wins); fanout/fleet tunnels
never replace without a resume match.

### RegisterAck (2)

```json
{
  "success": true,
  "tunnel_id": "tun_xxx",
  "tunnel_name": "my-api",
  "region": "eu",
  "region_name": "Europe",
  "public_url": "https://foo.eu.localport.dev",
  "urls": [
    "https://foo.eu.localport.dev",
    "http://foo.eu.localport.dev"
  ],
  "subdomain": "foo",
  "port": 0,
  "mode": "fanout",
  "protocol": "http",
  "error": "",
  "error_code": "",
  "retryable": null,
  "limit_type": "",
  "session_id": "hex32",
  "client_id": "cl_<32 hex>",
  "revoked_ticket_kids": ["<kid>"]
}
```

`revoked_ticket_kids` is sent to devices only and omitted when empty: session
ticket signing key ids the edge saw revoked. The agent acts on it only in a
successful ack and treats it as a hint, since the edge relays and is not the key
authority: a named kid the device holds is refused in memory, and the device
fetches its key set from the control plane at the earliest time the fetch floor
allows (see "Device enrolment and rollover"). That set settles the hint: a kid
it lists is trusted again, one it omits is gone. A hint that no set settles
lapses after 15 minutes; at most 64 are held. Nothing from this field is written
to disk.

`region_name` is the server-supplied display name for the region; when empty
the agent falls back to a built-in mapping, then the uppercased slug.

`client_id` is the id the edge minted for this session. It is the id the
dashboard and the edge's logs show. A reconnect that resumes (see below) keeps
it; any other registration gets a new one. It is not a secret and grants
nothing.

`session_id` is an edge-minted secret for this session; present it as
`resume_session_id` on the next `Register` for this tunnel to reclaim the
slot immediately on reconnect. A session replaced this way receives a
non-retryable `Shutdown` with code `TU012`, so two agents sharing one token
cannot kick each other in a loop (the replaced one stops).

A refused `Register` does not affect the live session. A takeover by a
different registration (not a resume) stops the replaced agent.

### PortsUpdate (13) / PortsAck (14)

A device's allowed ports are set in the dashboard. The list arrives in
`RegisterAck` and is replaced by `PortsUpdate`:

```json
{ "version": 41, "ports": [{ "port": 502, "protocol": "tcp" }, { "port": 80, "protocol": "http" }] }
```

`version` orders the list within a session. A `PortsUpdate` is applied only
when its version is higher than the current one, and every update is answered
with the version served. The list in a `RegisterAck` replaces the list and
version unconditionally, and connections to ports it drops are closed.

```json
{ "version": 41 }
```

A removed port stops being served the moment the edge applies the update, and
its live streams are closed at both ends. The edge closes them, and the agent
closes the local sockets it holds for that port when it applies the update. An
added port is accepted by the edge only after this acknowledgement, since
control frames and data streams travel on different connections.

A port the dashboard allows outside the device's `allowed_ports` stays in the
list and is refused: the dashboard shows it as blocked by the device.

`protocol` is `tcp` (opaque bytes) or `http` (requests are parsed for this
agent's own request view and for the status counters in the access log).

### NewConnection (3)

```json
{
  "connection_id": "conn_xxx",
  "remote_addr": "203.0.113.7:54321",
  "target_port": 502,
  "target_protocol": "tcp",
  "consumer": "user:0mkppnsc7lsdcv"
}
```

`remote_addr` is the L4 peer (host:port) of the inbound connection as seen by
the edge. Agents surface it as the originating address in their live-connections
view.

The last three are set for a device: which of its ports to dial, how to treat
the stream, and which identity asked. `consumer` is display text for this
agent's own output and is never forwarded to the local service.

A device checks the port against its own list and dials the target before it
sends `ConnectionReady`, which carries the result.

### ConnectionReady (4)

```json
{ "connection_id": "conn_xxx", "status": 200 }
```

`status` is the agent's verdict. Absent or `0` reads as `200`. The agent answers
`403` for a port it does not serve and `502` when the local target could not be
dialled; the edge passes both to the visitor or consumer.

### Heartbeat / HeartbeatAck (5, 6)

```json
{ "timestamp": 1711357200 }
```

Both sides send a heartbeat every 30 s on the control connection and ack the
peer's. Each side treats a control connection with no inbound frame for 75 s
(two missed heartbeats plus margin) as dead, so a dropped link (wifi loss,
sleep, NAT rebind) is detected within 75 s even though the socket never errors.

### SetActive (7)

```json
{ "active": true }
```

Marks the primary client of a fanout tunnel. The edge does the routing; the
agent takes no action.

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
| `client_connections` | A fanout tunnel reached its plan's client limit         | yes at registration, no when a session is closed for it |
| `no_plan`            | Team has no active paid or trialing subscription | no        |
| `payment_due_paused` | Team holds a plan, payment is overdue, and its grace window has elapsed | no |
| `plan_paused`        | Team's subscription is paused; it resumes from the billing page | no |
| `blocked`            | Access blocked for this tunnel or team           | no        |

`payment_due_paused`, `plan_paused` and `no_plan` are all terminal. The first
asks the team to pay an overdue invoice, the second to resume its paused plan,
the third to subscribe. The agent uses `limit_type` only to pick the hint it
appends to `reason`. Whether it reconnects is decided by `retryable`.

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
derives the SNI from the target's zone (see [Redirect](#redirect) below).

### MuxBind (11) / MuxBindAck (12)

```json
{
  "token": "<tunnel token>",
  "session_id": "<session_id from RegisterAck>",
  "timestamp": 1735689600,
  "nonce": "<32 hex chars>",
  "purpose": "session"
}
```

`purpose` is omitted for the port mux described here. `"session"` binds a
device's session mux instead (see [Session mux](#session-mux)).

Sent as the first frame on a second connection to the edge, over the same
carrier the control connection used (raw or WebSocket). There is no dedicated
ALPN, and the frame type identifies the connection as a mux. It attaches that
connection to a session already registered on the control connection. On the
port mux the edge then opens one HTTP/2 stream per inbound visitor connection
instead of asking the agent to dial back.

The bind is authenticated on its own, because it is dialed separately from the
control connection:

- `timestamp` and `nonce` are checked against the same replay window and the
  same store a Register uses, so neither frame can be replayed as the other.
- `token` proves which tunnel. A device sends none: the mux connection presents
  the client certificate its control session registered with, and the edge
  requires the same leaf.
- `session_id` names which live client the streams belong to, compared in
  constant time.

All three are required (for a device, the certificate stands for `token`). The
token identifies a tenant but not which of its clients; the session id on its
own is a bearer credential.

A bind never takes over a session, never mints a new one and never registers a
tunnel. It attaches to a live session or is refused. Refusals are rate limited
like failed registrations and carry only a generic reason, so the frame cannot
be used to probe tokens or session ids.

```json
{ "success": false, "error": "...", "code": "..." }
```

A refused port mux bind is not fatal. The agent keeps serving over dial-back,
which is also what happens when the connection later dies; a port mux that
bound once is retried. A session mux bind that fails is always retried with
backoff (see [Session mux](#session-mux)). `--no-mux` skips both.

Port mux streams carry opaque bytes, as a dialed-back connection does, so the
same mechanism serves http, tcp and tls tunnels, and both the primary and the
secondaries of a fanout tunnel. The visitor's address travels in the
`Localport-Visitor-Addr` header on each stream.

The edge decides per inbound connection: a stream when the agent has a live
port mux with room for one more stream, a `NewConnection` dial-back
otherwise. The edge holds at most 64 open streams per port mux, whatever
`SETTINGS_MAX_CONCURRENT_STREAMS` the agent advertises.

The agent's port mux server advertises `SETTINGS_MAX_FRAME_SIZE` 16384, the
HTTP/2 minimum. The edge keeps a request-body buffer of that size for every
open stream, so a larger value raises the edge's memory per stream.

## Lifecycle

```
Agent                              Edge
  |---- TCP/TLS connect ---------->|
  |---- Register ----------------->|
  |<--- RegisterAck (or Redirect)--|
  |                                |
  |---- MuxBind (2nd connection) ->|
  |<--- MuxBindAck ----------------|
  |<--- HTTP/2 stream per visitor -|
  |                                |
  |---- Heartbeat (every 30s) ---->|
  |<--- HeartbeatAck --------------|
  |                                |
  |<--- NewConnection -------------|   (without a mux)
  |---- [new socket dial] -------->|
  |---- ConnectionReady ---------->|
  |<==== bidirectional data =====>|
  |                                |
  |<--- Shutdown ------------------|   (or initiated by the agent)
  |---- close --------------------->|
```

A dial-back data connection rides its own freshly dialed socket; only the
initial control frame on that socket carries the matching `connection_id`.

## Error codes

The `error_code` (in `RegisterAck`) and `code` (in `Shutdown` / `Error`) fields
carry an **opaque, server-defined token**. The agent does not interpret it and
must not build behavior on specific values. It is surfaced verbatim so a user
can read it back to support. In the TUI it appears as a bottom-right border
capsule (`└────[ AT001 ]─┘`), and in `--noui` mode it is appended to the log
line as `[AT001]`. The set of codes and their internal meaning is private to
the server.

The human-readable explanation is the sanitized `error` / `reason` / `message`
string the edge supplies, together with the structured `retryable` and
`limit_type` fields. Messages never reveal server internals. Infrastructure
problems are reported as `"service temporarily unavailable"`.

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
| Payment overdue           | payment is overdue, update your payment method | no        |
| Resource limit            | resource limit reached                         | no        |
| Client limit              | this tunnel has reached the number of clients its plan allows | no |
| Tunnel terminated/deleted | tunnel terminated by an administrator          | no        |
| Session replaced          | replaced by a newer session for this tunnel    | no        |
| Unknown fleet device      | this device is not on the fleet: create it ... | no        |
| Device limit              | your team has reached the number of devices its plan allows | no |
| Duplicate device name     | another device on this tunnel is using this... | **yes**   |
| Token kind mismatch       | invalid token usage                            | no        |
| Fleet token (`SE030`)     | Fleet tokens are retired. Create the device ... | no       |
| Device certificate (`SE031`) | device certificate refused: enrol the device again ... | no |
| Protocol / clock          | protocol error, update the agent ...           | no        |

**Device limit** counts the devices a team has registered across all of its
fleets. A device that is already registered is never refused by it.

**Client limit** applies to one fanout tunnel. A tunnel or device that the
service has no room for right now is reported as service unavailable and is
retried.

**Unknown fleet device** is non-retryable. Waiting cannot change the answer, and
the message says what to do.

**Duplicate device name** is retryable. A fleet agent that restarts loses its
resume id and collides with its own stale session until the edge clears it. Two
devices that share a name keep failing with the same message.

Certificate failures on a consumer connection surface at the TLS
handshake layer, not as control-plane frames. A consumer either presents an
acceptable client certificate or the connection is refused.

### Retry policy

1. The `retryable` field on `RegisterAck` / `Shutdown` is authoritative.
2. When `retryable` is unset, the agent retries a `Shutdown` and gives up on
   a failed `RegisterAck`.
3. Unknown / opaque codes never change behavior; the agent relies on
   `retryable` and `limit_type` only.
4. Backoff is exponential (1.5×), capped at 30 s, plus up to 25 % jitter. The
   per-transport dial budget also escalates with consecutive failures
   (2 s doubling to 16 s) so high-latency links (2G, satellite) can
   complete the TLS handshake; an explicit dial-timeout setting is used
   verbatim.
5. Dead-link detection is symmetric. The agent treats a control connection
   with no inbound frame for 75 s (the edge heartbeats every 30 s) as dead
   and reconnects, even when the socket never returns an error.
   A detected host network change (interface or address churn) additionally
   fires an immediate probe heartbeat; if nothing arrives within 5 s of the
   probe the session reconnects, so a connection orphaned by a network
   switch recovers in seconds. TCP connections cannot survive an address
   change, so in-flight proxied connections on the old network close and
   visitors retry over the re-established tunnel.
   Wake from sleep is detected the same way via a wall-clock jump check
   (10 s cadence). After sleep the socket is presumed stale even when the
   address set is unchanged, so the wake fires the same probe.
6. When a previously assigned edge address keeps failing for 90 s, the
   agent falls back to the originally configured connect host, which
   resolves to healthy edges only. A routine edge restart finishes inside
   that window and restores the session (and any assigned port) on the same
   edge; a permanently lost edge costs at most that window before the tunnel
   returns on a replacement edge.

### Finding an edge

The agent dials `connect.<region>.localport.dev` (TTL 60 s). The name resolves
to any edge in the region, which may answer with a `Redirect`.

After a successful `Register` the agent reconnects to the same edge. After 90 s
of failures it returns to the connect host.

When resolving a host fails (timeout, SERVFAIL, unreachable nameserver), the
agent dials the IP of its last connection to that host that completed TLS.

- A name that resolves is always dialed as resolved.
- NXDOMAIN is final and never falls back.
- TLS still verifies the certificate against the hostname, so a stale IP fails
  the handshake.
- The table is per process and empty until the first successful connection.

### Redirect

The edge may answer a `Register` with a `Redirect` pointing at another edge,
a per-edge hostname like `e1.eu.localport.dev` (tunnels are pinned to one edge
inside a shared region zone). The agent follows up to 5 hops before giving up,
and only to hosts under the platform base domain.

SNI is derived per dial from the address being dialed. The original connect
host is used verbatim; a redirect target (`e1.eu.localport.dev`) gets the
target zone's connect host, i.e. the target's first label replaced with the
configured connect label (`connect.eu.localport.dev`). Post-redirect
reconnects and data dial-backs present the same derived SNI. Reasons:

1. The edge demuxes agent traffic by SNI: only `connect.<region-zone>` reaches
   the agent handler; any other SNI is treated as tunnel traffic. A
   cross-region redirect therefore needs the target zone's connect host, not
   the original one (which the target edge would treat as unknown tunnel
   traffic and close).
2. The edge serves the region-zone wildcard cert (`*.<region-zone>`), which
   covers `connect.<region-zone>` but not `connect.<per-edge-hostname>` (two
   labels deep), so the derived SNI must sit one label under the target
   zone. The dial address itself stays the per-edge hostname, which resolves
   directly to the pinned edge.

## Data streams on the port mux

A stream stands in for one inbound connection. The edge sets these headers; the
bytes a consumer sends are the stream body and can never reach them.

| Header                      | Meaning                                  |
| --------------------------- | ---------------------------------------- |
| `Localport-Visitor-Addr`    | L4 peer of the inbound connection         |
| `Localport-Target-Port`     | device port to dial                       |
| `Localport-Target-Protocol` | `tcp` or `http`                           |
| `Localport-Consumer`        | identity that opened the stream           |

The last three are set for a device only. A stream naming a port the device does
not serve is answered `403` before anything is dialled; a target that cannot be
reached is `502`.

## Session mux

Browser and CLI sessions (terminal, files, desktop) never use the port mux. A
device whose local config enables `terminal`, `files` or `desktop` opens a
second mux per control session, the session mux; `--no-mux` agents and host
tunnels open none, and the edge then refuses sessions with the retryable end
reason `no_session_mux`. Dial-back never carries a session. A second agent
process on the same device identity cannot hold its `.jti.lock` (see [Stored
identity](#stored-identity-localport-identity)) and opens no session mux either.

Bind: a new connection over the control connection's carrier, first frame
`MuxBind` with `purpose: "session"`, authenticated as any `MuxBind`.

After `MuxBindAck`, roles reverse relative to the port mux: the edge is the
HTTP/2 server and the agent the client, with prior knowledge (no ALPN). The
agent advertises `SETTINGS_MAX_FRAME_SIZE` 16 KiB and an initial stream window
of 128 KiB, and raises the connection window by 20 x 128 KiB. It pings a silent
connection every 30 s, closes it when a ping goes unanswered for 15 s, and
closes it when a write makes no progress for 15 s. It bounds each response's
header list to 4416 bytes as HTTP/2 counts it (name, value and 32 bytes per
field: 4 KiB plus Go's allowance for 10 fields) and advertises that as
`SETTINGS_MAX_HEADER_LIST_SIZE`. It sends `User-Agent: localport-agent` and
asks for no compression. The edge allows 20 concurrent streams: the accept
stream, 16 session streams, 2 recording segment requests and 1 recording open
or complete (see [Session recording](#session-recording)). The edge refuses a
17th session on one mux with the end reason `agent_closed`.

Accept stream: the agent's first request is `POST /v1/session-accept` with no
body (`END_STREAM` on its headers). The edge answers `200` and holds the
response open for the life of the mux. Each session is one notice on it:

| Bytes | Meaning                                  |
| ----- | ---------------------------------------- |
| 4     | `uint32` big-endian length, always 16    |
| 16    | session id                               |

A notice of any other length, or the accept stream ending, ends the mux.

Session stream: for every notice the agent opens `POST /v1/session` with header
`Localport-Session-Id: <32 lowercase hex chars>` (the id from the notice), so
every refusal travels on the stream itself. At most 16 opens wait for their
response headers at once: with 16 in flight the agent reads one more notice,
whose open waits for a slot, and reads no further notice until an open ends. It
resets an open whose headers do not arrive within 30 s. The request body is
agent-to-edge bytes and the response body edge-to-agent bytes. The edge answers
`404` to an id it is not waiting for on this mux. On `200` the stream carries
one session:

1. The edge writes the session ticket, `uint32` big-endian length then the
   ticket bytes, at most 8 KiB. The agent resets a stream whose ticket is
   longer or does not arrive within 5 s.
2. The agent answers with its first frame, `uint32` big-endian length then JSON
   of at most 4 KiB, within 10 s: `{"type":"accept","a_x25519":…,"ct_mlkem":…,"sig":…}`
   or `{"type":"refused","code":"<code>"}`. A code must match `[a-z_]{1,32}`.
   The agent checks, in order, and refuses with the first failing code:

   | Check | Code |
   | ----- | ---- |
   | a registration was acknowledged (its certificate binds the ticket) | `agent_busy` |
   | ticket `v` is 1 | `ticket_invalid` |
   | ticket `kid` known; an unknown one triggers one key fetch (at most 3 s, at most once per 5 minutes) and one retry | `ticket_unknown_key` |
   | ticket signature, then its fields and client keys parse | `ticket_invalid` |
   | `iat` at most 30 s ahead of the agent clock, `exp` - `iat` at most 60 s, and `exp` not more than 30 s past | `ticket_expired` |
   | `device` and `device_spki_sha256` name this device's registered certificate | `ticket_wrong_device` |
   | the kind is enabled in the local config (`terminal` and `ssh` need `terminal`, `files` needs `files`, `rdp` and `vnc` need `desktop` and that target) | `kind_disabled` |
   | the login is listed in the local `logins` | `login_not_allowed` |
   | this build serves the kind (Windows serves no `terminal`) | `kind_unavailable` |
   | a ticket with `rec` is a `terminal` ticket | `kind_unavailable` |
   | the held team recording key hashes to `rec.pub_sha256`; a mismatch triggers one key fetch, under the same 5-minute floor, and one retry | `recording_key_mismatch` |
   | fewer than 8 sessions run, and the agent is not shutting down | `agent_busy` |
   | the user lookup: the login has an account (`getent`, the account files without it, or the macOS directory), and as a non-root agent it is the agent's own user | `login_not_allowed`; a lookup that fails, times out or has no time left before the first-frame deadline is `agent_busy` |
   | `terminal` can spawn: as root a `login` at `/bin/login` or `/usr/bin/login` that root owns and no one else can write, with SELinux not enforcing | `kind_unavailable` |
   | the handshake: the client X25519 key is not a low-order point, and the agent signs the transcript | `ticket_invalid`; a local signing failure is `agent_busy` |
   | the `jti` was not used before (held until `exp` + 30 s, at most 4096) | `ticket_replayed`; a full or unavailable cache is `agent_busy` |

   Nothing before the last check consumes the ticket. The `jti` is written to
   `session_jti.log` and flushed to disk before `accept` is sent. `agent_busy`
   and `ticket_unknown_key` are worth one fresh ticket. A Strict recording
   opens after the `jti` check and before `accept`; when it fails the agent
   refuses `recording_unavailable` with the ticket spent (see
   [Session recording](#session-recording)). After a `refused`
   frame the agent half-closes the stream and reads it to its end for at most
   2 s before it closes it, so the frame reaches the edge.
3. After `accept`, both directions carry encrypted records, each a `uint32`
   big-endian length then the sealed record. The client's first record is
   `start`. The agent ends a session with an authenticated `close` record and
   one of these reasons: `idle` (30 minutes without a client `data` or
   `activity` record), `shutdown` (the control session is ending; sent within
   2 s), `config_changed` (`localport set` changed the device's entry and the
   agent reloaded it; the device's other sessions end too), `exited` (the process the session runs ended by itself; terminal),
   `recording_failed` (a Strict recording could no longer keep the session's
   output; terminal), `helper_failed` (the session helper's channel ended
   without an exit; terminal), `launcher_unavailable` (the session launcher
   could not be reached after the ticket was spent; terminal) or
   `protocol_error` (a first record that is not `start`, or
   a malformed or unauthenticated record). After its `close` the agent
   half-closes the stream and reads it to its end for at most 2 s, and it sends
   no record after `close`. A client `close` ends the session without an agent
   `close`.

Records: the first plaintext byte of a record is its type and the rest its
body. Every kind shares `close` (`0x00`, JSON `{"reason"}`), `start` (`0x01`),
`data` (`0x02`, raw bytes) and `activity` (`0x03`, empty body); `0x04` to
`0x0f` are refused, and a kind defines its own types from `0x10`. A
`terminal` session uses:

| Type | Direction | Body |
| ---- | --------- | ---- |
| `start` `0x01` | client to agent | JSON `{"cols","rows","term"}`: `cols` and `rows` integers 1 to 1000, `term` matching `^[a-zA-Z0-9.+-]{1,32}$` (`xterm-256color` when absent). Any other field closes `protocol_error`. The shell runs as the ticket's login, never one the body names. |
| `data` `0x02` | both | client to agent: terminal input; agent to client: terminal output, at most 16 KiB per record. A record may split a UTF-8 sequence. |
| `resize` `0x10` | client to agent | JSON `{"cols","rows"}`, the same bounds; the kernel signals the foreground process group. |
| `exit` `0x11` | agent to client | JSON `{"code"}`: the exit status of the process the agent spawned, or 128 plus the signal number. Sent once, followed by `close {"reason":"exited"}`. As root the spawned process is `login`, whose status is not the shell's on util-linux (it exits 0 after the shell ends). |

Any other type from the client, `0x12` and up included, closes
`protocol_error`. A process that cannot start sends a one-line reason as
`data`, then `exit {"code":127}` and `close {"reason":"exited"}`; the ticket
stays spent.

Reconnect: a failed dial or bind, and a mux that drops, are retried for the
life of the control session with full-jitter backoff from 1 s, doubling to a
60 s cap. The backoff resets only after a mux whose accept stream the edge
answered with `200` stayed up for 30 s; a bind that is acked but whose accept
stream fails, or a mux that drops sooner, keeps it growing. The first failure
after a reset is logged as a warning, later ones at debug level. The port mux
is independent of it.

Stop: when the control session ends or the agent stops, the agent first asks its
session handler to shut down (sessions send their close records, streams past
their ticket read are refused `agent_busy`, streams still reading it are reset,
terminal processes are ended: SIGHUP, then SIGKILL at 5 s, and each session
waits at most 3 s for its recording's final segment to reach the uploader),
waits for that at most 10 s, then closes the mux connection. The connection is
never closed before that step.

## Session recording

A `terminal` ticket may carry `rec`: `{"id","pub_sha256","policy"}`, where
`id` is a canonical UUID equal to the ticket's `jti`, `pub_sha256` the
unpadded base64url SHA-256 of the team recording public key (43 characters)
and `policy` `best_effort` or `strict`. Any other shape is `ticket_invalid`;
the session checks are in the table under [Session mux](#session-mux). The
agent records the session's output, resizes and exit, seals it in segments
and delivers them over its session mux. Code: `internal/recording/`,
`internal/session/recorder.go`, `internal/tunnel/recording_client.go`.

Format: the plaintext is asciicast v3, one JSON line per event (header, then
`o` output, `r` resize and `x` exit events). A segment holds whole lines and
is cut at 10 s or 256 KiB of plaintext, whichever comes first. Each recording
has a random 32-byte DEK, wrapped once with HPKE (ML-KEM-768 with X25519,
HKDF-SHA256, ChaCha20-Poly1305, info `localport-recording-v1` followed by
the id) to the team recording public key; the result is `wrapped_dek`. A
segment object is:

| Bytes | Meaning |
| ----- | ------- |
| 1 | version, `1` |
| 1 | codec: `0` the plaintext as is, `1` raw deflate (level 6, used only when smaller) |
| rest | ChaCha20-Poly1305 ciphertext and tag under the DEK |

The nonce is the segment index as a 96-bit big-endian integer, and the AAD is
`id || index (uint32 BE) || final (1 byte) || version || codec`. Only the
last segment has `final` 1; a recording that ends with nothing buffered seals
an empty final segment (18 bytes). `h_i` is SHA-256 of object `i`; the chain
is `chain_0 = SHA-256(h_0)` and `chain_i = SHA-256(chain_{i-1} || h_i)`. The
agent clears its DEK buffer after the final segment is sealed or the
recording is discarded. Copies inside the cipher state and those the Go
runtime makes are not cleared and stay in process memory until the runtime
reuses it.

Signatures: `lp(x)` is a `uint32` big-endian length then `x`. The agent signs
SHA-256 of these messages with the key of the device certificate the carrying
session mux presented, as ASN.1 DER in unpadded base64url:

- open: `lp("localport-recording-open-v1") || lp(id) || lp(SHA-256(wrapped_dek)) || lp(key_sha256)`
- complete: `lp("localport-recording-complete-v1") || lp(id) || lp(SHA-256(wrapped_dek)) || segments (uint32 BE) || lp(final_hash) || ended_at (uint64 BE, Unix seconds) || incomplete (1 byte) || final (1 byte) || lp(reason)`

The spool and memory hold only unsigned fields; every open and complete is
signed when it is sent, so a renewed certificate signs on the next mux.

Wire: each request is one stream on the session mux, every one with header
`Localport-Recording-Id` (the canonical 36-character UUID). JSON byte fields
are unpadded base64url.

| Request | Body | `200` answer |
| ------- | ---- | ------------ |
| `POST /v1/recording/open` | `{"wrapped_dek","signature"}` | `{"status","segments","chain"}`: the segments the server holds and its chain over them (empty with 0 segments) |
| `PUT /v1/recording/segment`, headers `Localport-Segment-Index` (decimal, no sign or leading zeros) and `Localport-Segment-Sha256` (unpadded base64url of `h_i`) | the segment object, at least 18 bytes | `{"status","segments"}`; a segment already stored answers `200` like a fresh one |
| `POST /v1/recording/complete` | `{"segments","final_hash","ended_at","incomplete","final","reason","signature"}` | `{"status","segments"}` |

A refusal is `{"code","retry_after"}`, `retry_after` in seconds on `429` and
`503` only (5 on a `503` without one). The agent counts a refusal only with a
known code at that code's status; anything else, `408` included, is a transport
failure. Each request, the wait for its stream slot included, has a deadline of
30 s plus its body length at 64 KiB/s; one that passes it is a transport
failure.

| Status | Code | Agent |
| ------ | ---- | ----- |
| 400 | `recording_bad_request` | drops the entry, error log |
| 401 | `recording_proof_invalid` | drops the entry, error log |
| 404 | `recording_not_found` | drops the entry |
| 409 | `recording_out_of_order` | repeats `open` to learn `segments`, drops what the server holds, resumes from there, never skipping an index |
| 409 | `recording_mismatch`, `recording_conflict` | drops the entry, error log |
| 410 | `recording_closed` | drops the entry |
| 413 | `recording_limit` | drops the entry |
| 429 | `recording_quota` | waits `retry_after` plus 0 to 15 minutes of jitter, keeps the spool |
| 502 | `recording_storage` | backoff |
| 503 | `recording_busy`, `recording_unavailable` | backoff with `retry_after` as the floor |

Backoff is full jitter from 1 s to 60 s and also covers transport failures and a
missing session mux; an entry that found no session mux is retried at once, with
its backoff reset, when the device's session mux comes up. Per mux the agent
sends at most 2 segment requests (spool drain uses at most 1, so a live segment
always has a stream) and 1 open or complete, and per recording at most one
segment at a time, in index order. A drop on a server refusal is logged with the
refusal's code, and a drop on a chain mismatch with `recording_mismatch`; a
local drop (device no longer configured, nothing accepted for 24 h, a server
count the agent cannot resync to) is logged without a code.

Delivery and spool: each sealed segment is sent at once. A segment not
acknowledged within 5 s, or sealed while no session mux is up, is written to the
spool; an acknowledged segment never is. A session holds at most 1 MiB of
unacknowledged segments in memory. The spool is `<state root>/recordings/` (the
directory that holds `identity/`), directories 0700 and files 0600, each written
to a unique temporary file, fsynced and renamed: `<id>/meta.json` (device
identifier, `wrapped_dek`, key hash, policy, counters, chain, and the complete
fields once known) and `<id>/<index>.seg`. `meta.json` is written before the
open and before the first output, so a crash leaves an entry to complete. The
spool holds at most 32 MiB per agent across every device and recording,
`meta.json` files included. Each recording counts the largest `meta.json` it can
reach (its complete fields included) plus the space of each segment hash it
accepted, so a recording's `meta.json` writes always fit once the recording
exists. A new recording, a segment write, and a segment whose hash does not fit
are refused when they would pass the cap. A segment write is also refused when
the spool's filesystem has under 64 MiB free. A segment write that finds the
filesystem or the user's quota full counts as `disk_low`. A spooled segment is
checked against its persisted hash when it is read back for upload; a file that
is missing, unreadable, over the largest segment object or does not match is a
lost segment, never retried: the recording completes `incomplete` at the
acknowledged count. An entry whose device is no longer in the local config is
dropped, and so is one with no accepted request for 24 h, counted from its last
accepted request or, for an entry resumed after a restart, from that start when
it is later.

After a restart the agent resumes every entry: it repeats `open` (idempotent)
to learn the server's `segments` and `chain` and sends the spooled segments
from that count upward. When the server's count is at most the persisted
sealed count, the agent checks that the count is at least its last persisted
acknowledged count and that the server's chain matches the hashes it holds
for that range, then resumes delivery at that count; a failed check drops the
entry. When the server's count is above the persisted sealed count (segments
delivered from memory whose hashes the crash lost), the agent takes the
server's `segments` and `chain` without a chain check and completes there;
an entry that already holds its complete fields, or a server chain that is
not 32 bytes, is dropped. When the lowest spooled index is above the server's
count, it completes at that count and drops the rest. A restart completion
attests the server's chain at restart, not the origin of every segment;
segment content stays authenticated by the AEAD. An entry without a complete
body is completed with `incomplete` true, `final` false and reason
`agent_restart`.

Policies:

- Best effort: the open is queued and the session starts at once. When the spool
  has no room for a segment's hash, or memory is full and the spool refuses the
  segment, recording stops (indices stay contiguous), the recording completes
  `incomplete` with reason `spool_full` or `disk_low`, and the session
  continues. When the recorder's queue (512 KiB of output not yet sealed) is
  full, recording stops the same way with reason `recording_failed`; terminal
  output never waits for it. An agent without a recording uploader, or whose
  spool has no room for a new recording, runs the session unrecorded.
- Strict: the open is sent after the `jti` check and before `accept`, within
  `min(5 s, 10 s from stream start - 3 s)`; with under 1 s left the agent
  does not try. Any failure, a missing uploader or no spool room for a new
  recording refuses `recording_unavailable` and spawns no shell. When the
  spool has no room for a segment's hash, or memory is full and the spool
  refuses the segment, the agent seals what it has, completes `incomplete`
  with reason `recording_failed` and ends the session with close reason
  `recording_failed`. When the recorder's queue is full, terminal output waits
  for space at most 5 s (less when the session ends first), then the recording
  and the session end the same way. A Strict session whose mux drops keeps
  running while the spool accepts.

Every session end seals a final segment (the `x` event when the shell
exited) and completes with `incomplete` false unless recording stopped. The
session's end waits at most 3 s for the final segment to reach the uploader;
past that it ends without it, and the recording completes `incomplete` with
reason `recording_failed` once the stalled handoff returns.
`recording_key_mismatch` and `recording_unavailable` are worth one fresh
ticket.

## Remote access (`localport access`)

A fleet has no public endpoint. A consumer presents a client certificate; the
fleet's grants decide whether that certificate's identity may reach the device,
and the device decides which of its ports are open.

One connection carries every forward:

```
localport access plc-01-factory.ap.localport.dev -L 5020:502 -L 8080:80

  one TLS connection   SNI = the device host, ALPN h2, client certificate
  one CONNECT stream   per accepted local connection
      CONNECT plc-01-factory.ap.localport.dev:502
      CONNECT plc-01-factory.ap.localport.dev:80
```

The CONNECT authority must be the device the connection was opened to, and its
port must be one the device serves. Refusals come back as status codes:

| Status | Meaning                                                      |
| ------ | ------------------------------------------------------------ |
| `405`  | not a fleet device address                                    |
| `421`  | the authority is not the device this connection was opened to |
| `400`  | the authority carries no usable port                          |
| `403`  | the identity has no access, or the port is not allowed        |
| `502`  | nothing is listening on that port on the device               |
| `503`  | the device is busy                                            |

The connection is closed when the device disconnects, when the certificate
chain expires, when a grant is narrowed, and when the certificate is revoked.
The command re-dials on the next forward, and the new attempt is refused if the
grant no longer covers it. An idle connection is pinged after 30 s and dropped
if the ping goes unanswered for 15 s.

A forward listens on `127.0.0.1` by default, reachable by every local user.
`-L unix:<path>:<device port>` listens on a Unix socket created with mode
`0600`. A stale socket with no listener is replaced. A live socket or any other
file at the path is refused. The parent directory must be writable only by the
owner (for example `/run/user/<uid>`), since whoever can write it can replace
the socket. Not available on Windows.

**The agent follows no HTTP redirect.** A `3xx` from a control-plane call, the
CI token request or the WebSocket upgrade is a terminal error reported with its
status. Following it would send the token or CSR to the `Location` host.

**Every connection the agent makes requires TLS 1.3**, including both carriers,
the consumer connection and the control-plane calls. TLS 1.3 encrypts the client
Certificate message, which carries the consumer's SPIFFE identity. Under TLS 1.2
it is sent in the clear. No flag or environment variable lowers the minimum.

**Server verification uses the system trust store.** The edge presents its
region zone wildcard certificate, publicly trusted and issued by Let's Encrypt,
as its mTLS server identity. It is not signed by the tunnel CA. The CA in a
`--pem` file or `.p12` archive is used for the other direction only, as part of
the chain the consumer presents.

A `--pem` file must still contain at least one CA certificate. That is checked
when the file is loaded, so a file without a chain fails locally with a clear
message instead of as a handshake alert from the edge.

### Human sign-in (`localport login`)

For a person, not a machine. RFC 8628 device authorization needs nothing on this
machine beforehand (no token, no team, no identity) and no browser redirect to
localhost, so it works over SSH into a jump box.

```
localport login
  ├─ P-256 keypair generated locally
  └─ POST /v1/mtls/device/start  { csr_pem, hostname, agent_os }
       ← { device_code, user_code, verification_uri,
           verification_uri_complete, interval, expires_in }

     prints:  Open https://dashboard.localport.io/device?code=HBQX-4T2M
              or go to https://dashboard.localport.io/device and enter  HBQX-4T2M

  POST /v1/mtls/device/token  { device_code, csr_pem }
       ← 428 { "error": "authorization_pending" }   ... keep polling
       ← 200 { cert_pem, ca_chain_pem, identity, team_id, not_after }

  ~/.localport/identity/<team>/user-<username>/{cert-<serial>.pem,key-<serial>.pem,meta.json}
```

`hostname` and `agent_os` describe the machine, not the person. The approval
screen shows them beside the requesting address, so somebody signing in from a
laptop and a jump box can tell which one is asking. Both are self-asserted and
optional, like `agent_version` and `agent_os` on Register. Nothing on the server
gates on either.

- **Both URIs are printed, and the prefilled one leads.**
  `verification_uri_complete` (RFC 8628 §3.3.1) carries the code so the common
  path is one click; the bare address and the code are printed beside it for a
  browser on another device. The approval screen shows the requesting IP and
  what the certificate will reach. Nothing auto-submits, and the code stays
  visible so it can be checked against what is on screen.
- **The CSR goes up at the start**, and the server pins its hash. The human
  approves one key, and only that key can collect.
- **Pending and slow-down continue the poll.** `SE021` is RFC 8628
  `authorization_pending`. `SE022` is `slow_down`, which adds 5 seconds to the
  interval. Every other refusal, whether unknown, denied, already consumed or
  expired, is the same opaque message, so a guessed device code cannot be used
  to map the state of somebody else's sign-in. The agent branches on the code,
  never on message text.
- **A sign-in certificate does not renew.** It lives hours; re-running
  `localport login` is how a fresh one is obtained. The identity is the person's
  immutable username, so removing them from the team ends it. The control plane
  refuses `/v1/mtls/certs/renew` for a sign-in certificate, and the agent does
  not ask: the credential records `source: sso`, and `Renew` refuses before
  building a request. A sign-in carries no `renew_after`, and the field is
  omitted from `meta.json`. `localport access` prints the expiry and that
  `localport login` is how it comes back.

### Stored identity (`localport identity`)

`localport setup <TOKEN>` spends a single-use setup token against the control
plane, keeps a private key that never leaves the machine, and stores the result
in the store of the process (directories `0700`, files `0600`):

- unprivileged: `$LOCALPORT_HOME/identity/`, or `~/.localport/identity/` when
  `LOCALPORT_HOME` is unset;
- privileged (root, an elevated Administrator, or `localport run --system`
  or `--service`):
  `identity/` in the machine-wide config directory, `/etc/localport-device`,
  `/Library/Application Support/localport-device` or
  `%ProgramData%\localport-device`.
  `LOCALPORT_HOME` is ignored and the directory is never followed as a
  symlink. A privileged process reads no other directory, so credentials
  under `$HOME/.localport` or `/var/lib/localport` are not used by it; `sudo
  localport login` or `setup` stores them here.

Each process uses one root, the same one its local config uses. An
unprivileged process with neither `LOCALPORT_HOME` nor a home directory has no
root and refuses to start.

On Windows the machine-wide credentials are shared by the elevated
Administrator that runs `connect` and the device service, which runs as the
virtual account `NT SERVICE\localport-device`: files under that directory
grant SYSTEM, Administrators and that account, and only a privileged process,
and only for paths under that directory, accepts that account as an owner or
writer. The machine-wide directory holds the devices' private keys; keep it out
of backups and configuration management.

```
<team>/<kind>-<identity>/
  cert-<serial>.pem   leaf first, then the issuing chain, which is what the agent presents
  key-<serial>.pem    P-256 private key, generated locally, never transmitted
  meta.json           identity, team, team_name, kind, spiffe_id, source, api_url,
                      serial, not_after, the cert and key file names, and
                      renew_after only when the credential renews
  .renew.lock         serializes the credential's writers (save, renewal, promotion)
  ticket_keys.json    device only: { keys: [{ kid, public_key }], recording_key },
                      the session ticket keys the device pins
  .keys.lock          serializes ticket_keys.json writers; taken after
                      .renew.lock, never before it
  session_jti.log     device only: one { jti, until } JSON line per accepted
                      session ticket; expired lines are dropped at start, and
                      the file is rewritten when it holds more than twice the
                      live entries. An unreadable file refuses sessions for
                      120 s after start, then a fresh log starts
  .jti.lock           held by the one process that serves the device's sessions
```

Before every read and write, each directory from the base (`LOCALPORT_HOME`,
`~/.localport` or the machine-wide config directory) down to the credential is
opened without following links and must be a directory owned by the agent's
user. The base may be a symlink only when it comes from `LOCALPORT_HOME` or
`$HOME`, and its target must have the same owner. The machine-wide config
directory is never followed. A failing path is refused, never repaired.
`meta.json`, `pending.json`, the certificate, the key and `ticket_keys.json` are
opened with `O_NOFOLLOW` (`FILE_FLAG_OPEN_REPARSE_POINT` on Windows) and must be
owner-only.

A save writes the certificate and key under new serial-named files, then
`meta.json`, which names them. Writing `meta.json` is the commit point, so a
save interrupted before it leaves the previous credential loadable. Files from
earlier saves are removed afterwards.

`team_name` is the team's display name. `localport identity list` prints it so a
person holding credentials in two teams can tell them apart, and nothing else
reads it. It is omitted when the control plane could not resolve it, and a
record without it still loads. A renewal refreshes it but never blanks it.

`source` is `token`, `oidc` or `sso`. Only `token` and `oidc` renew, and any
other value is treated as non-renewing. A renewal carries the source forward
unchanged.

`meta.json` is validated on read and on write. A record naming an unknown kind
or source, missing an expiry, or pairing a non-renewing source with a renewal
deadline is refused at the store.

**The path and every identity field are read from the certificate, never from
the response body.** One machine may hold credentials for several teams, and
`user` and `client` are separate SPIFFE namespaces that may hold the same name,
so the path carries both.

The path carries no control-plane component. `--api` exists for development, and
a developer running two side by side sets `LOCALPORT_HOME` to isolate the whole
store of an unprivileged process. Which plane issued a credential is recorded as
`api_url`, which is where renewal reads it.

Components are used verbatim, with nothing escaped, sanitized or folded. Each is
checked against the control plane's identity grammar of lowercase alphanumerics
and internal dashes, no leading or trailing dash. Anything else is refused, not
repaired, since a repaired component names a different credential than the
certificate does.

`localport access` with no `--pem` and no `--p12` presents this credential.
When a machine holds several, a selector picks one:

```
gw-01                     a bare identity
<team>/gw-01              narrowed to one team
<team>/client/gw-01       fully qualified
```

Two segments are team/identity, never kind/identity. The three-segment form
exists because a team may hold a `client` and a `user` credential under the same
name.

Precedence is `--identity` > `LOCALPORT_IDENTITY` > an interactive choice. A
selector that was supplied and matches zero or several credentials is an error,
never a prompt, so a typo cannot select a different principal. The prompt
appears only when no selector was given, only on a terminal, and never under
`--config`; everywhere else an ambiguous match is refused with the full form of
each candidate.

The certificate reaches TLS through a callback rather than being copied
into the config, so a renewal is picked up on the next handshake without
restarting. A reload that finds a different SPIFFE identity in the file is
refused, and the process keeps presenting what it opened with.

**Renewal carries no bearer secret.** The agent proves it still holds the
current certificate's private key:

```
POST /v1/mtls/certs/renew
{ cert_pem, csr_pem, signature }

signature = base64( ECDSA-P256( oldKey, SHA256( csrDER
                                              || uint64be(unixSeconds / 60)
                                              || hex(oldCertSerial) ) ) )
```

The minute bucket bounds replay without a nonce store (the server accepts the
minute either side of its own). The serial binds the signature to the one
certificate it was made for, so an intercepted renewal cannot be replayed
against another certificate of the same identity.

Only an unexpired certificate issued to this agent renews. A certificate
downloaded from the dashboard or already expired is refused, and
`localport setup <TOKEN>` issues a new one.

This digest is a wire format shared with the control plane. Both sides pin it
with the same test vector; do not change one without the other.

The signature is recomputed on every attempt, because a retry that crosses a
minute boundary would otherwise send a signature the server no longer accepts.

Renewal is due at `renew_after`, which the server sets two thirds through the
lifetime; the agent uses the same point when the server sends none. The loop
runs inside `localport access`; a machine that is not permanently connected
should run `localport identity renew` from a daily timer instead. The previous
certificate stays valid until its own expiry, so rollover overlaps.

### Device enrolment and rollover

`localport connect <join-token>` checks or creates the store directory, then
spends a single-use join token at
`POST /v1/devices/enrol { join_token, csr_pem }` and stores a `device`
credential. A device identity is `<tunnelIdentifier>.<prefix>`; each half
follows the component grammar above, and the credential lives in
`<team>/device-<tunnelIdentifier>.<prefix>/`. Its `meta.json` adds `device`:
the device host and its region. The session ticket keys and the recording key
in the enrolment and renewal responses replace the set in `ticket_keys.json`;
the control plane lists unrevoked keys only, so a kid absent from a set is
revoked. The set is written after the credential is stored; a failure to write
it is reported and never fails or undoes the credential write.

A device also fetches the set on its own at
`POST /v1/devices/keys { cert_pem, signature }`: `cert_pem` is its current
certificate and `signature` is standard base64 of its key's signature over
SHA-256(`"localport-device-keys-v1"` || the Unix minute as 8 bytes big-endian
|| the certificate serial in lowercase hex). The control plane accepts the
minute before and after its own. The response is `{ keys: { ticket_keys,
recording_key } }`, and it replaces the set the same way. A response whose
`keys` or `keys.ticket_keys` is absent or null is refused rather than stored
as empty; an empty `ticket_keys` array is a valid set. The refresher
(`internal/identity/keyrefresher.go`) fetches once at start when the stored set
is empty, then every 6 hours with ±10 % jitter, on demand, and after a
revocation hint, at most once per 5 minutes, with concurrent requests sharing
one fetch. Each fetch signs with the credential current at that moment.
Transport failures, `5xx` and `429` are retried for up to a minute within the
fetch; a fetch that still fails keeps the stored set and is retried after 1
minute, doubling to 30 minutes, each wait with ±20 % jitter, until one
succeeds. A renewal does not trigger a fetch.
The device's settings go to the local config (`agent.yaml`), which `localport
run` reads. Every directory on the walk to the store or the local config must
also be writable by its owner only; a group- or other-writable one is refused.

A device certificate renews at `POST /v1/devices/renew`, with the request and
proof of `/v1/mtls/certs/renew`. An expired device certificate still renews
there, so it is due at once. A `429` is retried after the longer of the
backoff and its `Retry-After` (at most one hour), with jitter, so devices
behind one address do not return in step.

The control plane issues the renewed certificate as **pending** and keeps the
current one live until the device registers with the pending one. The store
holds both:

```
meta.json      current credential
pending.json   renewed credential, with renewed_from = the serial it renews;
               ignored unless renewed_from is the current serial
```

#### Device registration

The control and mux connections present the device certificate as the TLS
client certificate, on raw TLS and in the outer TLS handshake of the WebSocket
carrier. A TLS-intercepting proxy strips it, so a device cannot register
through one. A mux connection reuses the dialer, and so the certificate, of
the registration it binds to. A process-wide TLS session cache serves only
connections without a client certificate; each device certificate has its own,
because the edge restores a resumed session's client certificate from the
handshake that created it.

Rollover:

- Every registration presents the pending certificate when one exists, so an
  agent restarted after the control plane promoted it registers with it.
- A session ends to re-register when the store holds a pending certificate
  whose serial differs from the one the session registered with, as soon as
  no connection is open, checked every minute, and regardless of open
  connections once the current certificate is within 24 hours of expiry. The
  connections still open then are closed.
- The new certificate starts with an empty session cache, so the handshake
  sends it rather than resuming a session bound to the old one.
- The pending certificate becomes current, and the old key is deleted, only
  after a `RegisterAck` on it. A promotion blocked by a renewal in flight is
  retried.
- Once the pending certificate has been presented, the old one is never
  presented again: the control plane may already have promoted the pending
  one and superseded it. A retryable refusal retries with the pending
  certificate. `SE031` on it renews again from the pending key and retries; a
  definitive renewal refusal stops the device. `SE006` (expired) is retried
  while the renewal loop renews the certificate, and stops the device while
  the loop reports a definitive renewal refusal (a `4xx` other than `429`);
  a renewal that lands clears it.
- A store read error is retried and never deletes a credential.

`localport access` never offers or selects a device credential, and `setup`
and `login` refuse one. `connect`, `setup` and `login` check the store
directory before they spend their one-time secret.

A second `connect` for an enrolled device checks its flags before the spend
without the stored entry, since the identity is unknown until enrolment; a flag
that needs the stored entry (`--logins` alone, `--enable desktop` relying on a
stored target) is refused with the remedy: re-enrol without it, then
`localport set`. After enrolment it takes the local config lock, re-reads the
config and merges the flags onto the stored entry as `set` does: each flag
given overrides, the rest keep their stored values. A new identity appends an
entry. It prints the settings in force, and a re-enrolment that changes nothing
does not rewrite the config. When the flags conflict with the stored entry,
the stored entry stays in force with the new credential and `connect` exits
non-zero naming the conflict and `localport set`. A stored files root that no
longer exists is reported as such, with the stored entry in force; any other
failure to write the config prints the spent-token remedy. A device entry
enabling `terminal` or `files` needs at least one login, and one enabling
neither has none. `localport run` logs and skips a device whose credential is
missing or unreadable and runs the others; it refuses to start when the config
lists no device or none can start. A save or local config write that fails
after a join token, setup token or sign-in was spent names the remedy: a new
token or sign-in, then the command again.

### When the control plane cannot be reached

A credential call that fails because nothing answered is retried; one that fails
because it was refused is not.

| condition | behavior |
|---|---|
| transport failure (dial, DNS, TLS, timeout, reset, EOF) | retry |
| `5xx` | retry |
| `429` | retry, honoring `Retry-After` |
| any other `4xx` | terminal, immediately |

Waits carry full jitter, so many agents recovering from one outage do not retry
in lockstep. Backoff runs 2s to 30s inside a budget of 60s by default.
`localport setup --wait <duration>` extends the budget for a box that boots
before its network is ready, and `--wait 0` makes exactly one attempt for CI.
`--wait` applies only to retryable conditions; a bad token fails at once.

The sign-in poll keeps going through transport failures until its `expires_in`
deadline. If it expires after a run of transport failures, the error reports
the control plane as unreachable.

### A refused certificate is reported

Under TLS 1.3 the client sends its certificate after the server's Finished, so a
server that refuses it cannot say so during the handshake: `tls.Dial` returns a
healthy connection and the rejection arrives on the first read as
`remote error: tls: bad certificate`. `localport access` therefore reports the
error from the remote side of the copy and stays quiet about the local side,
where a client tool closing its own connection is ordinary.

The message names what the holder can check: that the identity has been granted
access to the device, and that the certificate is still valid and unrevoked. The
agent is not told why the edge refused, and does not guess.

### CI workload identity (`localport access --audience`)

A pipeline authenticates with a token its own platform minted. No secret is
stored in the repository, in the CI secret store, or on disk.

```
1  operator creates a setup token with source=oidc; the dashboard returns an
   AUDIENCE (lpa_...) generated by the control plane
2  the job declares `permissions: { id-token: write }`
3  the agent asks the runner for a token stamped with that audience
4  POST /v1/mtls/certs with `X-Workload-Token: <jwt>` and a CSR
5  the certificate is held in memory for the life of the process
```

Detection order:

| Source | When |
|---|---|
| `LOCALPORT_OIDC_TOKEN` | checked first; covers GitLab `id_tokens:`, Buildkite, a projected Kubernetes service-account token |
| GitHub Actions | `ACTIONS_ID_TOKEN_REQUEST_URL` + `ACTIONS_ID_TOKEN_REQUEST_TOKEN` present |

The audience must be supplied (`--audience` or `LOCALPORT_OIDC_AUDIENCE`). The
platform stamps it into the token, so the agent needs it before asking for one.
It is not a secret.

Nothing is written to disk and there is no renewal loop. The certificate lives
as long as the job.
