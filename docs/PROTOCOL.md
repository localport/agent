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
process on the same device identity cannot hold its `.sessions.lock` (see
[Stored identity](#stored-identity-localport-identity)) and opens no session mux
either.

Bind: a new connection over the control connection's carrier, first frame
`MuxBind` with `purpose: "session"`, authenticated as any `MuxBind`.

After `MuxBindAck`, roles reverse relative to the port mux: the edge is the
HTTP/2 server and the agent the client, with prior knowledge (no ALPN). The
agent advertises `SETTINGS_MAX_FRAME_SIZE` 16 KiB and an initial stream window
of 128 KiB, and raises the connection window by 21 x 128 KiB. It pings a silent
connection every 30 s, closes it when a ping goes unanswered for 15 s, and
closes it when a write makes no progress for 15 s. It bounds each response's
header list to 4416 bytes as HTTP/2 counts it (name, value and 32 bytes per
field: 4 KiB plus Go's allowance for 10 fields) and advertises that as
`SETTINGS_MAX_HEADER_LIST_SIZE`. It sends `User-Agent: localport-agent` and
asks for no compression. The edge allows 21 concurrent streams: the accept
stream, 16 session streams, 2 recording segment requests, 1 recording open and
1 recording complete or failed open (see
[Session recording](#session-recording)). The edge refuses a
17th session on one mux with the end reason `agent_closed`.

Accept stream: the agent's first request is `POST /v1/session-accept` with no
body (`END_STREAM` on its headers). The edge answers `200` and holds the
response open for the life of the mux. Each session is one notice on it:

| Bytes | Meaning                                                        |
| ----- | -------------------------------------------------------------- |
| 4     | `uint32` big-endian length, always 24                          |
| 16    | session id: the bytes of the UUID the stream's access row carries, which each recording of a channel opened while the stream carries the connection names |
| 8     | `uint64` big-endian serial of the SSH user certificate the edge admitted |

A notice of any other length, or the accept stream ending, ends the mux.

Session stream: for every notice the agent opens `POST /v1/session` with header
`Localport-Session-Id: <32 lowercase hex chars>` (the id from the notice), so
every refusal travels on the stream itself. At most 16 opens wait for their
response headers at once: with 16 in flight the agent reads one more notice,
whose open waits for a slot, and reads no further notice until an open ends. It
resets an open whose headers do not arrive within 30 s. The request body is
agent-to-edge bytes and the response body edge-to-agent bytes. The edge answers
`404` to an id it is not waiting for on this mux. On `200` the stream carries
the resume prelude, then frames that carry one SSH connection (RFC 4253)
between the client (browser or `ssh-proxy`, relayed unparsed by the edge) and
the agent's SSH server (see [Resumable connections](#resumable-connections)).
A first connect starts a connection; a resume moves a detached one onto the
stream:

1. Server identity: version `SSH-2.0-localport`; host key the device key of the
   last acknowledged registration (`ecdsa-sha2-nistp256`), the key whose SPKI
   SHA-256 the certificate's device option names and the mint response hands
   the client. Key exchange `mlkem768x25519-sha256`, then `curve25519-sha256`;
   ciphers `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`,
   `aes128-gcm@openssh.com`; MACs `hmac-sha2-256-etm@openssh.com`,
   `hmac-sha2-512-etm@openssh.com`. The prelude must finish within 10 s of
   the stream's start, and the handshake and userauth within 10 s of the
   connection's start, apart from a keyboard-interactive prompt, which has
   5 minutes of its own.
2. Userauth: `publickey` with an SSH user certificate only, at most 3 attempts.
   After the client proves possession of the certificate's key, the agent
   accepts it only when all of these hold; every refusal is a userauth failure
   and is logged:

   | Check |
   | ----- |
   | a registration was acknowledged (its key is the host key) |
   | a user certificate for the key the first connect's prelude bound the connection to |
   | a user certificate whose serial is the notice's serial |
   | signed by a session CA key the agent holds (`ticket_keys.json`); an unknown CA key triggers one key fetch (at most 3 s, at most once per 5 minutes) and one retry |
   | valid now within 30 s of skew, for the user name as its principal |
   | exactly the critical options `device@localport.io`, naming this device's prefix and registered key (`spki_sha256`), and for a `files` or `ssh` certificate `files@localport.io`: the file directions its SFTP channels may use, one of `""`, `download`, `upload`, `download,upload` (any other value, or a `files` or `ssh` certificate without it, is refused), and for a `vnc` or `rdp` certificate `clipboard@localport.io`: the clipboard directions of its desktop channel, one of `""`, `copy`, `paste`, `copy,paste` (any other value, a desktop certificate without it, or the option on another kind, is refused) |
   | the kind (`kind@localport.io`) enabled in the local config (`terminal` and `ssh` need `terminal`, `files` needs `files`, `rdp` and `vnc` need `desktop` and that target) and served by this agent (`terminal`, `ssh`, `files`, `rdp`, `vnc`) |
   | for `terminal`, `ssh` and `files`: the user name listed in the local `logins`; for `rdp` and `vnc`: the user name `localport-desktop` and no `rec@localport.io` (a desktop session is never recorded) |
   | a `rec@localport.io`, when present, naming the held team recording key; a mismatch triggers one key fetch, under the same floor, and one retry |

   On Windows, a user name listed in the device's `password_logins` then needs
   `keyboard-interactive` with one prompt, `Windows password: `, without echo: the
   certificate step answers partial success and names only that method, so a
   keyboard-interactive attempt never stands alone. An empty answer, or one
   over 256 bytes, fails userauth. The agent holds the answer for the
   connection's life, passes it to each channel's launcher request, which logs
   the login on with it, and clears it when the connection ends.

   At most 8 connections run at once, detached ones included; a first connect
   past that, or one arriving while the agent shuts down, is refused in the
   prelude.
3. Channels: `session` channels, and on an `ssh` connection the port
   forwarding channels below (others are refused `prohibited`); a `terminal`
   connection has one session channel, an `ssh` or `files` connection at
   most 4 open at once. On a session channel of a `terminal` or `ssh` connection the
   agent accepts `pty-req` (cols and rows 1 to 1000, term matching
   `^[a-zA-Z0-9.+-]{1,32}$`), `window-change`, `shell` (with a PTY: the login
   shell on a terminal; without one, on `ssh` only: the login shell on pipes)
   and, on `ssh` only, `exec` (a command of at most 2 KiB, run by the login
   shell with `-c`, on Windows as `"%SystemRoot%\System32\cmd.exe" /c
   "<command>"`, on a PTY when one was requested, else on pipes with stdout
   and stderr apart). `subsystem` `sftp` is accepted on `ssh` and is the only
   request a `files` connection accepts. `env` is accepted before `shell`,
   `exec` or `subsystem` for `LANG` and `LC_[A-Z]{1,24}` only: at most 16 per
   channel, each value at most 256 bytes of UTF-8 without control characters,
   names and values together at most 1 KiB; the helper sets them after the
   login's environment. It refuses every other `env`, other subsystems,
   `x11-req`, `auth-agent-req@openssh.com`, `signal`, and every global request
   other than the port forwarding requests below. Each `shell`, `exec` or `subsystem` is one
   launcher request of kind `terminal`, `exec` or `sftp`; an `sftp` request
   serves the SFTP protocol (version 3) as the login, confined to the
   device's `files_root` or the login's home, opening only regular files and
   directories and writing in place at the requested offsets. The request
   carries the certificate's `files@localport.io` access (`files_download`,
   `files_upload`; only an `sftp` request may): without download an open for
   reading is refused `SSH_FX_PERMISSION_DENIED`, a read-write open needs both
   directions, and without upload every change (open for writing,
   setstat, rename, posix-rename, remove, mkdir, rmdir, symlink, link) is, as
   OpenSSH `sftp-server -R`; listing, stat, readlink and realpath are always
   served, and each refusal is a file event with result `permission_denied`.
   A shell or exec on an `ssh` connection is not restricted by it. A refusal fails
   the request and writes
   `localport: <code>` to the channel's stderr (`login_not_allowed`,
   `kind_disabled`, `agent_busy`, `kind_unavailable`, `launcher_unavailable`,
   `recording_unavailable` for a Strict channel whose recording did not open).
   The helper's exit becomes `exit-status`, or for a Unix helper killed by a
   signal `exit-signal` (the RFC 4254 name without `SIG`, `<name>@localport.io`
   outside its list, core-dumped false), then the channel closes; a Strict
   channel whose recording fails ends with
   `localport: session ended: recording_failed`.

   Port forwarding (RFC 4254 section 7, OpenSSH PROTOCOL section 2.4) is
   served on an `ssh` connection only, when the device's config enables
   `forwarding` and the certificate carries the direction's flag extension:
   `port-forwarding-local@localport.io` for local forwards,
   `port-forwarding-remote@localport.io` for remote forwards. Otherwise a
   forwarding channel is refused `prohibited` and a forwarding global request
   is answered false.

   | Direction | Requests | Platforms |
   | --------- | -------- | --------- |
   | local | channel `direct-tcpip`, any destination | all |
   | local | channel `direct-streamlocal@openssh.com`, an absolute path of at most 104 bytes | Linux, macOS |
   | remote | global `tcpip-forward`, `cancel-tcpip-forward`: bound on `127.0.0.1` (on `::1` when the client names `::1`) whatever address the client names; port 0 answers the bound port; each accepted connection opens a `forwarded-tcpip` channel | all |
   | remote | global `streamlocal-forward@openssh.com`, `cancel-streamlocal-forward@openssh.com`: socket created with mask 0177, an existing path refused; each accepted connection opens a `forwarded-streamlocal@openssh.com` channel | Linux, macOS |

   A local forward whose dial fails is refused `connect failed` with the
   helper's code (`connection_refused`, `unreachable`, `permission_denied`,
   `address_in_use`, `path_exists`, `unsupported`, `invalid`, `limit`) as its
   message. One connection holds at most 32 forward channels (local and
   forwarded together) and 8 remote listeners; the device's connections
   together hold at most 64 forward channels. Past a limit a channel is
   refused `resource shortage` and a listen is answered false. Session
   channels keep their own limit of 4.

   Every dial and listen runs in the connection's networking helper: a
   launcher request of kind `forward` at the first allowed forward starts it
   as the login, and it ends with the connection. On Linux and macOS it
   passes each connected socket back to the agent, which relays the socket
   and the channel directly; on Windows each forward's bytes ride the
   helper's pipe with a 64 KiB credit window per forward and direction. When
   the helper exits, the connection's forwards end and later forwarding
   requests on it are refused (`helper_failed`); the connection continues.
   Forwarded data, both ways, counts as activity for the idle timer.

   A desktop connection (`rdp` or `vnc`) serves one channel of its kind's
   type, `rdp@localport.io` or `vnc@localport.io`, with an empty open
   payload, and nothing else: any other type (`direct-tcpip` and the other
   kind's type included) or a payload is refused `prohibited`, a second
   channel `resource shortage`, and every global request is answered false.
   A `prohibited` refusal before the channel opened ends the connection;
   one after it leaves the channel serving.
   The agent dials the device's configured target of the kind itself, with
   a 10 s timeout, without a helper. A failed dial refuses the channel
   `connect failed` with `connection_refused` or `unreachable` (a timeout
   included); the channel is accepted only after the dial succeeds.

   The handshake before the relay is bounded. From the channel's accept, the
   client has 30 s to send its part, up to the last client read before the
   key question (for `rdp` the request PDU; for `vnc` the client's last
   version, type or VeNCrypt reply); past it the connection ends
   `desktop_handshake_timeout`. Each target read and write has a 30 s
   deadline, which ends it `desktop_handshake_timeout` too; the deadlines
   are cleared before the relay. Waiting for the reply to
   `desktop-key@localport.io` has no handshake bound. Both bounds keep
   running while the connection is detached, so a network drop during the
   handshake ends it rather than resuming it. A target EOF or I/O error
   before the relay ends `desktop_target_closed`; a client EOF or close ends
   it `exited`, with nothing told.

   On a `vnc` connection the agent reads the VNC handshake (RFC 6143 section
   7.1, as noVNC speaks it), forwarding each byte it admits unchanged: the server's
   ProtocolVersion (`RFB ddd.ddd\n`; the repeater's `000.000` is refused),
   the client's (`RFB 003.003`, `003.007` or `003.008`), the security type
   list and the client's choice (3.3: the server's `u32` choice), and for
   VeNCrypt (19) its versions, ack, subtypes and the client's subtype. When
   the choice or the VeNCrypt subtype is RA2ne (6) it reads the server's RSA
   key (`u32` bit length, 1024 to 8192, then modulus and exponent of
   `ceil(bits/8)` bytes each) and holds it for the key step below, whose
   key is the SHA-256 of exactly those length, modulus and exponent bytes;
   the key question's payload is that hash in lowercase hex (SSH string)
   and whether it is pinned (boolean). After a true reply or a pin match it
   forwards the key. Once a key is pinned for the target, a handshake that
   chooses no RA2ne ends `desktop_key_downgraded`. A malformed handshake
   ends `desktop_handshake_invalid`.

   The security types are those noVNC 1.7.0 runs and the agent frames: None
   (1), VNCAuth (2), RA2ne (6), Tight (16), VeNCrypt (19), XVP (22), ARD (30)
   and MSLogonII (113); VeNCrypt subtypes None, VNCAuth, RA2ne, Tight, XVP,
   ARD, MSLogonII and Plain (256). Any other choice, every stream-encrypting
   type included (RA2 5, VeNCrypt TLS and X509 257 to 262), ends the
   connection `desktop_protocol_violation` before it reaches the other side.
   A server's refusal (type 0 under 3.3, an empty list under 3.7 and 3.8) is
   forwarded with its reason of at most 4 KiB and ends the connection.

   The agent then frames the rest of the handshake per security type,
   forwarding each message: authentication, the Tight NOTUNNEL tunnel and
   None, VNCAuth or UnixLogon (129) sub-authentications only, SecurityResult
   (a failure and its 3.8 reason are forwarded and end the connection),
   ClientInit and ServerInit. Every length is bounded before it is read. After
   ServerInit it frames every message in both directions, and streams
   rectangle bodies as they arrive. These end the connection
   `desktop_protocol_violation`: an unknown message type, a length past its
   bound, a rectangle in an encoding no forwarded `SetEncodings` kept, a
   negative `CutText` length, a `SetPixelFormat` after the first
   `SetEncodings`, `FramebufferUpdateRequest` or `EnableContinuousUpdates`, a 24-bit
   `SetPixelFormat` of 8-bit channels at shifts that are not byte-aligned, and
   an extension message whose pseudo-encoding no forwarded `SetEncodings` kept.

   Client to server the agent allows `SetPixelFormat` (8, 16 or 32 bits per
   pixel), `SetEncodings`, `FramebufferUpdateRequest`, `KeyEvent`,
   `PointerEvent`, `ClientCutText`, and with their pseudo-encoding
   `EnableContinuousUpdates`, `ClientFence`, `SetDesktopSize`, xvp and the
   QEMU extended key event. `SetEncodings` is forwarded reduced to Raw,
   CopyRect, RRE, Hextile, Zlib, ZRLE, Tight, TightPNG and the pseudo-encodings
   quality level, compress level, DesktopSize, LastRect, ExtendedDesktopSize,
   DesktopName, Cursor, XCursor, Fence, ContinuousUpdates, QEMUExtendedKeyEvent,
   QEMULedEvent and Xvp; every other entry is removed, Extended Clipboard
   (0xC0A1E5CE), ExtendedMouseButtons, H.264 and JPEG among them. Server to
   client it allows `FramebufferUpdate`, `SetColourMapEntries`, `Bell`,
   `ServerCutText`, `EndOfContinuousUpdates`, `ServerFence` and xvp.

   `ServerCutText` passes only when the connection's current certificate
   allows `copy`, `ClientCutText` only when it allows `paste`, and each only
   up to 1 MiB. A refused `CutText` is consumed and the session continues. A
   resume certificate's directions apply from its next `CutText`. Typed
   keystrokes and the screen are not restricted.

   On an `rdp` connection the agent is an RDCleanPath gateway (the protocol
   IronRDP's web client speaks). It reads one DER RDCleanPath request PDU
   of at most 16 KiB: version 3390, a `destination` and an
   `x224_connection_pdu`, optionally `proxy_auth`, and no other field (a
   `preconnection_blob`, `server_auth` or the VMConnect form is refused);
   `destination` and `proxy_auth` are ignored and never logged, and bytes
   after the PDU enter the relay first. The X.224 Connection Request, one
   TPKT of at most 512 bytes whose length field equals its size, goes to
   the target unchanged. The target's Connection Confirm is read as one
   TPKT of 11 to 512 bytes: a Negotiation Failure is sent to the client as
   an RDCleanPath error PDU (code 2, the confirm as `x224_connection_pdu`)
   and ends `rdp_negotiation_failed`; a confirm without a Negotiation
   Response (Standard RDP Security) or selecting a protocol other than TLS
   (1), CredSSP (2) or CredSSP with Early User Authorization Result (8) ends
   `rdp_security_refused`. The agent then runs TLS 1.2 or later with the
   target, without a server name and without chain verification; a TLS
   alert or protocol error ends `rdp_tls_failed`. The key is the SHA-256 of
   the leaf certificate's SubjectPublicKeyInfo; the key question's payload
   is, as SSH wire values: string that hash in lowercase hex, boolean
   pinned, string the certificate's SHA-256 (whole DER) and string its
   SHA-1 (the Windows thumbprint), both lowercase hex, string subject and
   string issuer (RFC 4514, each at most 512 bytes), boolean self-signed
   (subject and issuer equal), uint64 notBefore and uint64 notAfter (Unix
   seconds). After a true reply or a pin match the agent sends the
   RDCleanPath response PDU (version 3390, the confirm as
   `x224_connection_pdu`, every peer certificate's DER leaf first as
   `server_cert_chain`, the configured target as `server_addr`) and relays
   the channel and the TLS plaintext through its RDP filter; nothing from
   the target reaches the client before then. A malformed request or
   confirm ends `desktop_handshake_invalid`.

   The RDP filter frames every byte of the plaintext and forwards only what
   it frames; anything else ends the connection `desktop_protocol_violation`
   (section numbers are those of MS-RDPBCGR, MS-RDPECLIP and MS-RDPEDYC):
   - CredSSP, under CredSSP (2) and CredSSP with Early User Authorization
     Result (8): each TSRequest in either direction is one DER SEQUENCE
     (tag 0x30) of at most 64 KiB with definite lengths, read by its outer
     length, so bytes glued after it are framed on their own. The client's
     exchange is over at its TSRequest carrying `authInfo`; under protocol 8
     the server's 4-byte Early User Authorization Result (0 or 5) follows.
     The next client byte must start a TPKT. Under TLS (1) the first byte
     must.
   - Slow path: a TPKT of at most 16 KiB plus 4 holding one X.224 Data TPDU
     with EOT set and one MCS PDU: client to server Connect Initial (first),
     Erect Domain, Attach User, Channel Join, Send Data Request and
     Disconnect Provider Ultimatum; server to client Connect Response
     (first), Attach User Confirm, Channel Join Confirm, Send Data
     Indication and Disconnect Provider Ultimatum. Fast-path PDUs (action 0,
     no security flags) are framed by their length and forwarded; they
     carry no channel data (2.2.8.1.2, 2.2.9.1.2).
   - Static channels: the Connect Initial's CS_NET (at most 31 channels)
     may name only `drdynvc` and, when the certificate allows a clipboard
     direction, `cliprdr` (names compared case-insensitively). Any other
     name, or `cliprdr` with no direction allowed, ends the connection
     `desktop_channel_refused` before the Connect Initial reaches the
     target; the agent never rewrites CS_NET. The Connect Response must
     select no RDP Standard Security encryption; its SC_NET maps the names
     to channel ids. Send Data on any id other than the I/O channel, the
     message channel, the user channel from Attach User Confirm and the
     mapped `cliprdr` and `drdynvc` ids, or a client Send Data from another
     initiator, ends the connection.
   - Chunks: on `cliprdr` and `drdynvc` a chunk with `CHANNEL_PACKET_COMPRESSED`
     or a compression type, or larger than the negotiated chunk size, ends
     the connection. The chunk size is the server's `VCChunkSize` when both
     the Demand Active and the Confirm Active carry it (a server value
     outside 1,600 to 16,256 ends the connection), else 1,600 (3.1.5.2.1);
     a Deactivate All starts a new exchange. Chunks reassemble by
     `CHANNEL_FLAG_FIRST` and `LAST` up to 1 MiB plus 64 KiB on `cliprdr`
     and 1,600 bytes on `drdynvc`; a successful Format Data Response past
     the bound is discarded chunk by chunk, not buffered. The agent writes
     the messages it forwards or sends in chunks of the negotiated size.
   - Dynamic channels (`drdynvc`): the agent frames Capabilities (5),
     Create (1), Data First (2), Data (3) and Close (4) (2.2). The client's
     Capabilities Response must carry version 1 or 2, so compressed data,
     which needs version 3 on both sides (2.2.3.3, 2.2.3.4), never appears;
     a version 3 response, Data First Compressed (6), Data Compressed (7)
     and Soft-Sync (8, 9, which serve multitransport tunnels only) end the
     connection. Only `Microsoft::Windows::RDS::DisplayControl` opens: the
     agent answers a server Create Request for any other name with a
     Create Response of `STATUS_NOT_FOUND` (0xC0000225) and the client never
     sees it. Data on a channel the client did not create successfully, in
     either direction, ends the connection; a Close for one is dropped.
   - Clipboard (`cliprdr`), per the connection's current certificate:
     Clipboard Capabilities pass with `CB_STREAM_FILECLIP_ENABLED`,
     `CB_FILECLIP_NO_FILE_PATHS`, `CB_CAN_LOCK_CLIPDATA` and
     `CB_HUGE_FILE_SUPPORT_ENABLED` cleared; Monitor Ready passes server to
     client. A Format List from the server passes only when `copy` is
     allowed, from the client only when `paste` is, reduced to CF_TEXT (1),
     CF_OEMTEXT (7), CF_UNICODETEXT (13) and CF_LOCALE (16). A list refused
     or reduced to nothing is answered by the agent with a Format List
     Response OK, and when the receiver held a list in that direction the
     agent sends it an empty Format List and absorbs its answer; a resume
     that narrows a direction does the same at the next `cliprdr` PDU. A
     Format Data Request passes only for a format of the list the agent
     forwarded that way; the agent answers any other with
     `CB_RESPONSE_FAIL`, in order behind the answers to earlier requests (at
     most 64 outstanding per direction). A Format Data Response passes only
     as the answer to the oldest outstanding request, while its direction is
     allowed, and up to 1 MiB; otherwise the requester gets
     `CB_RESPONSE_FAIL`. A File Contents Request is answered
     `CB_RESPONSE_FAIL` with its stream id; File Contents Responses, Lock,
     Unlock and Temporary Directory are dropped. Every length is checked
     before use. Typed keystrokes and the screen are not restricted.

   The key step, both kinds: a key other than the one pinned for the
   device's target of the kind ends the connection `desktop_key_changed`
   (the agent logs the target and both hashes); otherwise the agent sends
   the channel request `desktop-key@localport.io` (want-reply true) with
   the kind's payload. A false reply ends it `desktop_key_rejected`; a true
   one pins an unpinned key. An unreadable pin store ends
   `desktop_key_unavailable`. The pins live in `desktop_pins.json` (see
   Stored identity); `localport set <device> --rdp-reset-pin` or
   `--vnc-reset-pin` forgets the kind's pin, or removes the whole file when
   it is unreadable.

   The agent then relays the channel and the target until either ends; the
   channel's end, or its refusal after the dial, ends the connection, and
   every end of the connection closes the target connection. The agent
   answers every other request on the channel false. Only data from the
   client on the channel counts as activity for the idle timer; target
   output and global requests do not. A recorded
   connection writes an asciicast event `p` at each listen, cancel, forward
   open and forward close (direction, kind, address, result, bytes in and
   out), never the forwarded bytes; under Strict a `p` event the recorder
   cannot take ends the connection `recording_failed`.
4. End: the agent closes the connection, after writing
   `localport: session ended: <reason>` to each open channel's stderr, for
   `idle` (30 minutes without client channel data or a request; on a desktop
   connection, without client channel data),
   `shutdown` (the control session is ending), `config_changed`
   (`localport set` changed the device's entry and the agent reloaded it; the
   device's other sessions end too), `exited` (the channel of a `terminal`
   or desktop connection, or the last channel of a `files` connection, closed or
   was refused, a Strict
   recording failure on it included), the desktop handshake's
   `desktop_handshake_timeout`, `desktop_target_closed`,
   `desktop_key_changed`, `desktop_key_downgraded` (`vnc`),
   `desktop_key_rejected`, `desktop_key_unavailable`,
   `desktop_handshake_invalid`, `rdp_negotiation_failed`,
   `rdp_security_refused` and `rdp_tls_failed` (`rdp`) (step 3),
   `desktop_protocol_violation` (step 3, also during the relay),
   `desktop_channel_refused` (`rdp`, during the relay),
   `recording_failed` (a Strict
   connection's port forwarding events could not be recorded) and, on one
   channel, `helper_failed` (the session helper's channel ended without an
   exit). A client that closes the
   connection ends it without a reason. A desktop connection's channel has no
   stderr: before closing it for a reason, unless the channel already ended,
   the agent sends the channel request `end@localport.io` (want-reply false)
   whose payload is one SSH string, the reason (one or more of `[a-z_]`).

Reconnect: a failed dial or bind, and a mux that drops, are retried for the
life of the control session with full-jitter backoff from 1 s, doubling to a
60 s cap. The backoff resets only after a mux whose accept stream the edge
answered with `200` stayed up for 30 s; a bind that is acked but whose accept
stream fails, or a mux that drops sooner, keeps it growing. The first failure
after a reset is logged as a warning, later ones at debug level. The port mux
is independent of it.

Stop: when the control session ends or the agent stops, the agent first asks its
session handler to shut down (connections end with `shutdown`, handshakes in
progress are aborted, session processes are ended: SIGHUP, then SIGKILL at
5 s, and each channel waits at most 3 s for its recording's final segment
to reach the uploader),
waits for that at most 10 s, then closes the mux connection. The connection is
never closed before that step.

## Resumable connections

A session connection survives a lost stream (network drop, edge restart,
fleet re-pin) for 5 minutes: the layer runs below SSH, so every channel and
forward carries on. Code: `agent/internal/session/resume.go`,
`resume_prelude.go`; the browser's copy is `web/wasm/sshclient/client` (the
two pin one wire vector, `TestResumeWireVector`). A connection does not
survive an agent restart.

Prelude messages are a 4-byte big-endian length (at most 16 KiB) and the x/crypto
SSH wire encoding of one message (`sshtype` 160 to 165, version 2; the agent
refuses any other version). The edge relays them like any bytes.

| Step | Sender | Message |
| --- | --- | --- |
| first connect | client | hello: version, fresh X25519 key, the certificate the edge admitted, the client's signature (its certificate key) |
| | agent | hello reply: status, fresh X25519 key, a random 16-byte handle, its host key, its host-key signature |
| resume | client | resume: version, handle, fresh X25519 key, bytes received, close (boolean), the resume certificate, the client's signature |
| | agent | resume reply: status, fresh X25519 key, bytes received, its host-key signature |
| | client | proof: `HMAC-SHA256(token, transcript)`, sent only after it verified the reply under the pinned host key |
| | agent | proof reply: status |

- Signatures cover SHA-256 of the messages so far with their signature fields
  empty, prefixed by `localport-resume-client-v1` or `localport-resume-agent-v1`
  and a zero byte. The token is HKDF-SHA256 over the first connect's X25519
  shared secret, salted with its transcript, info `localport-resume-v1`; it
  never crosses the wire, so a relay cannot resume.
- The agent admits a hello as userauth admits a certificate (table above,
  serial the notice's), and binds the connection to the certificate's key. It
  admits a resume only for a live handle, with a resume certificate (critical
  options exactly those of the table above plus `resume@localport.io`, naming
  the original serial in lowercase hex) for the same subject, kind,
  login and key that passes the local checks a hello does (kind and login
  enabled, recording key held, table above), and only then checks the proof,
  before it resends anything.
  An installed resume runs the connection under the resume certificate and
  the resume stream's session id: later recordings name that id and carry
  that certificate, and its forwarding extensions apply from then on, so a
  direction it no longer allows ends that direction's listeners and
  forwarded connections; an SFTP channel started with a file direction its
  `files@localport.io` no longer allows ends `files_narrowed`, written to
  its recording as an asciicast marker of that label. A resume whose
  certificate names a recording that a started channel or the running forwards
  helper cannot meet (never recorded, under either policy, or recording failed
  under Strict) is answered 3 and ends the connection with the logged reason
  `recording_required`; a start in progress across such a resume is refused
  with `recording_required`.
- Statuses: 0 ok, 1 `resume_refused`, 2 `resume_busy` (another resume of the
  handle runs; retry), 3 `resume_lost` (no such connection, or a position
  outside the send buffer). Three failed proofs end the connection
  `resume_refused`. A resume of a handle whose stream is still attached
  detaches that stream first.
- A close resume (close true) is how a client that lost its stream ends the
  connection at once instead of leaving it to the detach deadline. It passes
  every check a resume does, proof included; the agent then answers 0 and
  ends the connection as a received closeTag does, whatever the position, and
  no later resume of the handle attaches. A refused close resume leaves the
  connection detached.

After the prelude each side sends frames `uvarint ack | uvarint len | data`:
`ack` is the count of bytes received since its last ack, `data` at most
128 KiB. A side keeps every byte it wrote until it is acked, at most 2 MiB; a
write blocks while the buffer is full. A resume resends from the position the
peer reported. A deliberate close (the SSH layer closes the connection, or
`ssh-proxy`'s input ends) sends what is buffered, then the ack value
`0xffffffffffffffff` (closeTag): the peer ends the connection instead of
waiting. The closing side keeps reading until the peer closes the stream, at
most 2 s.

On the agent a stream that ends without a closeTag detaches the connection:
it keeps its session slot, channels and helpers, and every recording gets an
asciicast marker `detach` (then `attach` on a resume). The detach deadline is
fixed when the connection's last stream ends, 5 minutes later, and only an
installed resume clears it: a refused or failed resume attempt never moves
it (the handle is not secret). An attempt in progress is not cut off; a
deadline that passed meanwhile ends the connection `detach_timeout` when the
attempt ends. Attempts on one connection run one at a time: a resume
arriving while another attempt runs is `resume_busy`, and one arriving after
the deadline with no attempt running is `resume_lost`. Shutdown, a config change, the idle timeout and a handler panic
end detached connections as attached ones.

## Session recording

A `terminal`, `ssh` or `files` certificate may carry `rec@localport.io`:
`{"policy","pub_sha256"}`, where `pub_sha256` is the unpadded base64url
SHA-256 of the team recording public key (43 characters) and `policy`
`best_effort` or `strict`; the userauth checks are in the table under
[Session mux](#session-mux). On a recorded connection every `shell`, `exec`
or `sftp` subsystem opens its own recording before its helper starts: a fresh UUIDv7 recording id,
and the session id from the notice (`session_id`) of the stream the connection runs on (a resume's, after a resume), so every
channel of every connection, including multiplexed channels (OpenSSH
ControlMaster) and repeat connections on one certificate, has its own
recording. A Strict channel whose open fails within 5 s is refused
(`recording_unavailable`) and other channels are unaffected; a Best effort one
runs unrecorded. A recorded `shell` or `exec` writes
`localport: this session is recorded` to its stderr before any helper
output; an `sftp` channel, whose client shows no stderr, does not. The agent records the channel's output, resizes and exit,
seals it in segments and delivers them over its session mux. The open carries
the admitting certificate (`certificate`, base64url, at most 8 KiB), from
which the control plane creates the recording's row; the edge forwards the
open only for a connection its session mux carries and adds when it admitted
that certificate, so a channel that starts after a short-lived certificate
expired is still recorded. The spool's `meta.json` keeps the certificate and
the session id so a resumed open after a restart sends them again. Code:
`internal/recording/`, `internal/session/recorder.go`,
`internal/tunnel/recording_client.go`.

Format: the plaintext is asciicast v3, one JSON line per event (header, then
`o` output, `r` resize, `f` file activity and `x` exit events; an `sftp`
channel's header has the default size, 80 by 24). An `f` event's data is a
JSON object string: `op` (`exec`, `read`, `write`, `mkdir`, `rmdir`,
`remove`, `rename`, `setstat`, `symlink`, `link`, `list`), `path`, `target`
(rename, symlink, link), `command` (exec, at most 2 KiB), `bytes` (read and
write: one event when the handle closes, with the bytes moved) and `result`
(`ok`, `no_such_file`, `permission_denied`, `file_exists` or `failure`;
absent on `exec`). The agent writes the `exec` event from the request when the
command starts; the SFTP server sends the others to the agent on its own pipe,
and an event that fails validation ends the channel. `path` and `target` are
at most 4 KiB: bytes that are not valid UTF-8, control characters and the
backslash are written as `\xNN`, and a longer name is cut and ends with `...(truncated)`.
An `sftp` channel's recording holds its `f` events only, never the protocol
bytes it carries. Players skip codes
they do not know, as asciicast v3 requires. A segment holds whole lines and
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

- open: `lp("localport-recording-open-v2") || lp(id) || lp(session_id) || lp(SHA-256(wrapped_dek)) || lp(key_sha256)`
- failed open: `lp("localport-recording-open-failed-v1") || lp(id) || lp(session_id) || lp(key_sha256) || lp(reason)`, `key_sha256` being the hash the admitting certificate names
- complete: `lp("localport-recording-complete-v1") || lp(id) || lp(SHA-256(wrapped_dek)) || segments (uint32 BE) || lp(final_hash) || ended_at (uint64 BE, Unix seconds) || incomplete (1 byte) || final (1 byte) || lp(reason)`

Test vectors, pinned by the agent (`internal/recording/sealer_test.go`
`TestDigestGoldenVectors`) and by the control plane's tests. Inputs: id
`0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b`, session_id
`0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60`, wrapped_dek the 100 bytes `0x00..0x63`,
key_sha256 32 bytes `0xaa`, ended_at 1767225600.

| Message | Fields | SHA-256 (hex) |
|---|---|---|
| open | as above | `1fd36cf1ee83db594888e6f756215db9f0da2d54010de28871dd26bd07aa1b80` |
| failed open | reason `spool_full` | `a307228e2e7c2275b8773203aeafef41f8c97adf675c3ad565762de0d2c72ff9` |
| complete | segments 3, final_hash 32 bytes `0x11`, incomplete 1, final 0, reason `spool_full` | `92888520be1ffa46e439c6bd69fe2f649229a2fd30069502ca2d3a620dce86a9` |
| complete | segments 0, empty final_hash, incomplete 0, final 0, empty reason | `13f8d36b55dfc5860e976202b9cc377f9be382876974a2bbd5621c2db827109f` |
| chain | `h_0` = SHA-256(`0x00`), `h_1` = SHA-256(`0x01`): `chain_1` | `9b7558cb7f9026dd06976425c566b059852482d41d70b9be604842e13bb87320` |

The spool and memory hold only unsigned fields; every open and complete is
signed when it is sent, so a renewed certificate signs on the next mux.

Wire: each request is one stream on the session mux, every one with header
`Localport-Recording-Id` (the canonical 36-character UUID). JSON byte fields
are unpadded base64url.

| Request | Body | `200` answer |
| ------- | ---- | ------------ |
| `POST /v1/recording/open` | `{"wrapped_dek","signature","certificate","session_id"}` (`session_id` the canonical UUID of the stream the connection runs on, a resume stream's after a resume; only an open while the mux carries that stream can create the recording, a later one reopens it and a missing recording is `recording_not_found`) | `{"status","segments","chain"}`: the segments the server holds and its chain over them (empty with 0 segments) |
| `POST /v1/recording/open`, header `Localport-Recording-Failed: <reason>` (a failed open: `spool_full`, `disk_low` or `recording_failed`) | `{"wrapped_dek":"","signature","certificate","session_id"}`, signed over the failed open digest | `{"status","segments"}`; moves a recording that never started to `incomplete` with the reason, creating it when it does not exist and the session is attested; a repeat answers `200`, any other recording state `recording_closed` |
| `PUT /v1/recording/segment`, headers `Localport-Segment-Index` (decimal, no sign or leading zeros) and `Localport-Segment-Sha256` (unpadded base64url of `h_i`) | the segment object, at least 18 bytes | `{"status","segments"}`; a segment already stored answers `200` like a fresh one |
| `POST /v1/recording/complete` | `{"segments","final_hash","ended_at","incomplete","final","reason","signature"}` | `{"status","segments"}` |

Every open a live channel or forwards start sends, normal or failed, carries
`Localport-Recording-Session` (the session's canonical UUID) and
`Localport-Session-Channels` (decimal, the recorded starts of that stream so
far, this one included, counted before the start is attempted and from zero on
each resume stream). The edge reads both before it takes a stream slot, so a
`recording_busy` refusal still counts. An open of a spooled entry after an agent
restart carries neither.

Each recorded start reports its outcome: one open, and one failed open when the
start fails before or after that open. A failed open never delays the channel.
It is queued in memory (at most 64, the oldest dropped), kept across a mux loss,
retried with backoff from 1 s to 30 s on `recording_busy`,
`recording_unavailable`, a transport failure or no mux, ended by any other
refusal, and dropped 10 minutes after queuing.

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
always has a stream), 1 open and 1 complete or failed open, and per recording at most one
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
final segment is always spooled and named in `meta.json` before it can be sent,
so a crash after its delivery still completes the recording as final. At
restart a segment file at the sealed count, written just before a crash, is
adopted, with each contiguous one after it. The
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

- Best effort: the channel's open is sent before its helper starts, within
  5 s; when it fails the channel runs unrecorded and no spool entry stays. When the spool
  has no room for a segment's hash, or memory is full and the spool refuses the
  segment, recording stops (indices stay contiguous), the recording completes
  `incomplete` with reason `spool_full` or `disk_low`, and the session
  continues. When the recorder's queue (512 KiB of output not yet sealed) is
  full, recording stops the same way with reason `recording_failed`; terminal
  output never waits for it. An agent without a recording uploader, or whose
  spool has no room for a new recording, runs the session unrecorded.
- Strict: the channel's open is sent before its helper starts, within 5 s.
  Any failure, a missing uploader or no spool room for a new recording
  refuses that channel (`recording_unavailable`) and spawns nothing; other
  channels are unaffected. When the
  spool has no room for a segment's hash, or memory is full and the spool
  refuses the segment, the agent seals what it has, completes `incomplete`
  with reason `recording_failed` and ends that channel with
  `recording_failed`. When the recorder's queue is full, terminal output waits
  for space at most 5 s (less when the channel ends first), then the recording
  and the channel end the same way. A Strict channel whose mux drops keeps
  running while the spool accepts.

Every channel end seals a final segment (the `x` event when the helper
exited) and completes with `incomplete` false unless recording stopped. The
channel's end waits at most 3 s for the final segment to reach the uploader;
past that it ends without it, and the recording completes `incomplete` with
reason `recording_failed` once the stalled handoff returns. A connection
refused for its recording key, or a channel refused because its Strict
recording did not open, is worth one fresh certificate.

## Native SSH clients (`localport ssh`)

The CLI reaches a device's SSH server with the system OpenSSH client and a
consumer credential (`localport login` or `localport setup`). Code:
`internal/cli/ssh.go`, `internal/identity/session.go`.

Mint: `POST /v1/sessions` on the control plane the credential came from, no
session, body `{"device_host","kind","login","client_ssh_pubkey","cert_chain","timestamp","sig"}`:
`kind` `ssh`, `client_ssh_pubkey` the client key in authorized_keys form,
`cert_chain` the credential's certificate PEM, `timestamp` Unix seconds, and
`sig` standard base64 of the credential key's signature over SHA-256 of
`"localport-session-request-v1"`, then `device_host`, `kind`, `login`,
`client_ssh_pubkey`, `cert_chain` and `timestamp` (decimal) each as a 4-byte
big-endian length and its bytes, then `timestamp / 60` as 8 bytes big-endian;
the control plane accepts it within a minute of its clock. The answer is
`{"certificate","url","host_key","device_host"}`: an OpenSSH user certificate
for the client key, valid 5 minutes, whose one principal is the login; the
WebSocket URL on the device's edge; and the device host key
(`ecdsa-sha2-nistp256`). Transport failures, `5xx` and `429` are retried
within the retry budget.

Files, under the state root (the directory holding `identity/`): the client
key `ssh/<team>/<kind>-<identity>/<device-host>` (ed25519, OpenSSH format,
0600, generated on first use, never sent), its certificate beside it as
`<device-host>-cert.pub`, the edge URL as `<device-host>.url`, and
`known_hosts`, one line per device host. `ssh-cert` mints only when the stored
certificate is not for this key and login, or has under 60 s left. It checks
the answer (a user certificate for the client key and exactly the login,
not expired, an `ecdsa-sha2-nistp256` host key, a `wss` URL) before writing,
then replaces the device host's `known_hosts` line with the answer's host key,
writes the URL and the certificate, each atomically, all under the lock
`ssh/.lock`, so concurrent connections mint once.

Stream: `ssh-proxy` dials the URL, sends the certificate in SSH wire form as
the first binary WebSocket message, runs the first connect's prelude with the
host key `known_hosts` holds at start, then carries the SSH connection in
frames (see [Resumable connections](#resumable-connections)). The end of its
input is a deliberate close. A stream lost without the agent's close, with no
close frame or a reason in `sshResumableEnds` (`closed`, `edge_shutdown`,
`edge_lost`, `device_offline`, `agent_closed`, `no_session_mux`, `edge_full`,
`wrong_edge`), is resumed within 5 minutes: a mint with `resume_certificate`
(never written to the certificate file), a new WebSocket with the resume
certificate first, then the resume prelude. Any other close reason, or a final
refusal, is printed as `localport: session ended: <reason>`.

`localport ssh-config <device-host>...` prints, per device:

    Host <device-host>
      ProxyCommand localport ssh-proxy --identity <ref> %r %h
      IdentityFile <key>
      CertificateFile <key>-cert.pub
      UserKnownHostsFile <state root>/known_hosts
      HostKeyAlias <device-host>
      StrictHostKeyChecking yes
      IdentitiesOnly yes
    Match host <device-host> exec "localport ssh-cert --identity <ref> %r %h"

ssh runs the `Match exec` while it reads its config, so the certificate is
fresh before ssh loads it and before the proxy starts; a failed mint leaves
`ssh-proxy` with no usable certificate, so ssh stops at the proxy and never
connects to the host name directly. `localport ssh [login@]<device-host>`
runs the same mint and then the system `ssh` with these options; with an
OpenSSH client older than 9.9 it prints a one-line notice that the
connection uses `curve25519-sha256`, not post-quantum key exchange.

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
virtual account `NT SERVICE\localport-device`: files under its `identity\`
directory grant SYSTEM, Administrators and that account, and only a
privileged process, and only for paths under `identity\`, accepts that
account as an owner or writer. The rest of the directory belongs to
Administrators: the service may read the directory and `agent.yaml`, read and
write `run.lock` (to lock it and record its PID), and cannot open
`agent.yaml.lock`. The
machine-wide directory holds the devices' private keys; keep it out
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
                      the session CA keys (SSH user certificate signers) the
                      device pins
  .keys.lock          serializes ticket_keys.json writers; taken after
                      .renew.lock, never before it
  desktop_pins.json   device only: { <kind>: { target, key_sha256 } }, the
                      desktop target server key a person trusted on the
                      first browser connection, per desktop kind
  .pins.lock          serializes desktop_pins.json writers (the agent and
                      `set --rdp-reset-pin`, `--vnc-reset-pin`); taken alone
  .sessions.lock      held by the one process that serves the device's
                      sessions; taking it removes the session_jti.log and
                      .jti.lock files older agents left
```

Before every read and write, each directory from the base (`LOCALPORT_HOME`,
`~/.localport` or the machine-wide config directory) down to the credential is
opened without following links and must be a directory owned by the agent's
user. The base may be a symlink only when it comes from `LOCALPORT_HOME` or
`$HOME`, and its target must have the same owner. The machine-wide config
directory is never followed. A failing path is refused, never repaired.
`meta.json`, `pending.json`, the certificate, the key, `ticket_keys.json` and
`desktop_pins.json` are opened with `O_NOFOLLOW` (`FILE_FLAG_OPEN_REPARSE_POINT` on Windows) and must be
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
