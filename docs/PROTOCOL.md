# Localport Wire Protocol

Binary control protocol between the agent and an edge server. The same framed
messages ride over one of two TLS 1.3 carriers, both terminating on the edge
HTTPS port (`:443`) and selected by ALPN after a single TLS handshake:

- **`localport-raw/1`** carries the framed bytes directly inside the TLS stream.
  Lowest overhead. The agent tries it first.
- **`localport-ws/1`** wraps the framed bytes in binary WebSocket frames
  (HTTP/1.1 upgrade at `/v1/control`). Traverses DPI and HTTPS-inspecting proxies.

The **multiplexed data plane** is not a third ALPN. The agent opens a second
connection over whichever carrier above the control connection already
established, sends a `MuxBind` frame as its first message, and from there the
connection speaks HTTP/2: the edge opens one stream per inbound visitor
connection instead of asking the agent to dial back. Because it reuses the
working carrier, it passes the same firewalls the tunnel does. An edge that
does not accept the bind, or `--no-mux`, leaves the tunnel working over
dial-back.

Each tunnel and each fleet device in a config opens its own control connection
and its own mux, bound to its own session.

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
| PortsUpdate     | 13  | E → C     | A device's new open ports        |
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
one local service and names its `protocol` (`http`, `tcp`, `tls`). A **device**
joins a fleet, sends no protocol, and serves the ports the dashboard opens on it.
Sending the wrong kind for the token is refused with `PR009`.

`allowed_ports` is a device's optional port ceiling (`--allow-ports`): up to 64
inclusive ranges of ports 1 to 65535. Absent means no ceiling. The edge refuses a
stream to an open port outside it and logs `blocked_by_device`; the agent
refuses it as well. A tunnel that sends `allowed_ports` is refused.

A registering client asserts nothing that access depends on. `client_name`
(the `--name` flag) is the device's name and its address. Whether it may be
reached is decided server-side.

The agent sends no client id. The edge mints one per session and returns it in
`RegisterAck.client_id`.

`agent_version` and `agent_os` describe the binary, not the client. They are
stored with the connection's server-side record for support. Both are
self-asserted and optional, and nothing on the server gates on either.
`agent_version` is the build's version string; `agent_os` is `GOOS/GOARCH`.

`resume_session_id` echoes the `session_id` from this tunnel's previous
`RegisterAck`. When it matches a live session on the edge, that stale session
is replaced in place, so a reconnect after a network drop is instant on
every tunnel kind. It is held in memory only (empty on first connect and after an
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
  "mtls": {
    "enabled": true
  },
  "session_id": "hex32",
  "client_id": "cl_<32 hex>"
}
```

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

The `mtls` field is optional. When present with `enabled: true`, inbound
connections must present a client certificate from one of the authorities the
tunnel trusts. It reports nothing else. Which authorities those are, and what any
certificate may reach, are decided server-side. Consumers verify the server
against system roots.

### PortsUpdate (13) / PortsAck (14)

A device's open ports are set in the dashboard. The list arrives in `RegisterAck`
and is replaced by `PortsUpdate`:

```json
{ "version": 41, "ports": [{ "port": 502, "protocol": "tcp" }, { "port": 80, "protocol": "http" }] }
```

`version` orders the list. A device applies an update only when the version is
higher than the one it holds, and answers every update with the version it
serves:

```json
{ "version": 41 }
```

A removed port stops being served the moment the edge applies the update, and
its live streams are closed at both ends. The edge closes them, and the agent
closes the local sockets it holds for that port when it applies the update. An
added port is accepted by the edge only after this acknowledgement, since
control frames and data streams travel on different connections.

A port the dashboard opens outside the device's `allowed_ports` stays in the
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

`remote_addr` is the L4 peer (host:port) of the inbound connection as seen by the
edge. Agents surface it as the originating address in their live-connections view.

The last three are set for a device: which of its ports to dial, how to treat the
stream, and which identity asked. `consumer` is display text for this agent's own
output and is never forwarded to the local service.

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
| `client_connections` | Too many concurrent clients across the team      | no        |
| `tunnel_count`       | Team hit its max tunnel count                    | no        |
| `no_plan`            | Team has no active paid or trialing subscription | no        |
| `payment_due_paused` | Team holds a plan, payment is overdue, and its grace window has elapsed | no |
| `blocked`            | Access blocked for this tunnel or team           | no        |

`payment_due_paused` and `no_plan` are both terminal. The first asks the team
to pay an overdue invoice, the second to subscribe. The agent uses `limit_type`
only to pick the hint it appends to `reason`. Whether it reconnects is decided
by `retryable`.

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
  "nonce": "<32 hex chars>"
}
```

Sent as the first frame on a second connection to the edge, over the same
carrier the control connection used (raw or WebSocket). There is no dedicated
ALPN, and the frame type identifies the connection as a mux. It attaches that connection to a session already
registered on the control connection; the edge then opens one HTTP/2 stream per
inbound visitor connection instead of asking the agent to dial back.

The bind is authenticated on its own, because it is dialed separately from the
control connection:

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
what happens when the connection later dies; a mux that bound once is retried.
`--no-mux` skips the attempt entirely.

Streams carry opaque bytes, as a dialed-back connection does, so the same
mechanism serves http, tcp and tls tunnels, and both the primary and the
secondaries of a fanout tunnel. The visitor's address travels in the
`Localport-Visitor-Addr` header on each stream.

The edge decides per inbound connection: a stream when the agent has a live mux,
a `NewConnection` dial-back otherwise.

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
| Client limit              | client connection limit reached                | no        |
| Tunnel limit              | tunnel limit reached                           | no        |
| Tunnel terminated/deleted | tunnel terminated by an administrator          | no        |
| Session replaced          | replaced by a newer session for this tunnel    | no        |
| Unknown fleet device      | this device is not on the fleet: create it ... | no        |
| Fleet device limit        | this fleet has reached its device limit        | no        |
| Duplicate device name     | another device on this tunnel is using this... | **yes**   |
| Token kind mismatch       | invalid token usage                            | no        |
| Protocol / clock          | protocol error, update the agent ...           | no        |

**Unknown fleet device** is non-retryable. Waiting cannot change the answer, and
the message says what to do.

**Duplicate device name** is retryable. A fleet agent that restarts loses its
resume id and collides with its own stale session until the edge clears it. Two
devices that share a name keep failing with the same message.

Certificate / mTLS failures on a consumer connection surface at the TLS
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

## Data streams on the multiplexed connection

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
| `403`  | the identity has no access, or the port is not open           |
| `502`  | nothing is listening on that port on the device               |
| `503`  | the device is busy                                            |

The connection is closed when the device disconnects, when the certificate
chain expires, when a grant is narrowed, and when the certificate is revoked.
The command re-dials on the next forward, and the new attempt is refused if the
grant no longer covers it. An idle connection is pinged after 30 s and dropped
if the ping goes unanswered for 15 s.

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

- **Both URIs are printed, and the prefilled one leads.** `verification_uri_complete`
  (RFC 8628 §3.3.1) carries the code so the common path is one click; the bare
  address and the code are printed beside it for a browser on another device.
  The approval screen shows the requesting IP and what the certificate will
  reach. Nothing auto-submits, and the code stays visible so it can be checked
  against what is on screen.
- **The CSR goes up at the start**, and the server pins its hash. The human
  approves one key, and only that key can collect.
- **Pending and slow-down continue the poll.** `SE021` is RFC 8628
  `authorization_pending`. `SE022` is `slow_down`, which adds 5 seconds to the
  interval. Every
  other refusal, whether unknown, denied, already consumed or expired, is the
  same opaque message, so a guessed device code cannot be used to map the state
  of somebody else's sign-in. The agent branches on the code, never on message
  text.
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
under `~/.localport/identity/` (directories `0700`, files `0600`):

```
<team>/<kind>-<identity>/
  cert-<serial>.pem   leaf first, then the issuing chain, which is what the agent presents
  key-<serial>.pem    P-256 private key, generated locally, never transmitted
  meta.json           identity, team, team_name, kind, spiffe_id, source, api_url,
                      serial, not_after, the cert and key file names, and
                      renew_after only when the credential renews
```

A save writes the certificate and key under new serial-named files, then
`meta.json`, which names them. Writing `meta.json` is the commit point, so a save
interrupted before it leaves the previous credential loadable. Files from earlier
saves are removed afterwards.

`team_name` is the team's display name. `localport identity list` prints it so a
person holding credentials in two teams can tell them apart, and nothing else
reads it. It is omitted when the control plane could not resolve it, and a
record without it still loads. A renewal refreshes it but never blanks it.

`source` is `token`, `oidc` or `sso`. Only `token` and `oidc` renew, and any
other value is treated as non-renewing. A renewal carries the source forward
unchanged.

`meta.json` is validated on read and on write. A record naming an unknown kind or
source, missing an expiry, or pairing a non-renewing source with a renewal
deadline is refused at the store.

**The path and every identity field are read from the certificate, never from
the response body.** One machine may hold credentials for several teams, and
`user` and `client` are separate SPIFFE namespaces that may hold the same name,
so the path carries both.

The path carries no control-plane component. `--api` exists for development, and
a developer running two side by side sets `LOCALPORT_HOME` to isolate the whole
store. Which plane issued a credential is recorded as `api_url`, which is where
renewal reads it.

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
never a prompt, so a typo cannot select a different principal. The prompt appears
only when no selector was given, only on a terminal, and never under `--config`;
everywhere else an ambiguous match is refused with the full form of each
candidate.

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

This digest is a wire format shared with the control plane. Both sides pin it
with the same test vector; do not change one without the other.

The signature is recomputed on every attempt, because a retry that crosses a
minute boundary would otherwise send a signature the server no longer accepts.

Renewal is due at `renew_after`, which the server sets two thirds through the
lifetime; the agent uses the same point when the server sends none. The loop
runs inside `localport access`; a machine that is not permanently connected
should run `localport identity renew` from a daily timer instead. The previous
certificate stays valid until its own expiry, so rollover overlaps.

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
