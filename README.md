<p align="center">
  <img src="https://assets.localport.io/logo/logo-dark@2x.png" alt="Localport" width="96" height="96" />
</p>

<h1 align="center">Localport</h1>

<p align="center"><strong>Your localhost, on the internet.</strong></p>

<p align="center">
  <a href="https://goreportcard.com/report/github.com/localport/agent"><img src="https://goreportcard.com/badge/github.com/localport/agent" alt="Go Report Card" /></a>
  <a href="https://github.com/localport/agent/releases"><img src="https://img.shields.io/github/v/release/localport/agent?color=2eb67d" alt="Latest release" /></a>
  <a href="https://localport.io/docs"><img src="https://img.shields.io/badge/docs-localport.io-2eb67d" alt="Documentation" /></a>
</p>

Localport exposes local services to the internet over secure tunnels and gives remote access to devices by identity. It supports HTTP, TCP, TLS, and mutual TLS, and operates through NAT, CGNAT, and corporate firewalls without port forwarding, router configuration, or a public IP.

This repository contains the Localport agent, the client process that runs on the host machine and maintains tunnel connections to the Localport network. The agent is the only component that runs in your environment, and it is released as open source under the Apache License 2.0. The remainder of the platform, including the edge network, control plane, and dashboard, is operated by Localport as a managed service.

Accounts and tunnels are managed at [localport.io](https://localport.io).

## Features

- **Protocols.** HTTP, TCP, and TLS tunnels with automatic, browser-trusted HTTPS.
- **Reserved addresses.** Static subdomains and ports persist across sessions, keeping public links and webhook URLs stable.
- **Remote access.** A fleet is a group of devices sharing one token. Each device receives its own address, remains reachable by name behind CGNAT or cellular networks, and serves the ports opened on it in the dashboard. A fleet has no public endpoint. Consumers reach a device with `localport access <device> -L <local>:<remote>` over one mutual TLS connection, presenting a client certificate.
- **Fanout tunnels.** One inbound HTTP request is delivered to every connected client, with a designated client returning the response.
- **Scoped access.** Each certificate names a stable identity. What an identity may reach is managed server-side and can be changed without reissuing certificates, and narrowing a grant or revoking a certificate closes live connections. Bring your own certificate authority if you prefer, since only its public chain is stored.
- **Self-renewing credentials.** `localport setup <TOKEN>` redeems a single-use token, generates its private key locally, and renews itself from then on. No certificate file to copy around and no long-lived secret on the machine.
- **Sign in as yourself.** `localport login` prints a short code, you approve it in the dashboard in any browser, and a short-lived certificate lands on this machine. It works over SSH into a jump box. A sign-in lasts hours and does not renew; run `localport login` again. Removing the person from the team ends their access.
- **CI with no secret.** In a pipeline the agent exchanges the platform's workload identity (GitHub Actions out of the box) for a short-lived certificate held in memory. Nothing is stored in the repository, the CI secret store, or on the runner.
- **Access control.** IP allow lists and password protection on public tunnels. Fleets are reached by client certificate.
- **Data privacy.** Traffic is never inspected, logged, or used for training, and each tunnel is pinned to a chosen region.
- **Cross-platform.** Prebuilt binaries for macOS, Linux, and Windows.

## Installation

```sh
# macOS and Linux (Homebrew)
brew install localport/tap/localport

# macOS and Linux (install script)
curl -fsSL https://localport.io/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://localport.io/install.ps1 | iex
```

For manual installation, download a binary from the [releases page](https://github.com/localport/agent/releases). Platform-specific instructions are in the [installation guide](https://localport.io/docs/installation).

## Usage

Create a tunnel or a fleet in the [dashboard](https://dashboard.localport.io) to obtain a token, then run the agent:

```sh
# Publish a local service
localport http 3000 -t <token>

# Join a fleet as a device (its ports are set in the dashboard)
localport connect -t <token> --name plc-01 --host 192.168.1.100

# Reach that device's ports
localport access plc-01-factory.ap.localport.dev -L 5020:502 -L 8080:80

# Run several tunnels and devices from one file
localport connect --config localport.yaml
```

Complete command, flag, configuration, and protocol documentation is maintained on the documentation site:

- [Quick start](https://localport.io/docs/quick-start): first-tunnel walkthrough
- [CLI reference](https://localport.io/docs/cli): commands, flags, and environment variables
- Tunnel guides, by protocol ([HTTP](https://localport.io/docs/http-tunnels), [TCP](https://localport.io/docs/tcp-tunnels), TLS) and delivery mode ([fanout](https://localport.io/docs/fanout))
- Remote access guides ([fleets](https://localport.io/docs/fleets), [`localport access`](https://localport.io/docs/remote-access))

## Build from source

Requires Go 1.25 or newer.

```sh
git clone https://github.com/localport/agent.git
cd agent
make build
./bin/localport version
```

`make build-all` cross-compiles binaries for macOS, Linux, and Windows into `bin/`.

## Documentation

- Product and guides: [localport.io/docs](https://localport.io/docs)
- Wire protocol: [docs/PROTOCOL.md](docs/PROTOCOL.md)

## How it works

- **Single port.** Every agent and consumer connection goes to the edge on 443. The edge routes by SNI and ALPN, so any network that allows HTTPS allows Localport.
- **Firewall traversal.** The agent tries raw TLS first and falls back to WebSocket, which passes deep packet inspection and TLS-intercepting proxies.
- **Multiplexing.** Each tunnel holds one control connection and one HTTP/2 connection carrying a stream per visitor. If the HTTP/2 connection is unavailable, the agent dials back once per visitor.
- **Network changes.** The agent watches interfaces and detects wake from sleep. After either, it probes the edge and reconnects within seconds when the old connection is gone.
- **Remote access.** `localport access` holds one mutual TLS HTTP/2 connection per device and opens a CONNECT stream per forward. The edge checks the certificate and grant before a stream reaches the device.

## Contributing

Issues and pull requests are welcome. For non-trivial changes, open an issue to discuss the approach before submitting. Run `make test`, `make vet`, and `make lint` before opening a pull request.

## Security

Report security vulnerabilities privately through [localport.io/contact](https://localport.io/contact). Do not open public issues for security reports.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The agent bundles open-source dependencies under permissive licenses (BSD, ISC,
Apache-2.0); their notices are reproduced in
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES), regenerated from the module graph by
`make notices`.
