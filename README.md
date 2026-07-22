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

Localport exposes local services to the internet over secure tunnels. It supports HTTP, TCP, TLS, and mutual TLS, and operates through NAT, CGNAT, and corporate firewalls without port forwarding, router configuration, or a public IP.

This repository contains the Localport agent: the client process that runs on the host machine and maintains tunnel connections to the Localport network. The agent is the only component that runs in your environment, and it is released as open source under the Apache License 2.0. The remainder of the platform, including the edge network, control plane, and dashboard, is operated by Localport as a managed service.

Accounts and tunnels are managed at [localport.io](https://localport.io).

## Features

- **Protocols.** HTTP, TCP, and TLS tunnels with automatic, browser-trusted HTTPS.
- **Reserved addresses.** Static subdomains and ports persist across sessions, keeping public links and webhook URLs stable.
- **Mesh tunnels.** A single token serves an entire fleet. Each device receives its own address and remains reachable by name behind CGNAT or cellular networks.
- **Shared tunnels.** One inbound request is delivered to every connected client, with a designated client returning the response.
- **Locked tunnels.** Mutual TLS with ECDSA P-256 certificates restricts access to authorized devices, with per-device revocation.
- **Access control.** IP allow lists and password protection on any tunnel.
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

Create a tunnel in the [dashboard](https://dashboard.localport.io) to obtain a token, then run the agent against the local service. Complete command, flag, configuration, and protocol documentation is maintained on the documentation site:

- [Quick start](https://localport.io/docs/quick-start): first-tunnel walkthrough
- [CLI reference](https://localport.io/docs/cli): commands, flags, and environment variables
- Tunnel guides, by protocol ([HTTP](https://localport.io/docs/http-tunnels), [TCP](https://localport.io/docs/tcp-tunnels), TLS) and routing mode ([mesh](https://localport.io/docs/mesh-tunnels), [shared](https://localport.io/docs/shared-tunnels), [locked / mTLS](https://localport.io/docs/locked-tunnels))

## Build from source

Requires Go 1.24 or newer.

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
