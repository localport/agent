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

Localport gives anything on your machine a secure public link in one command. HTTP, TCP, TLS, and mutual-TLS tunnels that work behind NAT, CGNAT, and corporate firewalls. No port forwarding, no router config, no exposed IP.

This repository holds the Localport agent, the program that runs on your machine and carries your traffic to the Localport network. The tool that sits between your machine and the internet should be one you can inspect, so the agent is open source under Apache 2.0. Read every line, build it yourself, and audit the wire protocol before you trust it with a single packet. The service it connects to, including the edge network, control plane, and dashboard, is a managed product run by the Localport team.

Sign up and manage your tunnels at [localport.io](https://localport.io).

## Features

- **Every protocol.** HTTP, TCP, and TLS tunnels, with browser-trusted HTTPS provisioned for you.
- **Reserved addresses.** Static subdomains and ports stay yours between runs, so shared links and webhook URLs never break on a restart.
- **Mesh tunnels.** One token for a whole fleet. Every device gets its own address and stays reachable by name, even behind CGNAT or a cellular modem.
- **Shared tunnels.** Fan a single webhook out to your whole team at once. One client, picked from the dashboard, sends the reply back.
- **Locked tunnels.** Mutual TLS with ECDSA P-256, so only the devices and people you trust can reach a service. Revoke any of them in a click.
- **Access control.** IP allow lists and password protection on top of any tunnel.
- **Private by design.** Localport never reads, logs, or trains on your traffic, and every tunnel runs in the region you choose.
- **Cross-platform.** Prebuilt binaries for macOS, Linux, and Windows.

## Installation

```sh
# macOS and Linux (Homebrew)
brew install localport/tap/localport

# macOS and Linux (install script)
curl -fsSL https://get.localport.io/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://get.localport.io/install.ps1 | iex
```

Prefer to do it by hand? Grab a binary from the [releases page](https://github.com/localport/agent/releases). Full instructions for every platform are in the [installation guide](https://localport.io/docs/installation).

## Usage

Create a tunnel in the [dashboard](https://dashboard.localport.io) to issue a token, then run the agent against a local service to bring the tunnel online.

Every command, flag, config file, and tunnel type is documented in full:

- [Quick start](https://localport.io/docs/quick-start), a working tunnel in about a minute
- [CLI reference](https://localport.io/docs/cli), the complete list of commands and flags
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

Issues and pull requests are welcome. For anything beyond a small fix, open an issue first so we can agree on the approach before you write code. Run `make test`, `make vet`, and `make lint` before you submit.

## Security

If you find a security vulnerability, please report it privately rather than opening a public issue. Use the contact form at [localport.io/contact](https://localport.io/contact) and we will respond quickly.
