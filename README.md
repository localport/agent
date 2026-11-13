<p align="center">
  <img src="https://assets.localport.io/logo/logo-dark@2x.png" alt="Localport" width="96" height="96" />
</p>

<h1 align="center">Localport</h1>

<p align="center"><strong>Secure tunnels and remote access by identity.</strong></p>

<p align="center">
  <a href="https://github.com/localport/agent/actions/workflows/ci.yml"><img src="https://github.com/localport/agent/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI" /></a>
  <a href="https://github.com/localport/agent/actions/workflows/codeql.yml"><img src="https://github.com/localport/agent/actions/workflows/codeql.yml/badge.svg?branch=main" alt="CodeQL" /></a>
  <a href="https://github.com/localport/agent/releases"><img src="https://img.shields.io/github/v/release/localport/agent?color=2eb67d" alt="Latest release" /></a>
  <a href="https://github.com/localport/agent/blob/main/go.mod"><img src="https://img.shields.io/github/go-mod/go-version/localport/agent?color=2eb67d" alt="Go version" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/localport/agent?color=2eb67d" alt="License" /></a>
  <a href="https://localport.io/docs"><img src="https://img.shields.io/badge/docs-localport.io-2eb67d" alt="Documentation" /></a>
</p>

Localport publishes services over secure tunnels and gives identity-based remote access to devices. Tunnels serve HTTP, TCP, and TLS at a public address, with automatic HTTPS for HTTP tunnels and access checks such as IP allow lists, passwords, and webhook signature verification. Fleet devices have no public address and are reached by client certificate over mutual TLS. Both work through NAT, CGNAT, and corporate firewalls without port forwarding, router configuration, or a public IP.

An HTTP tunnel can also switch to fanout delivery, which gives a whole team one permanent URL. Each request, such as a webhook, reaches every teammate's agent, and one designated client returns the response.

This repository contains the Localport agent, the client process that runs on the host machine and maintains tunnel connections to the Localport network. The agent is the only component that runs in your environment, and it is released as open source under the Apache License 2.0. The remainder of the platform, including the edge network, control plane, and dashboard, is operated by Localport as a managed service.

Accounts and tunnels are managed at [localport.io](https://localport.io).

<p align="center">
  <img src="docs/assets/terminal.svg" alt="The agent running a TCP tunnel that lists its live connections, then an HTTP tunnel that lists each request with its method, path, status and duration" width="600" />
</p>

## Features

- **Protocols.** HTTP, TCP, and TLS tunnels with automatic, browser-trusted HTTPS.
- **Reserved addresses.** Subdomains and reserved ports persist across sessions, keeping public links and webhook URLs stable.
- **Remote access.** A fleet is a group of devices, each enrolled once with its own single-use join token. Each device receives its own address, remains reachable by name behind CGNAT or cellular networks, and serves the ports allowed for it in the dashboard. A fleet has no public endpoint. Consumers reach a device with `localport access <device> -L <local>:<remote>` over one mutual TLS connection, presenting a client certificate.
- **Fanout tunnels.** One permanent URL for the whole team. Each inbound HTTP request is delivered to every connected client and a designated client returns the response, so every developer receives the same webhooks without registering an endpoint of their own.
- **Scoped access.** Each certificate names a stable identity. What an identity may reach is managed server-side and can be changed without reissuing certificates, and narrowing a grant or revoking a certificate closes live connections. Bring your own certificate authority if you prefer, since only its public chain is stored.
- **Self-renewing credentials.** `localport setup <TOKEN>` redeems a single-use token, generates its private key locally, and renews itself from then on. No certificate file to copy around and no long-lived secret on the machine.
- **Sign in as yourself.** `localport login` prints a short code, you approve it in the dashboard in any browser, and a short-lived certificate lands on this machine. It works over SSH into a jump box. A sign-in lasts hours and does not renew; run `localport login` again. Removing the person from the team ends their access.
- **CI with no secret.** In a pipeline the agent exchanges the platform's workload identity (GitHub Actions out of the box) for a short-lived certificate held in memory. Nothing is stored in the repository, the CI secret store, or on the runner.
- **Access control.** IP allow lists on every tunnel. HTTP tunnels can also require a password, required request headers, or a verified webhook signature (GitHub, Stripe, Shopify, Slack, or HMAC-SHA256), checked on every request. Fleets are reached by client certificate.
- **Data privacy.** Traffic is never inspected, logged, or used for training, and each tunnel is pinned to a chosen region.
- **Cross-platform.** Signed releases for macOS 13 or later, Linux with kernel 3.2 or later (including 32-bit ARM), and Windows 10 or later, as binaries, apt/dnf/apk packages, and a container image.

## Installation

```sh
# macOS and Linux (Homebrew)
brew install localport/tap/localport

# macOS and Linux (install script)
curl -fsSL https://localport.io/install.sh | sh
```

```powershell
# Windows (PowerShell). Elevated, it runs the Localport installer; otherwise it
# installs localport.exe for the current user.
irm https://localport.io/install.ps1 | iex
```

```sh
# Container image (linux/amd64, linux/arm64, linux/arm/v7)
docker run --rm ghcr.io/localport/agent:latest version
```

On Debian, Ubuntu, RHEL, Rocky Linux, Amazon Linux, Fedora and Alpine, the install script sets up the signed package repository at `pkg.localport.io`, so upgrades come through `apt`, `dnf` or `apk`. Manual repository setup, direct downloads from the [releases page](https://github.com/localport/agent/releases), and platform-specific notes are in the [installation guide](https://localport.io/docs/installation).

Windows:

- The installer, `localport-setup-<version>-windows-amd64.exe` on the releases page, installs `localport.exe` and `localport-session.exe` for every user in `%ProgramFiles%\Localport` (`/D=<dir>` chooses another directory, which must be writable only by SYSTEM and Administrators) and adds that directory to the machine `PATH`. It runs silently with `/S`. It enrols no device: run `localport connect <join-token>` from an elevated prompt afterwards. An upgrade stops the device services, replaces every installed file together and starts the services again from the installed path. The install is one transaction: if any step fails, or the installer is interrupted, the machine is put back as it was (on the next run, if interrupted) and the installer exits with the number of its `AG08x` or `AG09x` code, `AG084` as exit status 84 ([docs/ERRORS.md](docs/ERRORS.md)); it exits 1618 when another Localport installer or uninstaller is running and 1633 on Windows that is not 64-bit (the Windows Installer codes); `/LOG=<file>` writes each step's output to a file. An old `localport.exe` still running (an open tunnel) keeps running; its old file is deleted by the next install or the next restart of Windows.
- Uninstall from Settings, Apps, or with `"%ProgramFiles%\Localport\uninstall.exe" /S`. It removes the device services, the `PATH` entry and the installed files as one transaction, undone if a step fails, and keeps the devices in `%ProgramData%\localport-device`; `/PURGE` deletes them too, as `localport service uninstall --purge` does.
- `localport-windows-amd64.zip` (both executables and the notices) is the package winget's portable install and Scoop use. Those copies run tunnels and `localport access`, but the device service refuses to run from them (`AG013`): the package manager replaces and removes them without stopping the service. Install devices with the installer.
- Code signing: when a release is signed, the installer, the uninstaller and both executables carry an Authenticode signature from SignPath Foundation, applied by SignPath's service to files built by this repository's release workflow after a maintainer approves each release. The signing service receives only the release files; no user data. Until then the Windows files are unsigned and are verified through the signed `checksums.txt`: SmartScreen shows "Windows protected your PC" (More info, Run anyway), and Smart App Control on Windows 11 may block them, in which case use the install script without elevation or wait for a signed release.

Every release is signed and carries SLSA build provenance and an SBOM. [SECURITY.md](SECURITY.md) shows how to verify one, and [RELEASING.md](RELEASING.md) describes how releases are built and signed.

## Usage

Create a tunnel in the [dashboard](https://dashboard.localport.io) to obtain its token, or create a fleet device to obtain its join command, then run the agent:

```sh
# Publish a local service
localport http 3000 -t <token>

# Enrol this machine as a fleet device with the join token the dashboard shows,
# and install the device service that runs it at boot
sudo localport connect <join-token> --enable terminal,files --logins pi

# A device serving another machine, limited to these ports
sudo localport connect <join-token> --host 192.168.1.100 --allow-ports 502,8000-8100

# Change what a device allows; the device service reloads to apply it
# (only that device restarts, and its open sessions end)
sudo localport set plc-01 --enable terminal,files,desktop --vnc

# Install the device service again for the enrolled devices, without a join token
sudo localport service install

# Stop and remove the device service (--purge also deletes the config, device credentials and recording spool)
sudo localport service uninstall

# Reach that device's ports
localport access plc-01-factory.ap.localport.dev -L 5020:502 -L 8080:80

# Open a shell on a device with the system ssh, or add it to ~/.ssh/config
# so ssh, scp, sftp and rsync reach it by name
localport ssh pi@gw-01-factory.eu.localport.dev
localport ssh-config gw-01-factory.eu.localport.dev >> ~/.ssh/config

# Run several tunnels from one file
localport connect --config localport.yaml
```

Device service:

- As root (an elevated Administrator on Windows), `connect` installs and starts the device service: on Linux the systemd unit `localport-device.service`, or the OpenRC or OpenWrt procd service `localport-device`; on macOS the launchd daemon `io.localport.device`; on Windows the service `localport-device`. It runs `localport run --service`, which serves every device in the machine-wide local config. `--foreground` runs the devices in the terminal instead: as root on Linux and macOS every device in the machine-wide config, through `run --system` as the `localport` account (`--no-mux` is not available there); without root the device always runs in the foreground.
- On Linux and macOS the agent runs as the system account `localport`, which `connect` and `service install` create (the OpenWrt package creates it). The systemd unit adds `NoNewPrivileges`, an empty capability set, `ProtectSystem=strict` with write access only to the identity directory and `run.lock`, `ProtectHome`, `PrivateTmp`, `PrivateDevices` and a system call filter. A root session launcher, `localport-session` (systemd `localport-session.socket`, launchd `io.localport.session`, OpenRC and procd `localport-session`), starts each terminal session; the agent reaches it over `/run/localport/session.sock` (`/var/run/localport/session.sock` on macOS), which only the `localport` group can open.
- On Windows the service runs as the virtual account `NT SERVICE\localport-device`, whose token holds only `SeChangeNotifyPrivilege`. A second service, `localport-session`, runs as LocalSystem with only the privileges a logon needs and starts each terminal session; the agent reaches it over the pipe `\\.\pipe\localport-session`, which only the agent can open. A session logs the login on without a password (S4U), loads its profile and runs `cmd.exe`; a command runs as `cmd.exe /c "<command>"`. Logins are `user` (a local account), `DOMAIN\user` or `user@domain`; an S4U session has no network credentials, so it cannot reach file shares as the user. Logins listed with `--password-logins` (Entra ID accounts, which S4U cannot log on) are asked for their Windows password at each session instead; the agent holds it for that session only. `agent.yaml` belongs to Administrators and the service can only read it; `identity\` holds the credentials and the recording spool.
- Files on Linux and macOS: the device directory (`/etc/localport-device`, `/Library/Application Support/localport-device`) is root:localport 0750; `agent.yaml` is root:localport 0640 and only root changes it; `identity/` (credentials, ticket keys, the recording spool `identity/recordings/`) belongs to `localport` with mode 0700. Root never opens a file inside `identity/`: `sudo localport status`, `identity`, `login`, `setup`, `access`, `run` and the enrolment step of `connect` run as `localport`.
- `localport status` shows the service state; root and members of group `localport` also see the devices, whether sessions use PAM, and on macOS whether the launcher has Full Disk Access; root also sees each device's key fingerprint.
- One process serves the devices. A second privileged `run` or `connect --foreground` is refused at once, naming the device service when it is installed. A restarting service waits up to 30 s for the previous process to exit, then exits with status 3.
- The service manager starts the `localport` and `localport-session` binaries as root (`localport-session` keeps root; `localport` runs as the account on Linux and macOS), so only root (SYSTEM, Administrators or TrustedInstaller on Windows) may be able to replace them. Install it with the install script as root (`/usr/local/bin`, or `/opt/localport/bin` when `/usr/local/bin` is not root-owned) or, on Windows, the installer (`%ProgramFiles%\Localport`), and call it by that absolute path, such as `sudo /usr/local/bin/localport connect <join-token>`. A Homebrew, Scoop, winget portable or user-profile install cannot run the device service. Every privileged `run` repeats this check at start, so a service whose binary changed owner keeps restarting with the reason in its log.
- Before spending the join token, `connect` refuses a service definition under the service's name that it did not write (systemd drop-ins are accepted and listed), another process serving the devices, and a binary that fails the check above.
- When the install fails after enrolment, `sudo localport service install` installs the service without a new join token.
- `service uninstall` stops and removes the service and the session launcher, and keeps the devices and the recording spool. `--purge` also deletes `agent.yaml`, the device credentials under `identity/` and the recording spool `identity/recordings/`; machine credentials from `setup` stay. On Windows, while a tool holds a deleted service open, install and purge refuse with `AG044` until that tool closes or Windows restarts.
- Logs: the systemd journal, the OpenWrt system log, and the Event Log sources `localport-device` and `localport-session` on Windows. A Windows service that crashes leaves the Go runtime's report in `%ProgramData%\localport-device\crash\device` or `crash\launcher` (Administrators can read both; the device service can reach only its own); its next start renames it to `<UTC time>.crash`, keeps the five newest and writes an Event Log error naming the file, without the report's text. `service uninstall --purge` deletes both directories. Under launchd and OpenRC the agent writes `/var/log/localport/device.log` and the launcher `/var/log/localport-session.log`, each rotated by the process itself.

Terminal sessions (Linux and macOS):

- The agent hands each terminal session to the root launcher, which checks the request against the root-owned `agent.yaml` (the device must enable the terminal and list the login) and starts a helper, `localport-session helper`, for it. The helper runs the PAM service `localport` (installed by the packages in `/etc/pam.d/localport`): account checks, credentials and the session, so `pam_systemd`, `pam_selinux`, `pam_loginuid` and `pam_limits` apply. It takes the account and its groups from the system's account database, the environment from PAM and `/etc/login.defs`, writes utmp and wtmp, opens the pseudo-terminal and starts the login's shell.
- On hosts without PAM (Alpine without linux-pam, OpenWrt, Yocto without PAM) the helper applies the checks sshd applies without PAM: `/etc/nologin` is absent (it refuses every account but root), and the account exists, is not locked (`!` in the shadow file) or expired (on or past its expiry day), and has an existing, executable shell. `localport status` and the dashboard show "no PAM".
- Where no usable login exists, `run_as_agent: true` in a device's `agent.yaml` entry runs its sessions as the `localport` account, without PAM (`/etc/nologin` still refuses them); the dashboard shows it.
- An agent running as a user (`connect --foreground` or `run` without root) serves only its own user.
- `exit` reports the shell's status.
- A session ends with SIGHUP to its shell and its terminal; 5 s later the helper sends SIGKILL to the session. The helper is the shell's parent and does not reap it before then, so the shell's pid cannot be reused for that signal. Without pidfd (Linux before 5.3) and on macOS the terminal's session leader, when it is not the shell, is signalled by pid, so a pid reused within the 5 s window can receive the SIGKILL. A reconnect of the session mux, like the agent stopping, ends every session; a session also ends when its device's settings change (`config_changed`), when the helper fails (`helper_failed`), or when the launcher cannot be reached (`launcher_unavailable`).
- Sessions are children of the launcher, whose stop or restart leaves them running (systemd `KillMode=process`; OpenWrt procd ends them when the launcher is stopped, not when it restarts in place). A process started in a session that ignores SIGHUP survives in its logind session scope (with `pam_systemd`).
- On macOS, Full Disk Access for the launcher (`localport-session`) is opt-in, granted in System Settings or by a configuration profile.
- `sudo localport service install`, `sudo localport service uninstall` and a `sudo localport connect` that installs the service (not `--foreground`) run from a terminal session ignore SIGHUP and SIGPIPE, so ending the session they restart or stop does not stop them halfway, and they write their outcome to the system log under the tag `localport`. The `connect` record names only the command and whether it completed or failed, never the join token. Runs without root write no record, and a host with no system log daemon listening gets none.

SSH clients:

- `localport ssh-config <device-host>...` prints an `ssh_config` block per device: ssh runs `localport ssh-cert` while it reads the config, which mints a 5-minute certificate for a per-device client key when the stored one has under a minute left, and `localport ssh-proxy` carries the connection to the device's edge. `localport ssh [login@]<device-host>` does the same in one command and runs the system `ssh`.
- The client key, certificate and edge URL live under `<state root>/ssh/<credential>/`, one set per device and login (`<login>@<device-host>`), so two logins never replace each other's certificate, and the device host keys in `<state root>/known_hosts`, which each mint rewrites from the control plane's answer; ssh accepts exactly that key (`StrictHostKeyChecking yes`).
- The device's SSH server serves shells, commands, `sftp` (and so `scp` and `rsync`) and `LANG`/`LC_*` environment variables. Agent forwarding and X11 are refused. OpenSSH 9.9 or later negotiates post-quantum key exchange; older clients use `curve25519-sha256`.
- Port forwarding (`ssh -L`, `-W`, `-R`, and the forwards VS Code Remote SSH opens) needs `forwarding` enabled on the device (`--enable terminal,forwarding`; it requires `terminal` and is refused with `--host`) and a grant that permits the direction (local or remote) for the person or machine. Local forwards may reach any destination the login can; remote forwards listen on the device's loopback only. Unix-socket forwards work on Linux and macOS; Windows serves TCP forwards only. Every dial and listen runs as the login, in one helper process per SSH connection. A connection holds at most 32 open forwards and 8 remote listeners, and a device at most 64 open forwards across its connections. A recorded connection records each forward's open and close (address, result, byte counts), never the forwarded data.

Session recording (terminal, SSH and file sessions, set by the team's recording policy):

- A recorded session's certificate names the policy; each shell, command or file session on a connection is its own recording. Commands and file operations (read, write, rename, remove and the rest, with paths and byte counts) are recorded as file activity events beside the output. A recorded shell or command first prints `localport: this session is recorded`.
- The agent encrypts the recording on the device under a key of its own, wrapped to the team's recording key, and uploads it in segments over the session mux. It never holds the team's private key, so it cannot decrypt other recordings. It clears its copy of a recording's key when the recording ends; copies inside the cipher and the Go runtime stay in process memory until the runtime reuses it.
- `best_effort`: the session starts at once. When the agent cannot deliver or store the recording, recording stops, the recording is marked incomplete, and the session continues.
- `strict`: the agent opens the recording before the shell, command or file session starts, and refuses it with the retryable `recording_unavailable` when it cannot; other sessions on the connection are unaffected. One whose recording can no longer be kept ends with `recording_failed`.
- A segment not acknowledged within 5 s, or produced while the agent is offline, is kept in the spool `<state root>/recordings/` (the directory that holds `identity/`: the machine-wide config directory for the device service, `$LOCALPORT_HOME` or `~/.localport` for a manual run as a user) until it is uploaded. The spool holds at most 32 MiB in total and stops taking writes when its filesystem has under 64 MiB free. An agent restart resumes the uploads; an entry older than 24 h, or of a device no longer in the local config, is deleted.

The machine-wide config directory (`/etc/localport-device`, `/Library/Application Support/localport-device` or `%ProgramData%\localport-device`) holds `agent.yaml`, under `identity/` each device's private key, and under `recordings/` the recording spool. Keep it out of backups and configuration management.

Security notes:

- `--allow-ports` is the only port limit enforced on the device. Without it the agent serves any port the dashboard allows on that host. Plain mode (`--noui` or no TTY) logs a warning at startup and the TUI shows `Limit  none` in the device header.
- `localport access -L` listens on 127.0.0.1, so any local user can use the forward with your identity, as with `ssh -L`. Avoid `--local-addr 0.0.0.0` on shared hosts. Use a `0600` Unix socket instead, `-L unix:/run/user/1000/plc.sock:502` (not on Windows).
- `${VAR}` in a config file is expanded from the environment before parsing, so a config can send any environment variable to Localport. Only run trusted config files.

Complete command, flag, configuration, and protocol documentation is maintained on the documentation site:

- [Quick start](https://localport.io/docs/quick-start): first-tunnel walkthrough
- [CLI reference](https://localport.io/docs/cli): commands, flags, and environment variables
- Tunnel guides, by protocol ([HTTP](https://localport.io/docs/http-tunnels), [TCP](https://localport.io/docs/tcp-tunnels), TLS) and delivery mode ([fanout](https://localport.io/docs/fanout))
- Remote access guides ([fleets](https://localport.io/docs/fleets), [`localport access`](https://localport.io/docs/remote-access))

## Build from source

Requires Go 1.27 or newer.

```sh
git clone https://github.com/localport/agent.git
cd agent
make build
./bin/localport version
```

`make build-all` cross-compiles every release platform into `bin/`.

## Documentation

- Product and guides: [localport.io/docs](https://localport.io/docs)
- Wire protocol: [docs/PROTOCOL.md](docs/PROTOCOL.md)
- Error codes (`[AG###]`) and what to do: [docs/ERRORS.md](docs/ERRORS.md)

## How it works

- **Single port.** Every agent and consumer connection goes to the edge on 443. The edge routes by SNI and ALPN, so any network that allows HTTPS allows Localport.
- **Firewall traversal.** The agent tries raw TLS first and falls back to WebSocket, which passes deep packet inspection and TLS-intercepting proxies.
- **Multiplexing.** Each tunnel holds one control connection and one HTTP/2 connection carrying a stream per visitor. If the HTTP/2 connection is unavailable, the agent dials back once per visitor.
- **Network changes.** The agent watches interfaces and detects wake from sleep. After either, it probes the edge and reconnects within seconds when the old connection is gone.
- **Remote access.** `localport access` holds one mutual TLS HTTP/2 connection per device and opens a CONNECT stream per forward. The edge checks the certificate and grant before a stream reaches the device.
- **Sessions.** A device that enables `terminal`, `files` or `desktop` holds a second HTTP/2 connection for browser and CLI sessions. Each session is one SSH connection, end to end between the client and the agent's own SSH server (the edge relays bytes it cannot read; the device key is the host key). The agent admits a client only by an SSH user certificate it verifies itself (signed by a session CA key it pins, valid, for this device, for the serial the edge admitted) and applies its local `enable` and `logins`. At most 8 connections run at once; one idle for 30 minutes is closed. A `terminal` connection is one login shell for the certificate's login (see Terminal sessions above); an `ssh` connection also runs commands (`exec`). A `vnc` connection carries one channel that the agent relays to the device's configured VNC target (`--vnc`), whatever address the client names; it runs no login and is never recorded.
- **TLS 1.3 everywhere.** Tunnel, consumer, and control-plane connections all require TLS 1.3. Private keys are generated on the machine and never leave it.

## Contributing

Issues and pull requests are welcome. For non-trivial changes, open an issue to discuss the approach before submitting. Run `make test`, `make vet`, and `make lint` before opening a pull request. `sudo LOCALPORT_TEST_LOGIN=<account> make test-root` runs the tests that need root: a real PAM terminal session started by the session helper for that test account, which needs `/bin/sh` as its shell and the `localport` PAM service file installed (`packaging/pam/`). On Windows, `LOCALPORT_TEST_LOGIN=<local account> LOCALPORT_TEST_PASSWORD=<its password> go test -run '^TestRootPasswordLogon$' ./internal/sessionhelper/` checks the session helper's password logon against that account.

## Security

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md). Do not open public issues for security reports.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The agent bundles open-source dependencies under permissive licenses (BSD, ISC,
Apache-2.0); their notices are reproduced in
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES), regenerated from the module graph by
`make notices`.
