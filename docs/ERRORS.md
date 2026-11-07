# Agent error codes

A refusal the agent reports to you carries its code, such as `[AG021]`,
right after its message; details may follow the code, and a refusal caused
by another shows both codes. Operating system failures (such as a permission
error) and flag usage errors carry no code. Codes the control plane or the
edge send (such as `[SE031]`) come from the service and are not listed here;
include them when you contact support.

Codes are grouped by area: AG00x credentials and keys, AG01x file and binary
checks, AG02x local config, AG03x commands, AG04x the device service, AG05x
terminal sessions, AG06x recordings, AG07x network.

| Code | Title | What to do |
|---|---|---|
| AG001 | Renewed device certificate lost | The device's credential store lost the certificate it last registered with. Create a new join command in the dashboard and run it on this machine. |
| AG002 | Device credential used to reach devices | A device credential only registers its device. Use `localport login` or `localport setup <TOKEN>` for a credential that reaches devices. |
| AG003 | No ticket key set | The control plane answered without the device's ticket keys. Retry later; if it persists, contact support. |
| AG004 | Ticket keys unreadable | `ticket_keys.json` beside the device's credential is unreadable or not owner-only. Make it a regular file owned by the account running the agent, mode 0600. |
| AG005 | Ticket keys busy | Another localport process held the device's key lock. Stop the other process, or retry. |
| AG006 | Renewal in progress | Another localport process is renewing this credential. Wait for it to finish, then retry. |
| AG007 | Credential does not renew | A sign-in credential expires instead of renewing. Run `localport login` again. |
| AG008 | Desktop target keys unreadable | `desktop_pins.json` beside the device's credential is unreadable, not owner-only, or not valid. Make it a regular file owned by the account running the agent, mode 0600, or run `localport set <device> --rdp-reset-pin` (or `--vnc-reset-pin`), which removes the file with every key it held; the next browser connection asks to trust the key again. In an untrusted credential directory the reset fails too: fix the directory's owner and mode first. |
| AG009 | Desktop target keys busy | Another localport process held the device's desktop key lock. Retry. |
| AG011 | Unsafe service executable | The device service runs only a binary that root (SYSTEM, Administrators or TrustedInstaller on Windows) alone can replace. Install localport with the install script under sudo, or an elevated install.ps1, and run it by that absolute path. |
| AG012 | Untrusted credential path | A credential file or directory is a link, has the wrong owner, or is writable by others. Fix the path the message names. On Linux and macOS: owned by the account running the agent, mode 0700 for directories and 0600 for files. On Windows: owned by that account, SYSTEM or Administrators; a file grants access to no one else, and a directory grants write access to no one else. Under the machine-wide config directory the device service's account `NT SERVICE\localport-device` is allowed too. |
| AG021 | Devices already running | Another localport process (the device service, `localport run` or `connect --foreground`) serves these devices. Stop it, or let it serve them. |
| AG022 | Fleet token retired | Create the device in the dashboard and run the command it shows. |
| AG023 | Terminal, files or forwarding with a host | Terminal, files and forwarding act on the machine running the agent. Remove the host, or remove terminal, files and forwarding. |
| AG024 | Logins without terminal or files | Logins apply only to terminal and files. Enable one of them, or remove the logins. |
| AG025 | Terminal or files without logins | Name at least one login with `--logins`. |
| AG026 | Desktop without target | Give desktop a target with `--rdp` or `--vnc`. |
| AG027 | Files root missing | The files root must be an existing directory. Mount or create it, or change it with `localport set`. |
| AG029 | Logins with run_as_agent | A device with `run_as_agent: true` runs terminal and files sessions as the agent account `localport`, so it lists no logins. Remove `--logins`, or drop `--run-as-agent` on a host with usable logins. |
| AG030 | Forwarding without terminal | SSH port forwarding rides an `ssh` connection, so it needs terminal on the same device. Enable both, for example `--enable terminal,forwarding`. |
| AG028 | Invalid local config | The local config failed validation; the message names the field. Every command that reads it refuses the same way, `localport set` included, so correct `agent.yaml` by hand: in `$LOCALPORT_HOME` (or `~/.localport`), or as root in the machine-wide config directory. |
| AG031 | No enrolled device | The machine-wide config lists no device. Enrol one with `sudo localport connect <join-token>`. |
| AG032 | No device can start | Every enrolled device's credential is missing or unreadable; the lines above name each one. Create a new join command in the dashboard for each device and run it. |
| AG033 | Device service installed | Deleting the devices is refused while the device service is installed, as when another command installed it during the purge. Run `sudo localport service uninstall --purge` again once that command has finished. |
| AG034 | Flags conflict with stored settings | The flags of a repeated connect differ from the device's settings. Change the settings with `localport set`, or run connect without the conflicting flags. |
| AG035 | Unexpected argument | connect takes one join token. Put every flag before the join token or right after it. |
| AG036 | No default login | Terminal and files need a login, and the account running the command gives none. Name the accounts with `--logins`. |
| AG041 | Foreign service definition | A service under the device service's name was not written by localport. Remove it as the message says, then retry. |
| AG042 | Device service not installed | Nothing to remove. Install the service with `sudo localport service install`. |
| AG043 | No supported service manager | This machine has no systemd, launchd or Windows service manager. Run the devices with `localport run` under your own supervisor. |
| AG044 | Windows service marked for deletion | Windows keeps a deleted service until every handle to it closes. Close the Services console, Event Viewer and any tool showing the service, or restart Windows, then retry. |
| AG053 | Device sessions locked | Another localport process serves this device's sessions. Stop the other process. |
| AG061 | Recording spool full | The recording spool reached its size limit, so recordings stop until uploads catch up. Check the device's connection to the control plane. |
| AG062 | Disk space low for recordings | The disk holding the recording spool is nearly full. Free disk space. |
| AG063 | Recording unavailable | A recording could not start; the message names the cause after the code. Causes: no recording uploader, a recording key that is not held or does not match the ticket, a key that cannot seal the recording's key (malformed, or the wrap fails), too little time before the session's deadline, a spool that cannot store the entry, no session mux, or the control plane refusing, not answering or answering the open with segments already stored. A strict session is refused and a best-effort session runs unrecorded. Retry the session; when it persists, act on the named cause. |
| AG071 | No transport | No connection to the edge worked. Check that this machine reaches the edge on TCP 443 and that no firewall or proxy blocks it. |
