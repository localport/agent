# Agent error codes

A refusal the agent reports to you carries its code, such as `[AG021]`,
right after its message; details may follow the code, and a refusal caused
by another shows both codes. Operating system failures (such as a permission
error) and flag usage errors carry no code. Codes the control plane or the
edge send (such as `[SE031]`) come from the service and are not listed here;
include them when you contact support.

Codes are grouped by area: AG00x credentials and keys, AG01x file and binary
checks, AG02x local config, AG03x commands, AG04x the device service, AG05x
terminal sessions, AG06x recordings, AG07x network, AG08x and AG09x the
Windows installer. The Windows installer and uninstaller exit with the
number of their code (`AG084` exits 84). Two refusals of the installer
itself use the Windows Installer codes instead: exit 1618, another
Localport installer or uninstaller is running (wait for it to finish, then
run it again), and exit 1633, the machine is not running 64-bit Windows.

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
| AG010 | Device credential not saved | The control plane issued the device credential, but writing it to the credential store failed; the message names why. The join token is spent: fix the cause, then create a new join command in the dashboard and run it. |
| AG011 | Unsafe service executable | The device service runs only a binary that root (SYSTEM, Administrators or TrustedInstaller on Windows) alone can replace. Install localport with the install script under sudo, or an elevated install.ps1, and run it by that absolute path. |
| AG012 | Untrusted credential path | A credential file or directory is a link, has the wrong owner, or is writable by others. Fix the path the message names. On Linux and macOS: owned by the account running the agent, mode 0700 for directories and 0600 for files. On Windows: owned by that account, SYSTEM or Administrators; a file grants access to no one else, and a directory grants write access to no one else. Under the machine-wide config directory the device service's account `NT SERVICE\localport-device` is allowed too. |
| AG013 | Package manager executable | A localport installed by winget (its portable zip package) or Scoop cannot run the device service: the package manager replaces and removes that file on its own, without stopping or re-registering the service. Install the device with the Localport installer (`localport-setup-<version>-windows-amd64.exe`, the winget installer package, or an elevated install.ps1, which runs the installer), then run `localport connect` or `localport service install` by its absolute path, `"%ProgramFiles%\Localport\localport.exe"`. |
| AG021 | Devices already running | Another localport process (the device service, `localport run` or `connect --foreground`) serves these devices. Stop it, or let it serve them. |
| AG022 | Sessions need the device service | On Windows the session launcher serves only the device service's account, so terminal and files sessions run only under the installed device service. Install it with `localport service install` from an elevated prompt instead of serving the device from this process. |
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
| AG037 | Agent account step failed | Root runs the device-store part of this command as the agent account `localport`, and that part failed. Its own error, printed above this line, says why. |
| AG038 | Agent account step not started | Root could not start localport as the agent account `localport`. Check that the account exists (`id localport`) and that the localport executable is intact; reinstall localport if either is missing. |
| AG039 | Internal command | `__agent` is the command localport runs itself, as the agent account. Run the command you meant without it. |
| AG041 | Foreign service definition | A service under the device service's name was not written by localport. Remove it as the message says, then retry. |
| AG042 | Device service not installed | Nothing to remove. Install the service with `sudo localport service install`. |
| AG043 | No supported service manager | This machine has no systemd, launchd or Windows service manager. Run the devices with `localport run` under your own supervisor. |
| AG044 | Windows service marked for deletion | Windows keeps a deleted service until every handle to it closes. Close the Services console, Event Viewer and any tool showing the service, or restart Windows, then retry. |
| AG045 | Device credentials not purged | `service uninstall --purge` removed the service, but deleting the device credentials or the recording spool failed; the message names the path. Fix that path's owner or mode, then run `sudo localport service uninstall --purge` again. |
| AG053 | Device sessions locked | Another localport process serves this device's sessions. Stop the other process. |
| AG054 | Logins disabled | The device has `/etc/nologin`, so sessions run only as root. Remove the file once maintenance is over. Hosts with PAM apply this through `pam_nologin` instead. |
| AG055 | Session launcher from another release | The agent and the session launcher service (`localport-session`) come from different localport releases, usually right after an upgrade. Restart the launcher service: `sudo systemctl restart localport-session` (Linux), `sudo launchctl kickstart -k system/io.localport.session` (macOS), or restart the `localport-session` service (Windows). |
| AG061 | Recording spool full | The recording spool reached its size limit, so recordings stop until uploads catch up. Check the device's connection to the control plane. |
| AG062 | Disk space low for recordings | The disk holding the recording spool is nearly full. Free disk space. |
| AG063 | Recording unavailable | A recording could not start; the message names the cause after the code. Causes: no recording uploader, a recording key that is not held or does not match the ticket, a key that cannot seal the recording's key (malformed, or the wrap fails), too little time before the session's deadline, a spool that cannot store the entry, no session mux, or the control plane refusing, not answering or answering the open with segments already stored. A strict session is refused and a best-effort session runs unrecorded. Retry the session; when it persists, act on the named cause. |
| AG071 | No transport | No connection to the edge worked. Check that this machine reaches the edge on TCP 443 and that no firewall or proxy blocks it. |
| AG072 | Registration failed | The connection to the edge broke or carried an unexpected answer while the tunnel or device registered. localport retries on its own; when it persists, contact support with the agent log. |
| AG073 | Redirect to an untrusted host | The edge sent this agent to a host outside the Localport service, so the agent refused to follow. localport retries on its own; contact support. |
| AG074 | Too many redirects | The edge redirected the agent more times than it follows. localport retries on its own; when it persists, contact support. |
| AG075 | Too many inbound connections | More inbound connections were opening at once than the agent serves, so this one was refused. Visitors can retry; when it persists, the local service is too slow to accept connections. |
| AG076 | Data connection failed | The agent could not open a data connection to the edge for an inbound connection. Check that this machine reaches the edge on TCP 443. |
| AG077 | Local service unreachable | The local service did not accept the connection (the message names the address and the cause). Check that the service runs and listens on that address and port. |
| AG078 | Port not allowed | The edge asked for a port the device does not serve: not in its port list or outside its `--allow-ports`. Add the port to the device in the dashboard, or widen `--allow-ports`. |
| AG079 | Connection broke while relaying | An inbound connection ended with an error from the visitor's side or the local service (the message names it), not a normal close. Nothing to do for a single connection; when many break, check the local service and the network. |
| AG081 | Installer step not elevated | A Windows installer step (`localport system`) ran without elevation. Run the Localport installer as an Administrator; it asks for elevation itself. |
| AG082 | Install directory unsafe | The install directory, or a directory above it, is owned by someone other than SYSTEM or Administrators, or grants another account a right that replaces an entry, or on the install directory itself one that adds a file or folder. Choose a directory under `%ProgramFiles%`, or fix the owner and permissions the message names. |
| AG083 | Device services did not stop | The installer could not stop the device or session launcher service in time, so it undid the install: the previous files, settings and services are as they were. Stop the services (`sc.exe stop localport-device`, `sc.exe stop localport-session`), then run the installer again. |
| AG084 | Install not committed | A product file could not be put in place (the message names it and the cause, often a file another program holds open), so the installer undid the install: the previous files, settings and services are as they were. Close that program, then run the installer again. |
| AG085 | Device services not re-registered | Registering the device services for the new executables failed, so the installer undid the install: the previous files, settings and services are as they were. The message names the cause; fix it, then run the installer again. |
| AG086 | Foreign service in the install directory | A service localport did not create runs a program inside the install directory, so uninstalling would break it; nothing was changed. Remove or move that service (the message names it), then uninstall again. |
| AG087 | Machine PATH not updated | The installer could not add its directory to the machine `Path`, so it undid the install: the previous files, settings and services are as they were. The message names the cause; fix it, then run the installer again. |
| AG088 | Installer step invalid | The installer called a `localport system` step that this `localport.exe` does not know, or with the wrong arguments; the installer and its executable come from different releases. Nothing was changed. Download the installer again from the releases page and run it. |
| AG089 | Uninstall not prepared | A step of the uninstall failed (listing or removing the device services, the `Path` entry, the Add/Remove Programs entry or a file), so the uninstaller undid it: the install is as it was. The message names the cause; fix it (for example, close a tool that holds a service open, or restart Windows), then uninstall again. |
| AG090 | Install rollback failed | An install or uninstall failed and undoing it also failed, so the machine may be between two states. The journal under `<install directory>\.localport-txn\` is kept, and the next run of the installer or uninstaller finishes the undo before it does anything else. Run the installer again; the message names the step that could not be undone. The undo also reports AG090 when it finished but removed a device service instead of restoring it, because the program that service ran was deleted or can be replaced by another account: run `localport service install` as an Administrator to register the service again. |
| AG091 | Service configuration busy | Another installer, uninstaller, `localport connect` or `localport service` command is changing the device services and did not finish within 2 minutes; or an install or uninstall that was interrupted is still open in an install directory, which the message names (its undo would reverse this change); or the lock could not be taken (the message names the cause). Wait for the other command to finish and run the command again. For an interrupted install or uninstall, run the Localport installer, or the uninstaller, for the directory the message names: it undoes the interrupted one first. Running an installer for a different directory refuses again. |
| AG092 | Uninstall entry not written | The installer could not write its Add/Remove Programs entry, so it undid the install: the previous files, settings and services are as they were. The message names the cause; fix it, then run the installer again. |
| AG093 | Device state not purged | The uninstall finished, but removing the device identities and config it was asked to purge failed, so they stay under `%ProgramData%\localport-device`. The message names the cause; fix it, then delete that directory as an Administrator. The device certificates stay valid until the devices are removed in the dashboard. |
