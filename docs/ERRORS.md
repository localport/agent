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
| AG002 | Device credential used to reach devices | A device credential only registers its device. Use `localport login` or `localport setup <TOKEN>` for a credential that reaches devices. |
| AG004 | Ticket keys unreadable | `ticket_keys.json` beside the device's credential is unreadable or not owner-only. Make it a regular file owned by the account running the agent, mode 0600. |
| AG005 | Ticket keys busy | Another localport process held the device's key lock. Stop the other process, or retry. |
| AG006 | Renewal in progress | Another localport process is renewing this credential. Wait for it to finish, then retry. |
| AG007 | Credential does not renew | A sign-in credential expires instead of renewing. Run `localport login` again. |
| AG011 | Unsafe service executable | The device service runs only a binary that root (SYSTEM, Administrators or TrustedInstaller on Windows) alone can replace. Install localport with the install script under sudo, or an elevated install.ps1, and run it by that absolute path. |
| AG012 | Untrusted credential path | A credential file or directory is a link, has the wrong owner, or is writable by others. Fix the path the message names. On Linux and macOS: owned by the account running the agent, mode 0700 for directories and 0600 for files. On Windows: owned by that account, SYSTEM or Administrators; a file grants access to no one else, and a directory grants write access to no one else. Under the machine-wide config directory the device service's account `NT SERVICE\localport-device` is allowed too. |
| AG071 | No transport | No connection to the edge worked. Check that this machine reaches the edge on TCP 443 and that no firewall or proxy blocks it. |
