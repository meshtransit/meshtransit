# Windows

The Windows client ships as a zip for amd64 and arm64 with PowerShell install
scripts. It runs as one service, `MeshTransit`, under LocalSystem: a Wintun
session cannot be handed to another process, so there is no separate network
helper. How the parts work is in [Client](../architecture/client.md).

## Build

```bash
make package-windows VERSION=0.1.0
```

It produces `meshtransit-windows-{amd64,arm64}-0.1.0.zip` with `meshd.exe`,
`meshctl.exe`, `wintun.dll` 0.14.1 (pinned by SHA-256; signed by its
authors), the install scripts and `SHA256SUMS`. `meshd.exe` and `meshctl.exe`
are not code-signed yet, and there is no MSI.

## Install

From an elevated PowerShell in the extracted folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

The script:

1. checks `SHA256SUMS`;
2. creates the local group **MeshTransit Users** and adds the account that
   runs it (add other users yourself);
3. copies the files to `C:\Program Files\MeshTransit`, and adds that folder to
   the machine `PATH`;
4. registers the service `MeshTransit` (LocalSystem, automatic start,
   restarted on failure) running `meshd.exe --enable-data-plane --enable-dns
   --enable-device-aliases --wireguard-listen-port=41641`;
5. starts it and waits for `meshctl status`.

Running it again from a newer zip upgrades in place and keeps the identity and
state.

| Path | What |
|---|---|
| `C:\Program Files\MeshTransit` | Binaries, `wintun.dll`, `uninstall.ps1` |
| `C:\ProgramData\MeshTransit\state` | State |
| `C:\ProgramData\MeshTransit\meshd.identity-key` | Identity key, sealed with DPAPI for LocalSystem and a fixed MeshTransit entropy |
| `C:\ProgramData\MeshTransit\logs\meshd.log` | Log; readable by SYSTEM and Administrators only; not rotated yet |
| `\\.\pipe\ProtectedPrefix\Administrators\MeshTransit\meshd` | Local API |

## Who may use meshctl

Open a new terminal after the install (for the `PATH`), and sign in again for
the group membership to take effect. Then `meshctl` works for:

- members of **MeshTransit Users**;
- an **elevated** administrator (an administrator's normal, non-elevated token
  is refused);
- LocalSystem.

`meshctl` also checks that the pipe belongs to SYSTEM, so another process
cannot pose as `meshd`.

## Join a Network

As on [Linux](linux.md#join-a-network):

```powershell
meshctl up --server https://control.example.com --fingerprint sha256:…
```

## Networking

- The tunnel is a Wintun adapter named **MeshTransit**, with a fixed GUID and
  MTU 1280; `meshd` sets its addresses and routes itself.
- MeshTransit DNS listens on `127.53.53.53:53`, and one NRPT rule sends only
  the mesh names to it. If Group Policy defines NRPT rules, Windows ignores
  local ones; `meshd` then also writes its rule under the policy key, but a
  policy refresh can remove it until the next update. For a lasting fix, add
  the mesh names to the policy.
  "DNS for all names" is not supported on Windows yet.
- `meshd` does not configure Windows Firewall or the adapter's network
  category. Windows may classify the adapter as a Public network and block
  incoming connections over the mesh; allow the traffic you need with a
  firewall rule for the **MeshTransit** interface.

## Subnet routes

A Windows machine reaches the Sites its rules grant once an administrator
accepts subnet routes, from an elevated console:

```powershell
meshd routes accept on
```

The setting lives in `C:\ProgramData\MeshTransit\settings\routes.json`, in
a directory only SYSTEM and Administrators may open; `meshd` ignores a file
anyone else owns or may change, and status then refuses every route with
`settings_unusable`. It applies within 10 seconds;
`meshd routes accept off` removes the routes again. The service installs
each granted prefix on the **MeshTransit** adapter and refuses one that
overlaps a network the machine reaches itself, or that holds a DNS server
of another adapter (`local_conflict`). Windows has no per-user routing, so
`meshd` keeps its own sockets off these routes: a connection to an address
inside one leaves through the interface Windows would use without it
(`IP_UNICAST_IF`), and the packet path sends nothing to a peer address
inside one. `meshctl status` shows the router each Site goes through.

A Windows machine does not forward into subnets: a subnet router runs on
Linux.

## Check and troubleshoot

- `meshctl status`, `meshctl netcheck`, `meshctl doctor control`.
- `Get-Service MeshTransit`, and the log in `C:\ProgramData\MeshTransit\logs`.
- To debug, stop the service and run `meshd.exe` from an elevated prompt with
  the service's flags (above): it runs in the foreground. `meshctl` talks only
  to a pipe owned by SYSTEM, so it may refuse such a process.
- If identity records exist but the key file is missing, `meshd` refuses to
  start: restore `meshd.identity-key`, which can only be unsealed on the same
  machine.
- `meshd` creates `C:\ProgramData\MeshTransit` and its folders itself, with
  access for SYSTEM and Administrators only, and refuses to start when one of
  them is a link or junction or is owned by anyone else; it does not create a
  missing parent folder. A log file another account could read, or one that
  is a link, is replaced by a new one.
- A key sealed by an older `meshd`, without the entropy, still opens and is
  resealed on the first start. From then on an older `meshd` cannot open it:
  to go back to an older version, restore the key file backed up before the
  upgrade, or stay on a version that has the entropy. If resealing fails,
  `meshd` logs a warning, keeps working and retries on the next start.

## Remove

From an elevated prompt:

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Program Files\MeshTransit\uninstall.ps1"
powershell -ExecutionPolicy Bypass -File "C:\Program Files\MeshTransit\uninstall.ps1" -Purge
```

The script stops and removes the service, the NRPT rule and the `PATH` entry,
and deletes the installed files (it leaves itself, so the folder remains).
`-Purge` also deletes `C:\ProgramData\MeshTransit` and the MeshTransit Users
group. Run `meshctl logout` first to remove the Device from its Network.
