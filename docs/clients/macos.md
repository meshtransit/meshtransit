# macOS

The macOS client ships as a tarball for Apple silicon (arm64) and Intel
(amd64) with an install script. It runs the same split as Linux: an
unprivileged `meshd` and a root `meshnetd` that owns the `utun` interface and
DNS. How the parts work is in [Client](../architecture/client.md).

## Build

```bash
make package-darwin VERSION=0.1.0
```

Run it on macOS. It produces `meshtransit-darwin-{arm64,amd64}-0.1.0.tar.gz`
with a `.sha256` each. The binaries are not signed or notarized yet. A file downloaded with a
browser carries the quarantine attribute; one fetched with `curl` does not.

## Install

```bash
tar xzf meshtransit-darwin-arm64-0.1.0.tar.gz
cd meshtransit-darwin-arm64-0.1.0
sudo ./install.sh
```

The script:

1. checks `SHA256SUMS`;
2. creates the hidden user and group `_meshd` and a group `meshtransit`, and
   adds the user who ran `sudo` to `meshtransit`;
3. installs `meshd`, `meshnetd` and `meshcred` in
   `/usr/local/libexec/meshtransit` and `meshctl` in `/usr/local/bin`;
4. creates the state directory and, with `meshcred provision`, the identity
   key;
5. installs the launch daemons `net.meshtransit.meshnetd` and
   `net.meshtransit.meshd` and waits for the local API.

Running it again from a newer tarball upgrades in place and keeps the identity
and state.

| Path | What |
|---|---|
| `/Library/Application Support/MeshTransit/state` | State, owned by `_meshd`, mode 0700 |
| `/Library/Application Support/MeshTransit/meshd.identity-key` | Identity key, mode 0400, excluded from Time Machine |
| `/var/run/meshd/meshd.sock` | Local API; `/var/run/meshd` is `_meshd:meshtransit`, 0750 |
| `/var/log/meshtransit/meshd.log`, `meshnetd.log` | Logs, rotated at 10 MB, 5 files |
| `/Library/LaunchDaemons/net.meshtransit.{meshd,meshnetd}.plist` | Launch daemons |

`meshd` runs as `_meshd` with the same flags as on Linux; `meshnetd` runs as
root and serves only `_meshd`.

The identity key is a file only `_meshd` can read; it is not tied to the
hardware yet (a Keychain-backed key is planned), and `meshcred` on macOS can
create it but not rotate it.

## Join a Network

As on [Linux](linux.md#join-a-network):

```bash
meshctl up --server https://control.example.com --fingerprint sha256:…
```

Until you log out and in again after the install, run `meshctl` with `sudo`
(the group membership takes effect at the next login).

## Networking

- The tunnel is a `utun` interface; macOS picks its number.
- MeshTransit DNS listens on `192.0.2.53:1053`, an address `meshnetd` adds to
  `lo0`, and is registered with `scutil` as a supplemental resolver for the
  mesh names only. "DNS for all names" is not supported on macOS yet.
- Instance metadata of cloud providers is not read on macOS.

## Subnet routes

A Mac reaches the Sites its rules grant once root accepts subnet routes:

```bash
sudo /usr/local/libexec/meshtransit/meshnetd routes accept on
```

The setting lives in `/Library/Application Support/MeshTransit/routes.json`
and applies within seconds; `routes accept off` removes the routes again.
`meshnetd` installs each granted prefix on the `utun` interface in the
host's routing table, marked as its own, and refuses one that overlaps a
network the Mac reaches itself (`local_conflict`). macOS has no per-user
routing, so `meshd` keeps its own sockets off these routes: a connection to
an address inside one is bound to the interface the Mac would use without
it (`IP_BOUND_IF`), and the packet path sends nothing to a peer address
inside one. `meshctl status` shows the router each Site goes through.

A Mac does not forward into subnets: a subnet router runs on Linux.

## Use an exit node

Root chooses the Exit Pool (`--enable-exits` is on in both launchd jobs);
`meshctl` asks `sudo` for the password itself:

```bash
meshctl exit use POOL     # or auto, off
meshctl routes exit-allow-lan on
meshctl exit status
```

`sudo /usr/local/libexec/meshtransit/meshnetd routes …` still works.

`meshnetd` then routes `0/1`, `128/1`, `::/1` and `8000::/1` into the utun,
marked apart from subnet routes, and loads a pf kill switch into the anchor
`com.apple/250.MeshTransitExit`, which macOS's own `/etc/pf.conf` evaluates:
out only by loopback, the utun, `meshd`'s own sockets (user `_meshd`), DHCP,
neighbour discovery, link-local and, with `exit-allow-lan`, the attached
private subnets. pf is enabled with a reference of the helper's own and
given back when the kill switch goes. The rules stay while the helper is
down; a reboot drops them until it starts again. Replies to connections
opened from outside are dropped too. The MeshTransit DNS service matches
the root domain (`SupplementalMatchDomains` `""`), which makes its resolver
the host's default one without touching the primary service or its routes,
so every name goes to `meshd`, which asks the exit node's DNS forwarder; `meshd` resolves its own names from the
networks' resolvers (`scutil --dns`) through sockets bound to the physical
interface, its WireGuard sockets included.

While the exit routes are in place `meshnetd` also copies each physical
default route as a scoped route on its interface (`RTF_IFSCOPE`), so a
socket bound to that interface still has a route: `meshd` binds its own
sockets to the physical interface and to its address (macOS would give a
connecting socket the utun's address otherwise), and redials its relays
when the exit route comes or goes or the networks change under it. Its
WireGuard socket, bound to the physical interface, finds the scoped default
too and leaves with the interface's address, so peers are still reached
directly; a socket that could not be bound sends nothing until it is.

`sudo meshnetd --release-exit` removes the routes, the scoped defaults and
the kill switch; the uninstaller runs it. Tried on a Mac on 2026-10-21:
traffic leaves by the exit node, pf blocks the rest, and turning
`exit-use off` gives the Mac its network back at once.

### Captive portals

`meshd` finds a captive portal and root opens a window as on Linux
(`meshctl exit captive [--for D] [--close]`, which asks `sudo`). The window's
pf rules go into the kill switch's own anchor, right before its block: TCP
from each physical default interface's own address (`from (en0)`) to ports
80 and 443, and to the portal's own port, without state, so they stop the
moment the rules go. The `/1` routes leave the utun for the window, since a
route cannot tell ports apart: everything else meets the kill switch rather
than the tunnel, and the mesh keeps its own routes. macOS's own portal
window may appear by itself during the window, as expected.

`meshnetd` keeps what ends the window without it in
`/var/run/meshnetd/captive-holes.json` (root only): a child process it starts
for the window (`meshnetd captive close-at`) sleeps until the end, and the
launchd job `net.meshtransit.meshnetd-captive` (`meshnetd captive expire`,
every 30 seconds) ends any window past its time; either loads the kill
switch without the window's rules, puts the `/1` routes back and empties
mDNSResponder's cache. The window also ends by the wall clock, since the
monotonic clock stops while the Mac sleeps.

## Check and troubleshoot

- `meshctl status`, `meshctl netcheck`, `meshctl doctor control`, as on Linux.
- `sudo launchctl print system/net.meshtransit.meshd` (and `…meshnetd`) for
  the state of the launch daemons.
- Logs: `/var/log/meshtransit/meshd.log` and `meshnetd.log`.
- After a crash, `meshnetd` removes stale DNS entries and the `lo0` alias at
  its next start.

## Remove

```bash
sudo ./uninstall.sh            # from the extracted tarball
sudo ./uninstall.sh --purge    # also delete state, key, logs, the users and groups
```

Without `--purge` the identity and state are kept, so a new install reconnects
the same Device. The Device stays registered in its Network until you run
`meshctl logout` before uninstalling, or revoke it in the Console.
