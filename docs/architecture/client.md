# Client

The client turns a Device into a node of the mesh: it registers with Core,
keeps its map current, runs WireGuard to its peers, finds direct paths and
falls back to a relay, enforces the packet filter and answers MeshTransit DNS.
Code: `client/` (Apache-2.0).

## Binaries

| Binary | Runs as | Does |
|---|---|---|
| `meshd` | An unprivileged service user (Linux, macOS); LocalSystem (Windows) | The node daemon: everything below |
| `meshnetd` | root, Linux with only `CAP_NET_ADMIN` and `CAP_CHOWN` | The network helper: creates the TUN interface and applies addresses, routes and host DNS for `meshd` |
| `meshcred` | root: on Linux a oneshot `meshd` requires (normally once per boot), on macOS by the installer | Provisions the host key that encrypts `meshd`'s identity at rest; on Linux also rotates it (`rotate`, `finalize`, `commit`, `recover`) |
| `meshctl` | Any allowed user | Command-line client of `meshd`'s local API |

On Android and iOS the same daemon runs inside the app, through the gomobile
package `client/mobile` (below).

## Privilege boundary

`meshd` holds the keys and talks to the network but cannot change the host's
network configuration. `meshnetd` can, but holds no keys and accepts only
narrow, validated requests from `meshd`:

- It listens on a local socket and checks the caller's kernel credentials
  (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS); only the configured
  `meshd` user is served.
- It touches only its own interface, and only addresses and routes inside
  the overlay frame: `100.64.0.0/10`, `198.18.0.0/15` (Device aliases) and
  `fd00::/8`. `--allow-prefix` can narrow the frame, never widen it.
- It returns the TUN file descriptor to `meshd`, which runs the data plane.
- On Linux, with `--routed-table`, it can also install the subnet routes Core
  grants ([mtcp-v1 §7.6](../protocol/mtcp-v1.md)), but only those the host's
  own settings admit. Those settings live in `/etc/meshtransit/routes.json`,
  which only root writes (`sudo meshnetd routes accept on`, `accept-public`,
  `router-mode`, `advertise PREFIX…`, `withdraw PREFIX…`); everything is off
  until root turns it on, and a change applies within seconds. Subnet routes
  go in their own routing table, which one policy rule per address family
  has every user but `meshd`'s look up (`not uidrange`): the node's own
  sockets (Control, relays, WireGuard) follow the host's routing unchanged
  and cannot enter the mesh they carry. Each helper on a host uses its own
  table and rule priority (`--routed-table`, `--routed-priority`, default
  5400), and removes what it installed when it stops or starts again.
- It never lets a subnet route take over a network the host reaches itself:
  a route that overlaps an attached network, or an equal or more specific
  route of the host's main table (another VPN, for example), is refused as
  `local_conflict`. A system resolver inside an installed route keeps its
  physical path through a host exception in the routed table. It checks
  again whenever the host's routes or resolvers change, such as a laptop
  joining another Wi-Fi network, and a host with more than 16,384 routes of
  its own installs none. Each request is compared with the kernel's table,
  so a route removed behind its back is installed again; a route the kernel
  refuses is reported (`install_failed`, `family_unavailable` on a host
  without IPv6) without affecting the others.

## Subnet routes

With `--enable-subnet-routes` (Linux only for now), `meshd` asks Core for
the Sites its rules grant and handles them as
[mtcp-v1 §7.6](../protocol/mtcp-v1.md) requires:

- It asks `meshnetd` for every prefix of every granted Site, whatever its
  status, so traffic to a Site never leaves by the default route. One worker
  sends the requests in order, outside the data plane's lock, and only the
  answer to the latest one decides what the packet filter admits. It asks
  again every 10 seconds, so a restarted helper or a network change is
  caught up without a new map, and retries a removal until it succeeds.
- A Site prefix containing a mesh address of the node or of a peer is
  ignored: a router never takes over a node's own address.
- Only a `SERVED` Site's prefixes are given to its primary router's
  WireGuard peer. The packet filter lets a packet reach a Site only when the
  helper installed its prefix, the Site is served and the router is usable;
  a Site's hosts can only answer flows this node opened, never open one.
  Flows end when the helper removes the prefix or the Site gets another
  router.
- A packet for a Site that is not served (`UNSERVED`, `CONFLICT`,
  `CAPACITY`, or overlapping another Site) is answered with an ICMP host
  unreachable, at most 10 a second per Site, so applications fail at once.
- With lazy peers, a packet to a Site installs its router on demand.
- `meshctl status` shows a `Subnet routes` line: requested, installed and
  refused routes with their reasons, the health (`route_conflict_local`,
  `route_install_failed`) and the unreachable answers. The local API
  reports the same under `subnet_routes`.

On Windows a Wintun session cannot be handed to another process, so `meshd`
is one LocalSystem service that applies the same checks in process.

| Platform | Helper | TUN | Host DNS | Identity key at rest |
|---|---|---|---|---|
| Linux | `meshnetd` (`unixpacket` socket) | `/dev/net/tun` | `systemd-resolved` | Host-bound systemd credential (`meshcred`) |
| macOS | `meshnetd` (framed stream socket) | `utun` | `scutil` supplemental resolver | Owner-only key file (`meshcred`); not hardware-bound yet |
| Windows | none | Wintun | NRPT rule to `127.53.53.53` | DPAPI |
| Android, iOS | none | `VpnService` / packet tunnel file descriptor | not yet | Supplied by the app's key store |

## Local API and meshctl

`meshd` serves an HTTP API on a local socket only: `/run/meshd/meshd.sock`
on Linux, `/var/run/meshd/meshd.sock` on macOS and the named pipe
`\\.\pipe\ProtectedPrefix\Administrators\MeshTransit\meshd` on Windows. Every
request is authorized by the caller's kernel-verified identity:

- **Unix:** root, `meshd`'s own user or a UID given with `--allow-uid`. The
  packages run `meshd` with `--allow-socket-peers`, which admits any verified
  caller that can open the socket; the boundary is then the socket
  directory's permissions, which admit only the `meshtransit` group.
- **Windows:** LocalSystem, an elevated administrator or a member of
  `MeshTransit Users`.

It exposes health and status, profiles, control trust, login, node key
rotation, `up`, `down`, `logout` and diagnostics. `meshctl` is a thin client
of it (`meshctl up`, `status`, `down`, `logout`, `profile …`, `netcheck`,
`doctor control`); it never reads `meshd`'s state or keys.

## Identity and profiles

A **profile** is one Core deployment the node can join. Each has its own
record: the pinned control key, the machine key, the node key and, during a
rotation, the staged next keys. Records are encrypted at rest with
AES-256-GCM under the host key, stored owner-only, and bounded in size.

- **Trust.** Before registering, the node fetches Core's control key and
  checks it against the fingerprint given by the user or the enrollment link;
  from then on the key is pinned. Core can announce a next control key,
  which the node stages and adopts at rotation.
- **Registration** uses an enrollment key or a browser approval, over MTCP.
- `meshctl down` keeps the registration but disconnects, across restarts;
  `meshctl logout` ends the Device in Core and replaces the machine and node
  keys.

## Control session

`meshd` holds one [MTCP](../protocol/mtcp-v1.md) session to Core over HTTPS
port 443: HTTP Upgrade, falling back to WebSocket, then a Noise IK handshake
to the pinned control key.

- The node announces its capabilities, then receives a **map snapshot** and
  **deltas**. It acknowledges a snapshot at once and deltas in batches; a gap
  in the sequence makes it ask for a resync.
- The map is validated as a whole (`client/internal/networkmap`): sizes,
  addresses, keys and policy are checked, and endpoints the
  [endpoint policy](../../shared/endpointpolicy/endpoint.go) refuses are
  dropped. A map that fails validation is never applied.
- Core's lifecycle messages suspend, expire or revoke the node, or ask it to
  reconnect, possibly after a `Retry-After` the node honours (up to
  15 minutes).
- After a transient failure the node reconnects with jittered, doubling
  backoff up to 60 seconds, and always starts from a fresh snapshot. A
  permanent failure (revoked, suspended or expired Device, a changed control
  key, a rejected map) stops the stream and goes to the daemon, which
  recovers on its own schedule.

## Applying a map

For each map the daemon, in order:

1. hands the map to the WireGuard engine: interface addresses, aggregated
   routes, peers, the relay pool and the packet filter;
2. reports what it enforces (the [policy digest](../protocol/policy-digest-v1.md)
   of the installed filter);
3. starts or updates path probing for the peers;
4. applies DNS.

### Data plane

The engine is wireguard-go on the TUN interface. Peer changes are applied as
diffs, so an update does not reset the tunnels of unchanged peers; a peer
whose disco key changed starts a new session.

- Up to 10,000 peers. Above 1,000 peers they are **lazy**: a peer is
  installed in WireGuard when traffic to it, or a handshake from it, arrives,
  and removed after 10 minutes idle.
- The packet filter is deny-by-default and node-reduced: it allows inbound
  traffic only as the map's rules say, plus replies to flows the node opened.
  It also drops packets from or to an expired node key.

### Paths

Every peer with a home relay starts on the relay path; a direct path replaces
it once proven
([paths and relays](../concepts/paths-and-relays.md)):

- **Endpoints.** The node learns its own candidate addresses from STUN on the
  WireGuard socket, local interfaces, a port mapping (PCP, NAT-PMP or UPnP,
  used only if the node observed the external address itself) and, on AWS,
  GCP, Azure or DigitalOcean under Linux, the instance metadata. It reports
  them to Core, with its NAT type and home relay, in an `EndpointReport`. It
  refreshes them every 20 to 26 seconds while it has peers, and after a
  network change or a relay failure, but such event rounds at most once every
  5 seconds.
- **Probing.** About every 3 seconds the node pings the candidates of each
  online peer. A `CALL_ME_MAYBE` through the relay asks a peer without a
  working path to ping back, which opens both NATs. Pings are authenticated
  with the disco keys, and a per-peer budget bounds what a peer, or a Device
  lying about its endpoints, can make the node send.
- **Selection.** The first candidate that answers becomes the peer's
  WireGuard endpoint; another replaces it only if at least 10% and 2 ms
  faster. Without fresh pongs a path is trusted for 6.5 seconds, after which
  the peer falls back to the relay. WireGuard traffic goes to one path at a
  time.

### Relays

The node connects to the relays of its map over
[MTRP](../protocol/mtrp-v1.md): UDP first, then TLS 1.3 and WebSocket on the
relay's TLS port for networks that block UDP. The relay is authenticated by the Noise
handshake against its key in the signed relay map, not by its TLS
certificate, and the node presents the ticket Core issued for it.

The node keeps one **home relay**: a region its Network prefers (Private
Interchange) if one is usable, otherwise the home Core last recorded for it,
otherwise the lowest usable region; it switches only to a clearly faster
region. See [paths and relays](../concepts/paths-and-relays.md#relays) and
[Relay](relay.md).

### DNS

MeshTransit DNS answers the names in the map. `meshd` runs the resolver on a
local address and the host routes only the mesh names to it (split DNS);
other names keep using the host's resolvers. The map carries an address
record for each name (the node's own, its same-Network peers' and its
imported shares'), the suffix as a locally answered route and the Network's
zone as search domain. The node derives reverse (PTR) records itself from the
records of the zone its own name is in. On Android and iOS, DNS is not
implemented. See [DNS](../concepts/dns.md).

### Device aliases

When a Device is shared, the two nodes see each other at alias addresses
from the Deployment's alias pools (`198.18.0.0/15` in the packaged frame),
never at each other's real overlay addresses: the shared Device appears to
the consumer at its Resource Alias, the consumer to the shared Device at its
Consumer Source Alias. Core allocates the aliases and sends the grants
([Device alias v1](../protocol/device-alias-v1.md)); the nodes translate the
packets, and Core is never in the packet path.

## Mobile

`client/mobile` is the API the Android and iOS apps call (`APIVersion` 1):
create and activate profiles, trust the control key, log in, `Up`, `Down`,
`Logout`, report network changes and read status as JSON. The app provides
the TUN file descriptor, a key store, a log sink and, on Android, a socket
protector so the tunnel's own traffic bypasses the VPN. Routes are widened to
stable blocks (`/16` in IPv4, `/64` in IPv6) so a new peer does not rebuild the
VPN interface; only overlay routes are widened, and above 1,024 blocks the
routes stay exact. Mobile has no local API, port mapping, cloud metadata, DNS
or Device aliases yet.

## Platforms and packages

| Platform | Package | Service |
|---|---|---|
| Linux | `.deb` for `meshd` (with `meshnetd`, `meshcred`) and `meshctl` | systemd |
| macOS | Tarball with an install script | launchd daemons |
| Windows | Zip with `install.ps1` | One service, `MeshTransit` |
| Android, iOS | Built into the app (`make mobile-android`, `make mobile-ios`) | The OS VPN service |

`meshd` starts with its data plane, DNS and Device aliases off
(`--enable-data-plane`, `--enable-dns`, `--enable-device-aliases`); every
package turns all three on.
