# Client security model

What the client protects, where its trust boundaries are, and which controls
hold them. The mechanics are described in [Client](../architecture/client.md);
this page is about what an attacker at each boundary can and cannot do.

## Assets

- The machine, node and disco private keys of each profile, and the host key
  that encrypts them at rest.
- The authenticated control session and the pinned control key.
- The validated map: peers, routes, packet filter, relay map, DNS records and
  Device alias grants.
- The host's network configuration: the tunnel interface, its addresses and
  routes, and the DNS settings MeshTransit adds.
- Traffic metadata: peer identities, addresses, ports, counters and times.

Packet payloads are never collected.

## Trust boundaries

| # | Boundary | Untrusted side |
|---|---|---|
| 1 | `meshctl` and apps to `meshd`'s local API | Any local process |
| 2 | `meshd` to Core over MTCP | The network; Core only once its key is pinned |
| 3 | `meshd` to `meshnetd` (Linux, macOS) | `meshd`, from the helper's point of view |
| 4 | The data plane to packets from peers, relays and the network | Everything |
| 5 | `meshd` to relays over MTRP | The network and the relay operator |
| 6 | `meshd` to the local gateway (port mapping) and cloud metadata | The LAN |
| 7 | Flow logs to the log collector | The collector's storage |

## Invariants

- Control URLs are HTTPS on port 443, without credentials, query or
  fragment; there is no plaintext or proxy fallback.
- The client never chooses its Network; Core decides from its credentials.
- A map is validated as a whole before it replaces the active one; a missing,
  malformed or unauthorized map fails closed.
- One profile is active at a time, and profiles share no keys.
- Private keys never appear in logs, API responses, errors or flow events.
- The network helper never sees a key and accepts only a small fixed set of
  requests.
- Flow events carry metadata and counters only.

## Local API

- `meshd` listens only on a local socket or named pipe, refuses any other
  listener, bounds header and body sizes and read, write and idle times, and
  checks the caller of every connection:
  - **Linux and macOS:** `SO_PEERCRED` or `LOCAL_PEERCRED`. Root, `meshd`'s
    own user and UIDs given with `--allow-uid` are allowed. With
    `--allow-socket-peers` (set by the packages), any verified caller that can
    open the socket is allowed, and the socket directory (`meshd:meshtransit`,
    0750) limits that to the `meshtransit` group.
  - **Windows:** the pipe lives under `ProtectedPrefix\Administrators`, so
    only an administrator or LocalSystem can create it, and it refuses remote
    clients. Callers are authorized from the access token of the connection
    itself, read by impersonating the client at the identification level, not
    from whatever process holds the client's process ID: LocalSystem, an
    elevated administrator or a member of **MeshTransit Users**. An anonymous
    client is refused. `meshctl` opens the pipe at the identification level,
    which lets `meshd` read its token but never act as it, and checks that the
    pipe's owner is SYSTEM before sending anything.
- The socket is never created over a regular file or over a socket another
  `meshd` still answers on.
- Errors do not reveal state paths or internal storage errors. Keys are never
  returned; status shows counts and states, and only an explicit
  `meshctl netcheck` returns the node's own public address.

## Identity at rest

- Profile and identity records live in owner-only directories (0700) and
  files (0600), opened through separate `os.Root` handles so symlinks and path
  escapes are refused. Records are bounded (64 KiB per identity record, 1 MiB
  of profile state), strictly decoded, and
  written with a temporary file, `fsync`, rename and a directory `fsync`.
- Identity records are AES-256-GCM envelopes with a random nonce, the profile
  and envelope version as associated data. A new record is reopened and
  compared before it is committed.
- The 256-bit host key that seals them:

  | Platform | Stored as | Protects against |
  |---|---|---|
  | Linux | A systemd credential encrypted with the host key, created by the `meshcred` oneshot (no capabilities, no network) and decrypted only into `meshd`'s private credential mount | Copying the state to another host; reading the disk offline |
  | macOS | A file only `_meshd` can read, excluded from Time Machine | Other users; not root, and not hardware-bound yet |
  | Windows | DPAPI, sealed for LocalSystem with a fixed MeshTransit entropy | Other users, other machines and generic DPAPI tools; not code running as LocalSystem |
  | Android | The app's Android Keystore key | Other apps; backups are disabled |

  `meshnetd` never receives the key.
- On Linux the key can be rotated: `meshcred rotate` keeps a verified,
  host-encrypted recovery copy, `meshd` rewraps every record at its next
  start, and the old key is deleted only by an explicit `commit` after a
  `finalize` proves the new key alone reads everything
  ([Linux](linux.md#rotating-the-identity-key)). Rotation is not supported on
  macOS or Windows yet.

## Control session

- **Pinning.** First enrollment checks Core's control key against a
  fingerprint from an independent channel (the user, or the enrollment link)
  before creating any identity key. Every later connection fetches the key
  again and compares it, and its fingerprint, with the pinned one before the
  Noise handshake. `meshctl doctor control` only shows what the server
  presents, which is trust on first use if the path is compromised.
- **Control key rotation.** Core announces a next key with an authenticated
  `KeyUpdate` on the pinned session; the node stages it and adopts it only at
  rotation, so an unauthenticated peer can never replace the pin.
- **Registration.** Enrollment keys are read from standard input, kept only
  in memory and never stored. Browser follow-up links must be same-origin
  HTTPS registration paths. The whole exchange is time-bounded; trust,
  malformed-response and rejection failures are final, while timeouts and
  5xx are retried. One owner serializes registration, so concurrent callers
  cannot replay a follow-up or race the identity write.
- **Node key rotation** is authenticated by the machine key and the current
  node key, carries no login credential, and stages the new key durably
  before the request, so a crash or failure never loses the active key.
- **Map messages** are bounded per type (a snapshot at most 32 MiB, a delta
  8 MiB, decompression windows 8 MiB). Reconnects use jittered backoff and
  always begin with a fresh, validated snapshot.
- **Revocation.** Core's lifecycle messages suspend, expire or revoke the
  node; the daemon then tears down the data plane, DNS and probes. A transport
  failure is never treated as revocation. If cleanup cannot be proven, the
  session stops rather than reuse uncertain state.
- Control-supplied URLs are not fetched by the node.

## Map and packet filter

- The map is copied and validated before it is published: it bounds peers
  (100,000 in a map; WireGuard and path selection track up to 10,000),
  addresses, routes, endpoints, rules and relay topology, and rejects
  duplicate addresses, malformed keys, an unexpected self key, an expired or
  unauthorized self, endpoints the endpoint policy refuses, and any address
  or allowed prefix outside the overlay frame (`100.64.0.0/10`,
  `198.18.0.0/15`, `fd00::/8`). A map can therefore never route a LAN, a
  public range or the default route to a peer.
- On Android, where no helper exists, `meshd` checks the same frame before it
  hands addresses and routes to the platform VPN interface.
- The packet filter is deny-by-default and node-reduced. It checks address
  ownership in both directions, allows inbound traffic only as the rules say
  plus replies to flows the node opened (a bounded, expiring flow table), and
  drops malformed and fragmented packets.
- Every packet is checked against the self and peer key deadlines before any
  rule or flow state, so a silent control stream cannot extend access.
- A map update keeps only the flows it still authorizes. A flow ends when its
  peer's address moves to another node or key, when either end's key lapsed,
  when this node's addresses or key change, or when its alias grant changes.
  A flow that local rules admitted (a reply from a local server, or a
  shared-Device provider flow) also ends on any rule change. A flow this node
  opened survives local rule changes, because the remote node's filter
  authorizes it. Other peers joining, leaving or rotating keys leave
  established connections running.
- [Device alias](../protocol/device-alias-v1.md) packets are accepted only for
  the exact alias, direction and service of a valid, unexpired grant bound to
  both nodes' keys; raw destinations, spoofed sources, reverse initiation and
  invalid checksums are dropped. Legacy address fields alone grant nothing.

## Network helper

- `meshnetd` serves only the configured `meshd` user, verified with
  `SO_PEERCRED` (Linux, `SOCK_SEQPACKET`) or `LOCAL_PEERCRED` (macOS, framed
  stream). Messages are at most 192 KiB, unknown fields and passed descriptors
  are refused, and each operation has a deadline.
- Its startup configuration fixes the interface names, MTU, allowed user,
  overlay frame and DNS endpoint. Requests can only open the tunnel, set its
  addresses and host routes, set or reset MeshTransit DNS and, on Linux,
  request subnet routes; they cannot carry default routes, commands, paths
  or keys. Every tunnel prefix must lie in the frame (`100.64.0.0/10`,
  `198.18.0.0/15`, `fd00::/8`). Subnet routes go only in the helper's own
  table and only as far as root's settings in
  `/etc/meshtransit/routes.json` admit: never a default or very wide route,
  the frame, loopback, link-local or multicast, a public range without
  `accept-public`, more than 4,096 routes, or a network the host reaches
  itself. A compromised `meshd` cannot widen any of these. As a router it
  forwards only into the part of what is requested that root's settings
  offer while router mode is on, and only through its own nftables table.
  A router's health check reads that table, the forwarding settings it
  needs and connection tracking use, and repairs only what it installed
  itself; the helper sends no packets and keeps its address families
  (`AF_UNIX`, `AF_NETLINK`).
- Route changes add before they remove and roll back on failure. `meshd`
  checks the helper's result against the validated map before using the
  tunnel.
- On Linux it runs with only `CAP_NET_ADMIN` and `CAP_CHOWN` and calls one
  root-owned `resolvectl` without a shell. The local API and the helper use
  separate runtime directories, so neither group can replace the other's
  socket. On Windows there is no helper; `meshd` applies the same checks in
  its LocalSystem service.

## Paths, probes and relays

- **Candidates.** Loopback, link-local, multicast, unspecified and
  IPv4-mapped addresses are dropped, as are addresses in `100.64.0.0/10` and
  every address on a point-to-point interface, so a host running several
  clients never publishes another Network's overlay address. At most 16 are
  published. A candidate grants no route or permission; it is only something
  to probe ([paths and relays](../concepts/paths-and-relays.md)).
- **Probes** share the WireGuard socket and are authenticated with
  XChaCha20-Poly1305 under a key derived from the two disco keys (X25519).
  Zero, self and low-order keys are refused; packets are bounded; a pong must
  match a random transaction bound to the session, map revision, socket,
  peer and destination, and expires in seconds. Per-peer and global budgets
  bound how many pings a peer, or a Device lying about its endpoints, can
  make the node send. Probe processing never blocks WireGuard.
- **Path selection** keeps at most 10,000 peers. A direct path is used only
  for a signed candidate with a fresh authenticated pong, for 6.5 seconds
  without a new one. WireGuard roaming is off for peers with an endpoint, so
  a packet arriving on another path cannot move the endpoint; relay traffic
  never proves a direct path.
- **STUN** answers are accepted only from the signed relay map's STUN
  servers, with random transaction IDs, and from the exact expected source.
- **Relays** are reached over UDP, TLS 1.3 or WebSocket. The TLS layer does
  not verify the relay's certificate: the relay is authenticated only by a
  Noise handshake against its key in the signed relay map, and the node
  presents a ticket from Core. A relay sees only WireGuard
  ciphertext and node public keys. Queues, frame sizes, regions and retries
  are bounded; unknown senders and oversized frames are dropped.

## DNS

- DNS records come only from the validated map and are bounded; names are
  canonicalized, duplicates and resolver URLs are rejected, and only plain
  resolvers on port 53 are accepted.
- The resolver bounds message sizes, concurrency, connections and query
  time, randomizes upstream transaction IDs, validates answers and does not
  log query names.
- Host DNS is changed only for mesh names (split DNS), only after the
  resolver is ready, and rolled back on partial failure
  ([DNS](../concepts/dns.md)).

## Gateway and cloud metadata

- Port mapping talks only to the IPv4 default gateway. Replies must come from
  the gateway and match the request; UPnP URLs must be plain HTTP to the
  gateway's address with no redirect, credential or proxy; responses are
  bounded. Only the WireGuard UDP port is mapped, and mappings are removed on
  exit. `--port-mapping=off` disables it.
- Cloud metadata is read only on a provider recognized from DMI data (Linux),
  only from `169.254.169.254` without proxy or redirect, with a two-second
  timeout and a 64 KiB limit; only public addresses are kept.
  `--cloud-metadata=off` disables it.
- Neither logs gateway, external or metadata addresses.

## Flow logs

Flow logging is opt-in. It reads only bounded IP, TCP and UDP headers, keeps
5-tuples, states and counters, and never copies payload. Events are tied to
one map generation and its Node and Network scope; upload uses HTTPS with two
opaque bearer tokens from Core, refuses redirects, and is bounded. A full queue or
a failed upload drops telemetry, never packets.

## Known gaps

- **Windows:** `meshd` does not configure the firewall or the adapter's
  network category; Windows may treat the mesh as a Public network. Binaries
  are not code-signed.
- **macOS:** the identity key is a root-readable file, not hardware-bound or
  in the Keychain, and cannot be rotated. Binaries are not signed or
  notarized.
- **Linux:** a root attacker who can read systemd's host key can decrypt the
  identity; there is no TPM binding. State and credential backups must be
  handled as secrets.
- **Android:** the control key fingerprint is compared by eye, not taken
  from a link. DNS, aliases and always-on VPN are not implemented.
- A failed DNS apply also stops the control session today.
- There is no replay or rollback protection of local state across restarts,
  and no session resume: every reconnect takes a full snapshot.
- Node keys are not renewed automatically before they expire.
- Subnet routes reach Sites, and subnet routers forward into them, from
  Linux only; macOS and Windows report both unsupported. Exit routes, capability
  grants and fragment reassembly are not implemented; they fail closed.
- Flow logs have no durable client queue, credential rotation, retention
  policy or tamper-evident storage.
- Fuzzing, long relay saturation runs and repeated policy matrices are not
  part of an automated release gate yet; see
  [Qualification](../testing/qualification.md).
