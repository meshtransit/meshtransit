# Device alias client contract v1

## Status

The client implements validated alias maps and peer-specific packet translation
for TCP, UDP and ICMP echo over IPv4 and IPv6. The two participating `meshd`
processes enforce sharing; no additional gateway or proxy participates. Core
remains outside the packet path. Canonical addresses may be identical in the
consumer and provider Networks.

This is a client implementation checkpoint, not an enabled sharing release.
Core schemas 81–87 implement allocation, guarded readiness, withdrawal and map
projection behind explicit runtime switches. The client advertises alias v1
only when started with `--enable-device-aliases --enable-data-plane` and a fixed
WireGuard port. The root helper must independently include the installation's
alias pools in its allowed pools. No flag widens helper confinement or grants
membership. Every streaming reconnect and non-streaming endpoint update sends
`DeviceAliasVersion: 1`; the ordinary path omits the field. Explicit empty
endpoint withdrawal remains unchanged. An unrequested alias map is rejected
before the daemon consumer runs. Numeric protocol capability 142
is not evidence of this feature. Complete Core/client runtime traffic, bilateral authority updates, imported
DNS and alias flow reporting remain qualification gates. Earlier two-host
checks used encrypted map fixtures and do not qualify Core runtime enrollment.

## Product authority and wire boundary

`networkmap.AliasBinding` is ephemeral authority attached to one peer. It binds
an exact contract, endpoint, endpoint generation, grant revision, recovery epoch,
self Node key, peer Node key, direction, exclusive deadline and service list.
It creates no Device or membership and is never persisted in a profile.

The compatibility adapter accepts exactly one JSON document under the Node
capability `https://meshtransit.io/cap/device-alias-v1`, together with at least
one per-peer self masquerade address. These adapter-only address fields encode
the local alias for that peer. The peer's Addresses and AllowedIPs encode only
its remote aliases as identical exact host routes. The document fields are:

| Field | Meaning |
| --- | --- |
| `version` | Exactly 1 |
| `contract_id`, `endpoint_id` | Nonzero canonical UUID-shaped identifiers |
| `generation`, `grant_revision`, `recovery_epoch` | Nonzero unsigned authority versions |
| `self_key`, `peer_key` | Exact current Node public keys |
| `role` | `consumer` or `provider` |
| `expires_at` | Exclusive UTC deadline, bounded by both finite Node deadlines |
| `services` | Ordered disjoint protocol and destination-port grants |

Each service has `protocol`, `port_from` and `port_to`. TCP (6) and UDP (17)
require ports 1–65535. ICMPv4 (1) and ICMPv6 (58) allow echo only and use zero
ports, with the corresponding family present. No wildcard protocol is accepted.
The document is limited to 8 KiB, nesting depth four and 64 services. Field
names match exactly; unknown fields, casing variants, duplicate keys, multiple
documents, trailing values and integer overflows fail the whole candidate map.
Legacy masquerade fields without the typed grant are rejected.

The map validates at most 256 alias peers. Both families must have a canonical
local address and complete local/remote aliases. Duplicate addresses, mapped
IPv4, zones, loopback, link-local and non-unicast addresses are rejected. A local
alias cannot collide with any mapped address. Multiple provider peers may share
one Resource Alias only for the same contract, endpoint, generation and recovery
epoch. Consumer aliases cannot have incompatible owners.

The one-binding-per-peer representation cannot encode multiple incompatible
endpoint bindings for the same Node-key pair. Core must reject that combination
rather than duplicate peer keys or select one binding. Core must additionally
respect its complete map envelope limit; per-document limits do not authorize
an oversized aggregate map.

## Packet boundaries

| Boundary | Source | Destination |
| --- | --- | --- |
| Consumer kernel | Consumer canonical | Resource Alias |
| Consumer encrypted packet | Consumer Source Alias | Resource Alias |
| Provider kernel | Consumer Source Alias | Provider canonical |
| Provider reply kernel | Provider canonical | Consumer Source Alias |
| Provider encrypted reply | Resource Alias | Consumer Source Alias |
| Consumer reply kernel | Resource Alias | Consumer canonical |

WireGuard binds each remote source alias to the expected peer key. At the TUN
boundary the client requires the exact local alias destination before rewriting
it to the canonical local address. Outbound translation requires the exact
canonical local source. Raw-address fallback and spoofed local sources fail.

The consumer may initiate only a granted service. Provider ingress also requires
the current projected inbound PacketFilter rule. Only an admitted tracked flow
permits replies. A provider cannot initiate, even if a wildcard rule exists or
a bare TCP SYN uses an existing reply tuple. A separate opposite contract is
required for opposite initiation. New alias flows fail closed when the bounded
flow table is full; an untracked TCP continuation cannot create reply authority.

The translator validates packet length, original addresses, IPv4 header checksum
and transport checksum before modifying bytes. It recalculates the IPv4 header
and TCP, UDP and ICMPv6 checksums. IPv4 UDP without a checksum preserves that
absence; IPv6 UDP without a checksum is denied. A computed zero UDP checksum is
encoded as `0xffff`. Denial leaves packet bytes unchanged. Ports, TCP flags,
ICMP echo identifiers and payload bytes remain unchanged.

Alias v1 denies fragments, IPv4 options, IPv6 extensions, jumbograms, ICMP errors
and other transports. Ordinary peer behavior is unchanged. ICMP quoted-packet
translation and broader packet forms require a separate tested contract.

## Replacement, expiry and failure

Bindings and service slices are cloned before publication. Translation, rule
checks and flow state use one authority lock. Every packet checks both Node
and grant deadlines before consulting state. Clock loss denies admission.
Security changes clear flow state; endpoint-only changes preserve compatible
flows. A grant cannot regress its generation or revision, mutate within the same
revision, change contract recovery, or downgrade to an ordinary peer while that
peer remains installed. Address/key changes require a newer generation; grant
renewal or service changes require a newer revision.

The packet gate pauses while a map with aliases replaces keys, peer routes,
relay authority or TUN state. It resumes only after every engine operation
succeeds. Invalid maps or ambiguous apply failures withdraw packet authority
and close the engine where required. No authority lock is held over helper or
device I/O. Packet translation creates no worker or timer.

The privileged helper still receives canonical self addresses and exact remote
host routes. Alias pools must be explicitly included in its allowed route pools;
the client does not widen helper confinement. Allocation must exclude all
configured overlay pools, DNS reservations, active and quarantined aliases.
The examples in fixtures are not runtime allocation defaults.

## Evidence and remaining gates

The packet fixtures are independently generated synthetic inputs and expected
outputs, not copied reference implementation source. Eight checksum vectors
cover both families, absent IPv4 UDP checksum and computed-zero IPv6 UDP
checksum. Six two-client roundtrip vectors cover TCP, UDP and ICMP with
identical canonical IPv4 and IPv6 addresses. Tests exercise actual observed-TUN
boundaries, grant replacement, revoke, expiry, raw-address denial, source spoof,
reverse initiation, flow exhaustion, concurrent map changes and apply failure.
Fuzz targets cover packet rewriting and strict grant decoding; the discovered
invalid-original-address regression is retained in the corpus.

Local qualification includes whole-tree race tests, vet and lint, both bounded
fuzz targets, reachable dependency vulnerability checks and secret scans.
This evidence does not qualify live encrypted sharing. Remaining gates include
Core allocation/quarantine and authenticated bilateral authority, both-Network
wakeups/reconciliation, overlapping-address encrypted traffic on disposable
clients, policy/revoke/expiry latency, third-Network isolation and DNS lifecycle.

Current packet observers see outbound translated sources and inbound canonical
destinations. The existing flow reporter does not index local aliases, so
outbound alias observations are omitted. Alias telemetry needs an explicit
scope/identity contract and tests before release; it must not expose foreign
Workspace identifiers through ordinary inventory or logs.
