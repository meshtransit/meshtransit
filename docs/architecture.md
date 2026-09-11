# meshd architecture

## Purpose

`meshd` is a new MeshTransit daemon, not a renamed upstream daemon. The repository is split by stable product responsibilities so protocol compatibility can evolve without controlling the CLI, persistence model, or operating-system boundary.

## Components

```text
meshctl
  │ versioned JSON over a local Unix socket
  ▼
meshd
  ├── profile service       one active control-plane identity
  ├── control adapter       pinned TS2021/Noise registration and map stream
  ├── policy validator      fail-closed, atomic network-map validation
  ├── DNS planner           protocol-independent MagicDNS/split-DNS transaction plan
  ├── packet policy gate    inbound ACL plus bounded return-flow state
  ├── tunnel engine         userspace WireGuard relay/direct path POC
  ├── traffic events        bounded 5-tuple/counter events without payloads
  └── net-admin client      fixed-schema descriptor request to privileged meshnetd
                              │
                              ▼
                            meshnetd
                              pool-confined TUN and resolved-link setup; firewall later
```

The current code implements the profile service, persistent per-profile identity, explicit control-key pinning, TS2021/Noise registration, long-lived map streaming, product-owned map and DNS validation, local API, composition root, bounded control compatibility probe, and opt-in Linux TUN/WireGuard POCs. Data-plane status distinguishes `not_implemented`, `idle`, `tun_ready_no_crypto`, `waiting_endpoint`, `policy_unsupported`, `encrypted_direct`, `encrypted_relay_ready`, and `failed`; DNS is reported separately as `inactive`, `not_implemented`, `configured`, or `failed`.

## Repository boundary

- `meshd` owns long-running coordination, profile state, protocol adapters, tunnel state, and local API contracts.
- `meshctl` is an unprivileged client of that API. It must not import a tunnel engine or read daemon state files.
- `meshnetd` is a minimal privileged Linux helper in this repository. It holds no control-plane or node private keys and validates every request from `meshd`.

The cross-platform boundary is defined in
[platform-contracts.md](platform-contracts.md). Linux is the reference
implementation, followed by Windows and then macOS. The v0.1 capability scope,
native support matrix, and measurable release gates are defined in
[release-v0.1.md](release-v0.1.md); cross-compilation alone is not treated as
platform support.

## Privileged TUN boundary

`meshnetd` listens on a separate Linux `SOCK_SEQPACKET` Unix socket. Packaged Linux services keep the operator API under `/run/meshd` and the root helper under `/run/meshnetd`; each directory is writable only by the process that owns its listener. Startup fixes exactly one allowed meshd UID, data and DNS interface names, one MTU, at most sixteen non-overlapping overlay pools, one DNS endpoint, and one `resolvectl` path. The versioned JSON protocol is capped at 32 KiB and exposes only `open_tun`, `set_tun_routes`, `open_dns`, `set_dns`, and `reset_dns`. TUN requests contain bounded address and route lists; DNS requests contain only the helper-fixed endpoint plus bounded search and route domains. Subnet/default TUN routes, duplicates, address overlap, commands, client-selected paths, device parameters, and keys are impossible in the schema or rejected. The helper checks kernel `SO_PEERCRED`, creates non-persistent `IFF_TUN|IFF_NO_PI` interfaces, assigns descriptor ownership to the configured UID, applies only validated host prefixes, raises each link, and passes descriptors with `SCM_RIGHTS`. Route replacement is available only after that helper generation opened the data interface and only while the requested self addresses exactly match its recorded state. It adds new routes before removing old ones and rolls completed changes back if a netlink operation fails.

The unprivileged data-plane engine opens the descriptor after receiving a validated signed self map. It proves the private key belongs to the signed self node, intersects each peer route with that peer's signed host addresses, requests exactly those self/peer host prefixes, verifies the helper response byte-for-byte, and configures the official userspace WireGuard engine. A peer without an endpoint is installed with its public key and allowed host routes but remains unreachable until a valid endpoint arrives. A node with no local inbound rule may still open the path because Headscale sends node-reduced inbound filters and the remote destination enforces outbound authorization. A peerless reduced map replaces WireGuard peers, relay peer authority, and host routes in place, so packet forwarding remains fail-closed while the TUN, UDP socket, and relay transport stay available. Compatible peer-route changes use the same path: filter authority changes first, relay authorization and WireGuard peers change next, then the helper applies the route delta. Live peer updates contain only `replace_peers` plus peer-scoped fields; private key and listen port are device-creation fields and are never resent, because setting a WireGuard listen port unconditionally rebinds the socket. Any ambiguous step closes the device. A signed self-address or relay-topology change still creates a freshly confined interface. Profile changes, permanent control failure, and process shutdown close the active descriptor.

The WireGuard engine owns one monotonic UDP socket-generation namespace across every bind it creates for encrypted packets, bounded STUN requests, and authenticated peer probes. Recreating a tunnel consumes a fresh generation instead of restarting the counter. A fixed control-datagram mux consumes both control protocols before WireGuard parsing; detaching a session leaves its probe classifier in drop-only mode until the socket closes. STUN responses are accepted only when transaction ID, signed relay source, socket generation, and active-profile generation all match. Literal relay IPs are selected deterministically across regions. Server-reflexive and safe host-interface candidates are merged with configured candidates, translated to protocol endpoint types only inside the compatibility adapter, and sent through non-streaming updates using the active stream's discovery key. While peers exist, discovery refreshes at a randomized 20–26 second interval and immediately after a meaningful host-network change. A peerless map performs one discovery for the current socket and then pauses periodic probes; a network change or the reappearance of a peer triggers a fresh round. Socket changes reset stale candidate authority internally but publish only the post-discovery replacement, so control never observes an artificial empty-presence interval. Linux receives route, link, and address notifications over one bounded netlink socket; a 750 ms debounce and canonical snapshot comparison discard duplicate event bursts. The product data and DNS interfaces are excluded so applying a network map cannot trigger a refresh loop. If native notifications fail, a five-second polling source preserves detection; non-Linux builds currently use that polling behavior until their native adapters are qualified. Changed endpoint sets are coalesced; transient publication failures retry with bounded backoff; the latest desired set is resent after a map reconnect. Recently observed non-host candidates survive a short probe flap within bounded per-address and global history, then a dedicated timer withdraws them at the exact deadline while peers are active. Authenticated direct-path selection runs bounded, paced candidate rounds on a randomized 2.8–3.2 second cadence, safely resets stale preferred paths across map revisions without reopening an equivalent tunnel, and applies proven endpoint changes incrementally. Traffic-idle path-probe pacing and subnet/exit route transactions remain separate milestones.

Each accepted STUN response also produces an RTT bound to its exact signed
server, transaction, profile scope, and socket generation. The client retains
at most 2,048 signed probe targets, probes at most eight concurrently, keeps one
target from the current home region in every round, and rotates the remaining
slots across the topology. A session-owned selector smooths RTT with a 75/25
moving average, expires stale samples after five minutes and ten seconds, and
switches a reachable home only when another observed region is at least 10 ms
and 20 percent faster. A partial round must miss the current home twice before
reachability failover. Recent authenticated relay activity preserves the current
home during partial STUN loss. A measured replacement is opened without routing
traffic through it and must complete authenticated setup before publication; it
is polled on a bounded five-second cadence while pending. A changed usable control preference remains
authoritative; absent one, the lowest usable signed region is the deterministic
cold-start fallback. Candidate and home-relay changes are published atomically
through the pinned map protocol and resent after reconnect. The packet engine
changes home only after the control plane echoes the preference in a validated
map, so local network observations cannot rewrite peer authority directly.

The peer-probe wire adapter implements the current encrypted Ping/Pong format
behind `internal/compat/disco`. The daemon creates one ephemeral X25519 identity
per active control session, advertises its canonical public key through every
map reconnect and endpoint update, then destroys its private material after all
session workers stop. The adapter owns precomputed NaCl channels, authenticated
sender verification, and bounded message parsing. A product bridge atomically
derives a bounded peer-channel registry from each validated map, requires the
map to echo the session's discovery key, binds every channel to the peer's node
and discovery keys, and destroys replaced or deactivated shared secrets. It authorizes outgoing
probe destinations against that peer's signed endpoint set and translates only
authenticated packets into product-owned messages. A session-scoped runtime is
now attached to the shared UDP mux after each successful data-plane apply. It
copies matching packets into a bounded non-blocking queue, authenticates them on
an owned worker, answers valid Ping messages, and completes valid Pong messages
without blocking the WireGuard receive loop. Map-triggered probes are selected
round-robin across peers, capped, coalesced, and paced. The product-owned probe
manager binds every outgoing transaction to a validated peer, active-session
scope, map revision, socket generation, exact remote endpoint, and five-second
deadline. It caps pending state globally and per peer, consumes authenticated
mismatches, rejects replay and late replies, and invalidates all state before a
map or socket transition. Authenticated observations feed a product-owned
bounded selector that retains one smoothed RTT and exact expiry per authorized
candidate, uses a 6.5-second
freshness gate, requires a material improvement before switching, and resolves
near-equivalent paths deterministically by private reachability, IPv6, then
canonical address. An exact repeated generation preserves evidence only when
its peer/candidate authority is identical; every map or socket generation
change clears it. One owned daemon worker applies only selector transitions to
the exact installed peer and map revision through bounded WireGuard UAPI
`update_only` requests. It does not recreate the TUN or replace routes. Proof
expiry restores the deterministic control-signed base endpoint; a new map
revision reapplies the full signed configuration before new proof is admitted.
Update ambiguity closes the packet engine and stops the session fail closed.

The relay subsystem compiles an independent immutable authority from each
validated map. It accepts only non-STUN relay nodes, binds every destination
key to one selected region and one signed overlay identity, and starts the home
connection without blocking WireGuard startup. A valid control preference wins;
otherwise the latency selector reports a stable preferred region and retains a
deterministic lowest-region fallback while measurements are unavailable.
WireGuard peer
endpoints begin on the relay. An authenticated direct proof can replace that
endpoint incrementally, and proof expiry restores the relay instead of an
unproven network address.

`internal/relay` owns bounded queues, connection lifecycle, retry policy, and
product types. `internal/compat/derp` alone owns the pinned wire codec. The
adapter opens raw TLS without environment proxies or redirects, verifies normal,
alternate-name, or exact control-signed certificate authority, requires the
protocol upgrade and authenticated server greeting, and carries unchanged
WireGuard ciphertext. Region dialing starts the first signed node immediately
and a second after 200 milliseconds, replaces failed attempts without delay,
and never runs more than two node sessions concurrently. Only a fully
authenticated session can win; cancellation closes and joins every started
loser before returning. Each signed node receives a four-second end-to-end
session attempt inside the ten-second region budget, so a node that stalls TLS,
upgrade, or greeting cannot serialize all failover work. The upgrade response
is limited to 32 KiB. After upgrade, a strict reader admits only version-pinned
server frame types and bounds their shape before the compatibility codec can
allocate from a remote length. Each client has at most sixteen active region workers,
32 queued batches per region, one MiB per-region and four MiB total queued send
data, plus a bounded receive queue. An authenticated inbound packet records a
connection-scoped reverse route so a responder can reply on the exact region
where the peer was observed; disconnect removes that authority. Worker generations
prevent stale cleanup from deleting newer reverse authority. The oldest idle
non-home worker can be evicted only when it has no queued/in-flight traffic or
reverse routes; replacement waits for complete worker exit, preserving the
goroutine bound. Authenticated liveness frames update payload-free health state,
and receive silence forces bounded reconnect. Closing a pool
cancels dials, closes active connections, unblocks receive, and joins every
worker. Rapid authenticate-and-disconnect churn preserves exponential backoff;
the retry sequence resets only after a connection remains established for
thirty seconds.

## DNS boundary

The compatibility adapter translates every non-nil DNS map into product-owned values and preserves nil-as-unchanged delta semantics inside a streaming session. Resolver order, locally authoritative empty routes, search domains, MagicDNS intent, and A/AAAA records are retained. Names are canonicalized to lowercase without a trailing dot and the entire candidate remains atomic with the rest of the network map. The initial resolver boundary accepts only classic IP resolvers on port 53. URL-based DoH/HTTP resolvers, bootstrap addresses, exit-node overrides, malformed names, duplicate routes/records, and unsafe resolver addresses fail closed.

The DNS compiler creates deterministic forward and reverse node records from the validated map, detects record shadowing, and requires every node name to be covered by a locally authoritative route. Extra records outside an existing route receive an exact local route. A transaction manager prepares the local resolver before enabling OS routing, restores host DNS before clearing the resolver, and rolls back the first component if the second fails.

On Linux, `meshd` lazily opens a dedicated DNS link through `meshnetd`, then binds an unprivileged UDP/TCP resolver to the fixed endpoint. It publishes A, AAAA, and PTR records with short positive TTLs; authoritative misses return NXDOMAIN or NODATA with a bounded SOA. Forwarding selects the most-specific suffix, randomizes the upstream transaction ID, validates the complete response question, retries truncated UDP responses over TCP, and bounds query concurrency, connection count, message size, and timeouts. EDNS0 is negotiated hop by hop: responses advertise a 4096-byte resolver limit, honor the requestor's smaller UDP limit, retain the OPT record on truncated and error responses, reject unsupported versions with BADVERS, and do not reflect unknown request options. Query names are not logged.

Only after both listeners are ready does `meshnetd` install per-link DNS servers, search domains, and route-only domains through the fixed root-owned `resolvectl` binary. The helper independently validates the endpoint and a bounded canonical domain set. `DefaultRoute` is enabled only for an explicit root route. Partial updates invoke `resolvectl revert`; profile changes, control failure, disabled DNS maps, and shutdown revert host state before the non-persistent link closes. A live status becomes `configured` only after both resolver and host configuration succeed.

The TUN policy gate validates IPv4 and IPv6 headers before packets cross the encryption boundary. Outbound packets must use one of the signed self addresses and target a signed direct peer address. Inbound packets must use the reverse address ownership and either match the node-specific protocol/port allow rules or be the exact reply tuple of a locally initiated TCP, UDP, or ICMP echo flow. The connection table is bounded, expires entries by protocol, keeps closing TCP flows short-lived, and is reset whenever self addresses, peer addresses, or policy change. Malformed packets, fragments, unresolved capability selectors, and unsupported narrow transport semantics fail closed.

## Flow telemetry boundary

After policy acceptance, the WireGuard TUN wrapper observes outbound plaintext immediately before encryption and inbound plaintext before delivery to the kernel. The observer synchronously extracts only IP version, protocol, source/destination IP, TCP/UDP ports, TCP flags, and IP packet length; it never retains the input slice or payload. Denied packets are neither forwarded nor reported as successful traffic.

Events enter a bounded non-blocking queue and are aggregated by network-map generation plus 5-tuple. TCP SYN/SYN-ACK/ACK/FIN/RST flags produce `syn`, `syn_ack`, `established`, `closing`, or `reset`; UDP is reported as `observed`. Each side reports source-to-destination and reverse packet/byte counters. Queue saturation drops telemetry and emits a count, never tunnel traffic.

The pinned control stream supplies an opaque Node token and Network token. The compatibility adapter requires the data-plane-audit capability and validates their embedded network/self scopes before publishing redacted product-owned credentials. `meshd` sends them only in HTTPS headers to the configured exact origin and refuses redirects. The log service validates the HMAC and stores normalized records; no storage credential exists on the client.

## Multiple-network invariant

MeshTransit allows address reuse across isolated networks. Therefore one process may store several profiles but only one profile can be active in version 1. Netmaps from different profiles must never be unioned. A future simultaneous-network mode requires separate interfaces, routing tables, policy namespaces, and an explicit architecture decision.

The client never sends a `network_id`. Registration and session credentials identify the account; the server selects and authorizes the network. Browser registration must reauthorize the final choice.

## Compatibility strategy

The reference implementation is an interoperability oracle, not a source tree for mechanical copying. Product orchestration, persistence, local API, CLI, logging, and privilege separation are authored here.

The protocol adapter pins `tailscale.com` to `v1.102.3`, matching the current control-plane dependency and capability 142. Imports are confined to the compatibility adapter. Bootstrap fetches `/key?v=142`, compares the SHA-256 fingerprint with a value obtained independently by the operator, creates per-profile machine and node keys, and verifies server possession through Noise IK. Registration then uses the pinned key over Noise and a bounded HTTP/2 session. TLS port 443 is mandatory, environment proxies and redirects are disabled, and the normal certificate chain and hostname are verified. The upstream dialer is not used because its compatibility behavior includes plaintext fallback and permissive certificate handling that conflict with this product's security policy. A separate forward-test lane may exercise newer versions without changing the production baseline. Required BSD attribution is recorded in `THIRD_PARTY_NOTICES.md`.

Compatibility must be proven independently at four layers:

1. HTTPS server-key discovery and TS2021/Noise session establishment. Implemented by `doctor control`, registration, and the long-lived map stream.
2. Registration, login completion, keepalive watchdog, and bounded reconnect are implemented. Session-handle resume remains; reconnect currently requires a new full snapshot.
3. Network-map decoding, structural policy validation, DNS translation/planning, Linux DNS activation, and host-level TCP/UDP/ICMP policy enforcement are implemented. Capability-based networking, subnet/exit policy, and URL resolver transports remain.
4. Privileged TUN/DNS lifecycle, direct userspace WireGuard traffic, shared-socket STUN discovery, periodic and host-network-triggered candidate refresh/expiry, typed endpoint and health-gated home-relay publication, bounded encrypted relay traffic with idle region eviction, and authenticated direct endpoint switching are implemented as opt-in Linux POCs. Traffic-idle discovery pacing, generalized routes, native non-Linux network monitors, and non-Linux DNS backends remain.

## Local API

The API is versioned under `/v1` and is served only on a Unix socket. On Linux, every connection is associated with kernel `SO_PEERCRED` credentials; root, the daemon UID, and explicitly configured operator UIDs are allowed. A packaged service may also authorize kernel-verified callers that the daemon-owned `0660` socket admitted through its dedicated operator group. Platforms without a verified credential implementation deny requests unless an unsafe development override is set. Current endpoints are:

- `GET /v1/health`
- `GET /v1/status`
- `GET /v1/profiles`
- `POST /v1/profiles`
- `POST /v1/profiles/{id}/activate`
- `POST /v1/control/trust`
- `POST /v1/login`
- `POST /v1/login/complete`
- `POST /v1/doctor/control`

Unknown JSON fields are rejected. A create request contains only a display name and HTTPS control URL; it has no network field.

Status exposes only non-secret diagnostics from the latest validated snapshot:
the server-provided Network name, this node's overlay prefixes, peer count,
packet-policy rule count, DNS lifecycle state, aggregate direct/relay/pending
peer-path counts, relay-region connection health, and process-local aggregate
counts of meaningful host-network events and completed endpoint refreshes. Relay timing is included
for lifecycle diagnosis, but peer identity, endpoint addresses, hostnames,
keys, and packet contents are omitted. These values never influence
registration or Network selection; they let operators verify the
server-authorized scope and transport transitions without reading daemon state
or private key material.

## Identity and registration lifecycle

Each profile has distinct machine and node private keys plus an independent control-key pin. Identity creation is create-only so two enrollment attempts cannot silently overwrite each other. Repeating the trust command verifies the saved key and fingerprint against the live server; it never rotates either value.

The registration request deliberately omits any network selector. An auth key is accepted only through the local request, held in memory for that call, and never persisted. Browser registration persists only a same-origin HTTPS follow-up URL, treats it as secret state, and clears it after authorization. A changed control key or expired node key fails closed; explicit key-rotation and node-renewal protocols remain future work.

## Network-map lifecycle

Only a registered active profile may open a map stream. Every connection repeats HTTPS key discovery and compares both the persisted raw key and fingerprint before Noise. The client asks for uncompressed capability-142 frames, limits each frame to 16 MiB, applies a two-minute read deadline, and reconnects transient failures with bounded jittered exponential backoff.

Protocol structs remain inside the compatibility adapter. Each non-keepalive response is converted into a MeshTransit-owned candidate snapshot. Full and delta peer changes, named packet-filter updates, online state, relay topology, DNS configuration, and control time are applied to a clone. The candidate must pass identity, key, address, route, endpoint, policy, relay, DNS, cardinality, self-authorization, self-expiry, and registered-self-key checks before it atomically replaces the latest in-memory snapshot.

Reconnect deliberately resets delta state and requires a new full self snapshot. `PingRequest` is not executed because accepting an arbitrary URL would create an SSRF boundary; an allowlisted implementation can be added later. Capability grants are not widened into network permissions. Linux DNS activation remains explicitly opt-in; session-handle resume is deferred.

## Dependency policy

Use the standard library by default. Every external module requires a purpose, license review, fixed version, vulnerability scan, and maintainer approval. Protocol-specific dependencies remain behind internal packages so the product API does not inherit their naming or lifecycle model. The pinned relay codec is used only inside `internal/compat/derp`; dialing, TLS policy, retries, memory bounds, authorization, and path selection remain product-owned.
