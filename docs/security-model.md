# meshd security model

## Assets

- Node, machine, and future control-session private keys
- Authenticated control-plane session
- Validated network map and packet-filter policy
- Host routes, DNS state, firewall state, and TUN ownership
- Traffic metadata such as peer identities, addresses, ports, counters, and timestamps

Packet payloads are not an observability asset and must not be collected.

## Trust boundaries

1. `meshctl` to `meshd` over a filesystem-protected Unix socket.
2. `meshd` to the remote control plane over TLS and TS2021/Noise.
3. `meshd` to the future privileged `meshnetd` helper over a separate authenticated local channel.
4. The tunnel engine to untrusted network packets and relay traffic.
5. The event pipeline to remote log storage.

## Required security invariants

- Control URLs use HTTPS; plaintext fallback is forbidden.
- The client does not accept or send a caller-selected network identifier.
- A new netmap is validated fully before it replaces the active policy.
- Missing, malformed, stale, or unauthorized policy fails closed.
- Profiles are isolated and only one is active in version 1.
- Private keys never appear in logs, API responses, crash messages, or traffic events.
- `meshnetd` cannot access control credentials and accepts only a small allowlisted request schema.
- Traffic events contain metadata and counters only, never payload bytes or authentication material.

## Implemented controls

- Profile state is stored in a `0700` directory and a `0600` regular file.
- Profile metadata and identity records are opened through separate `os.Root`
  directory handles; symlink traversal and path escape are rejected by the
  operating-system boundary as well as by explicit file-type checks.
- Writes use a same-directory temporary file, `fsync`, atomic rename, and directory `fsync`.
- Persisted JSON rejects unknown fields, trailing values, invalid invariants, and files above 1 MiB.
- The local HTTP server refuses non-Unix listeners and limits header size, body size, read time, write time, and idle time.
- Linux reads `SO_PEERCRED` on every accepted connection and authorizes only root, the daemon UID, explicitly configured operator UIDs, or—when `--allow-socket-peers` is set—a verified caller admitted by the daemon-owned socket's `0660` owner/group permissions. Unverified peers remain denied.
- The socket creator will not overwrite a regular file or a responding daemon socket.
- API errors do not expose state paths or internal persistence errors.
- Local transport status exposes only aggregate direct/relay/pending peer
  counts, process-local relay-bootstrap/direct-promotion/fallback counters,
  last and maximum relay-to-direct promotion duration, relay-region lifecycle
  health, and process-local network-change/endpoint-refresh counters. It omits
  peer identities, endpoint addresses, hostnames, keys, and packet contents,
  and never feeds status data back into path selection.
- Authenticated local status also exposes aggregate Go runtime memory,
  goroutine, and GC counters for soak qualification. It exposes no stack trace,
  allocation profile, label, command line, address, or per-peer metric and does
  not open a network listener.
- Control URLs reject credentials, query strings, and fragments.
- Control URLs and the TS2021 key probe permit TLS port 443 only.
- The control probe bypasses environment proxies, refuses redirects, uses TLS 1.2 or newer with standard certificate and hostname verification, limits the key response to 64 KiB, validates the typed machine key, completes Noise IK with an ephemeral machine key, and returns only a SHA-256 fingerprint.
- Identity files live under a separately opened `0700` directory, must be regular `0600` files, reject symlinks and malformed or oversized JSON, and use file plus directory `fsync` for durable updates.
- Identity contents are stored in versioned AES-256-GCM envelopes with a fresh
  random nonce and profile/version associated data. New and replaced records
  are re-opened, authenticated, decoded, and compared before atomic commit.
- Packaged Linux provisions a 256-bit key once with a fixed
  `/usr/bin/systemd-creds` invocation. Only the host-encrypted blob persists in
  `/etc/credstore.encrypted`; systemd exposes plaintext through the private
  `meshd.service` credential mount. The root one-shot has no capabilities or
  network access, and `meshnetd` receives no credential.
- Rotation compatibility accepts either that legacy key or one strictly
  versioned, bounded two-key credential. New ciphertext always uses the active
  key; the fallback key can only open existing records, which are verified and
  atomically rewrapped before use. Daemon startup performs that bounded rewrite
  across every canonical identity record before opening the local API.
  Duplicate, malformed, oversized, and unsupported key sets fail closed.
- Explicit Linux rotation makes a verified host-encrypted recovery copy durable
  before replacing the primary credential. Finalization proves every record is
  active-key-readable and retains that copy; a separate commit repeats the
  proof before deleting fallback material. Offline mutation commands refuse to
  run while systemd reports `meshd.service` active.
- First enrollment is create-only. A caller-supplied canonical SHA-256 fingerprint must match before identity keys are created, and later operations verify both the stored raw control key and fingerprint before opening Noise.
- Secret key wrappers redact their string and Go-string representations. Identity material is never returned by the local API.
- Registration runs through the pinned Noise connection and a bounded HTTP/2 client; it refuses redirects and never falls back to plaintext transport.
- Auth keys are transient and are not written to identity state. Browser follow-up URLs must be same-origin HTTPS registration paths and are cleared after authorization.
- The complete registration exchange, including response-body consumption, is
  capped at fifteen seconds. Browser completion has a three-second child
  deadline; both pending responses and temporary timeouts, truncated transport,
  HTTP 408/425/429, and HTTP 5xx consume that bounded window before the next
  retry. Caller cancellation takes precedence, while trust, malformed-response,
  rejection, and key-expiry failures remain terminal. After an authenticated
  response returns, persistence uses the caller context rather than the expired
  remote-poll context, preventing a deadline race from discarding verified
  pending or authorized state. Temporary registration key copies are cleared
  after the exchange.
- Registration transitions have one context-aware owner, preventing concurrent
  local callers from replaying the same pending browser follow-up or racing
  identity persistence.
- Explicit Node-key rotation is authenticated by the registered machine key and
  active old Node key and carries no login credential or scope selector. The
  replacement private key is atomically staged before the remote request,
  retained unchanged across temporary failures and restarts, and promoted only
  after an authoritative response. Startup resumes a pending transition before
  opening the map stream; temporary key copies are cleared after use.
- One daemon service can own only one control supervisor at a time. A duplicate
  runner is rejected before session keys, endpoint workers, or a map stream are
  created, and ownership remains held through fail-closed runtime cleanup.
- Each map-stream connection repeats control-key discovery and compares the persisted raw key and fingerprint before opening Noise; plaintext and proxy fallback remain disabled.
- Map frames are length-prefixed and limited to 16 MiB, response headers are bounded, and a two-minute read deadline terminates silent streams.
- Reconnect uses bounded jittered exponential backoff, resets that backoff only
  after thirty seconds of stable stream lifetime, and requires a new validated
  full snapshot before accepting deltas.
- An established stream recognizes authority withdrawal only when an
  authenticated frame repeats the active self ID and node key, marks the self
  expired and unauthorized, and explicitly replaces both peers and packet
  filters with empty sets. This terminal error bypasses reconnect delay and
  makes the daemon remove the active runtime. A terminal-shaped frame before a
  full map, with mismatched identity, or with ambiguous omitted replacements
  fails as an invalid map instead of mutating accumulated state. Ordinary
  transport and coordination-dependency failures do not synthesize revocation.
- A temporary local consumer failure cannot reuse partially applied state. The
  daemon cancels and joins the map session, detaches peer probes, destroys the
  session discovery identity, reverts DNS, and closes the data plane before an
  interruptible one-to-thirty-second retry. The retry requires a fresh pinned
  connection and full snapshot; trust, authorization, and malformed protocol
  failures remain terminal until an explicit state change. Failure to prove
  local cleanup terminates the supervisor so process teardown can release its
  remaining ownership; uncertain state is never reused by an in-process retry.
- Candidate snapshots are copied and validated before atomic publication. Validation bounds peers, addresses, routes, endpoints, rules, selectors, and relay topology; rejects duplicate direct addresses, unauthorized or expired self nodes, an unexpected self key, malformed typed keys, invalid ranges, and test-only insecure relays.
- Control-supplied `PingRequest` URLs are not fetched, avoiding an unbounded SSRF surface.
- DNS updates are copied into a bounded product-owned model before publication. The adapter canonicalizes names, preserves empty local routes, rejects duplicates and resolver URLs, and initially accepts only non-loopback classic IP resolvers on port 53.
- DNS plan compilation rejects node-name ambiguity, extra-record shadowing, unrouted search domains, and oversized address sets. The Linux transaction manager exposes host routing only after UDP/TCP listeners are ready and rolls resolver/host state back on partial failure.
- The local DNS resolver bounds message sizes, EDNS0 payload advertisement, forwarding concurrency, TCP connections, idle time, and query time. It randomizes upstream transaction IDs, validates the returned question, retries truncated UDP over TCP, sanitizes EDNS options, preserves OPT on truncated/error responses, rejects unsupported EDNS versions, and does not log query names.
- DNS privilege is limited to a helper-fixed endpoint and interface. The helper accepts only bounded canonical search/route domains, invokes one root-owned non-writable `resolvectl` path without a shell, disables LLMNR/mDNS on the dedicated link, and reverts partial or removed configurations.
- Linux `meshnetd` uses a separate `SOCK_SEQPACKET` socket, verifies the configured UID with `SO_PEERCRED`, bounds each message to 32 KiB, rejects unknown JSON fields and ancillary descriptors, and applies a five-second operation deadline.
- Packaged Linux services place the local API and helper sockets in different
  mode `0750` runtime directories. `meshd:meshtransit` owns `/run/meshd`, while
  `root:meshd` owns `/run/meshnetd`; neither caller group can replace the other
  listener.
- Packaged Linux declares both daemons as `Type=notify`, limits notification
  attribution to the main process, and bounds startup to 30 seconds. Each
  daemon validates and removes `NOTIFY_SOCKET`, binds its owned listener before
  reporting readiness, and fails startup if an expected readiness notification
  cannot be delivered. Relative, empty abstract, NUL-containing, and oversized
  notification addresses are rejected before any service socket is opened.
- The helper's startup configuration fixes data/DNS interface names, MTU, allowed service account or UID, non-overlapping overlay pools, DNS endpoint, and `resolvectl` path. An account name is resolved once at startup to the UID checked by `SO_PEERCRED`. Its five operations are `open_tun`, `set_tun_routes`, `open_dns`, `set_dns`, and `reset_dns`; requests cannot carry subnet/default TUN routes, commands, client-selected paths, keys, or kernel parameters. Live route replacement requires the exact self-address set recorded when that helper generation opened the fixed data interface, adds before removing, and rolls back completed netlink changes on failure.
- The helper validates requested prefixes independently of `meshd`, and `meshd` validates the returned address/route set byte-for-byte against the signed map before attaching the userspace packet engine.
- TUN descriptors are non-persistent and passed with `SCM_RIGHTS`. A validated peerless map replaces all WireGuard peers, relay peer authority, and host routes in place while retaining an empty encrypted transport for control presence. Relay topology or self-address changes close the superseded descriptor before replacement, and the active descriptor is closed on any ambiguous update, profile change, control failure, and shutdown. Control and node keys never cross the helper boundary.
- The userspace WireGuard engine binds the node private key to the signed self public key, accepts only authorized non-expired peers, signed host routes, and validated canonical endpoints, and zeroes temporary private-key configuration buffers. Private key and listen port are sent only while creating a device; compatible live peer replacement cannot carry either device-level field and therefore cannot implicitly rebind the shared UDP socket.
- Peers without an endpoint may open only the encrypted UDP engine and their signed host routes; they receive no guessed destination and remain fail-closed until control publishes a valid endpoint.
- STUN shares the exact WireGuard UDP socket. Requests use cryptographically random transaction IDs, bounded server fan-out, one retry, and a one-second round. Responses must match the signed relay source, active-profile scope, and socket generation; malformed and late packets are consumed without reaching WireGuard. Socket generations are allocated monotonically across every bind created by one WireGuard engine, preventing tunnel recreation from reusing stale discovery or path authority.
- Relay RTT is accepted only from those matched STUN transactions. The signed target inventory is capped at 2,048 entries, each round probes at most eight endpoints, the current home contributes up to one endpoint per available IP family, and the remaining slots rotate deterministically. This prevents a locally unavailable family from masking a measurable home region. Per-region samples are bounded to ten seconds, smoothed, and expired after five minutes and ten seconds; duplicate, unknown-server, non-positive, or time-regressed observations fail closed. Signed STUN-only regions may still contribute a direct candidate but are excluded from home-relay selection.
- Candidate collection rejects unspecified, multicast, loopback, link-local, zoned, and IPv4-mapped addresses, excludes overlay interface addresses, deduplicates deterministically, and publishes at most sixteen typed endpoints. A candidate never grants a route, policy permission, peer identity, or preferred-path proof.
- Dynamic endpoint updates use the active map stream's discovery public key and a separate pinned Noise exchange. The update channel, retry loop, latest desired set, and profile generation are cancelled together, preventing a stale refresh from updating a later profile session. Every retry and map reconnect revalidates the persisted control key pin. Session shutdown explicitly withdraws candidates; a socket-generation change resets old discovery authority internally and publishes only the replacement discovered on the current socket, avoiding a transient empty presence update.
- Host-network monitoring runs unprivileged. Linux reads only route/link/address notifications from one bounded netlink socket, drains event bursts, debounces them, and compares a canonical in-memory snapshot before signaling the daemon. Loopback plus the fixed MeshTransit data and DNS interfaces are excluded. Snapshot values and raw netlink messages are never logged or returned through the local API; only aggregate counters are exposed. Native-source or sampling failure degrades to bounded polling while the independent periodic discovery cycle remains available.
- Runtime-recovery status is process-local and aggregate: it reports only failure and successful-recovery counts plus a pending bit. It does not retain or expose the failing error, peer, address, route, DNS name, key, packet, or payload.
- The isolated peer-probe wire adapter generates ephemeral identities from `crypto/rand`, rejects zero, self, non-canonical, and low-order peer keys, derives precomputed NaCl channels, and destroys private/shared material on close. Packets are capped at 2 KiB; the authenticated sender key, current message version, transaction ID, node key, zero padding, and reported source endpoint are validated before publication to the product-owned path selector.
- Each control session owns exactly one peer-probe identity. Its canonical public key is reused across map reconnects and endpoint publications, while profile changes, terminal stream failure, cancellation, and daemon shutdown stop the session workers before destroying the private key.
- The peer-channel registry activates only when the current map revision matches the probe generation and the self node echoes the session's exact discovery public key. It caps derived channels at the data-plane peer limit, rejects duplicate node/discovery identities and unauthorized peers, authorizes outgoing destinations against each peer's signed endpoint set, rejects stale generations, and destroys replaced or deactivated shared secrets while retaining a rollback-prevention watermark. Incoming wrapper keys remain untrusted until channel authentication succeeds; authenticated pings must also carry the mapped node key.
- The shared UDP mux removes STUN and peer-probe packets before WireGuard parsing. Detachment retains a drop-only probe classifier until socket closure. Probe authentication and Pong sends run on one owned worker behind a non-blocking 128-packet queue, so malformed or excessive control traffic is dropped instead of blocking encrypted packet receipt. Authenticated Ping responses are limited to 128 globally and 16 per peer per second.
- Outgoing peer probes are capped at 512 pending transactions globally and eight per peer. Map-triggered and randomized 2.8–3.2 second health rounds select at most eight endpoints per peer and 512 total in round-robin order, skip peers known offline, coalesce replacement maps, and pace sends at ten milliseconds. Round cadence is measured start-to-start so even a maximally sized paced round refreshes proof before the 6.5-second trust deadline. Each 96-bit random token is bound to the active-session scope, validated map revision, UDP socket generation, peer identity, exact destination, and a five-second deadline. Failed sends cancel their transaction immediately; authenticated mismatches consume the token; successful, mismatched, expired, generation-invalidated, and explicitly deactivated transactions cannot be replayed.
- Authenticated path selection stores at most 256 peers and 128 control-authorized candidates per peer. A proof is accepted only for its exact active session/map/socket generation and signed peer endpoint, carries bounded RTT plus a validated observed-local endpoint, and expires after 6.5 seconds. RTT uses a bounded 75/25 moving average; a candidate must improve latency by the larger of ten percent and two milliseconds to displace a non-equivalent fresh path. Near-equivalent paths converge deterministically toward private, then IPv6, then canonical address order. A newer map revision may rebind the remaining unexpired lease only when the active session scope, UDP socket, and complete peer node-key, discovery-key, and candidate authority are identical; rebinding never extends the deadline. Time regression, same-generation authority mutation, socket change, stale generation activation, and exact-deadline reuse fail closed.
- Selected endpoints are applied only to an existing peer with the exact installed map revision and only when the endpoint is in that peer's signed candidate set. WireGuard receives a peer-scoped `update_only` request containing no private key, routes, or interface changes. Each fresh proof for the current selection reasserts that endpoint, reconciling authenticated relay-driven WireGuard roaming without accepting relay traffic as direct-path authority. Non-selected proof refreshes produce no device write, and the probe scheduler plus queue bounds cap reassertion work. A proof-expiry timer restores the latest deterministic signed base endpoint. An equivalent new revision preserves the selected endpoint without a device write only while the selector transfers that bounded lease. A signed peer home-relay change may update only the retained fallback metadata while device identity, peer key and routes, discovery identity, candidate authority, session scope, UDP socket, and relay topology remain compatible; expiry restores that newest fallback. Any incompatible authority or transport change restores or recreates the signed base configuration before new proof is admitted. Any ambiguous device update closes the engine and cancels the session rather than continuing with unknown state.
- A validated peer discovery-identity change recreates only that peer inside the
  encrypted packet engine, clearing transport-session state retained across a
  remote daemon restart while preserving the TUN, shared socket, routes, and
  unrelated peers. The reset carries only the existing signed node key, base
  endpoint, and host routes; failure closes the engine instead of retaining a
  partially removed peer. The first authenticated direct-path proof after that
  change repeats the peer-scoped reset on its exact authorized endpoint, once,
  so handshake recovery is gated by proof that the replacement remote packet
  engine is reachable.
- Relay authority is derived only from the validated map and defensively copied. STUN-only nodes cannot become packet relays; peers are bound to an authorized region, node key, and overlay rate-limit identity; malformed, duplicate, zero, or oversized authority is rejected before opening a connection. A peerless authority is valid and keeps the bounded home transport ready without authorizing any destination. Compatible peer-set changes atomically replace the live authorization map; queued sends and received packets are rechecked, and reverse routes for removed peers are deleted. A different region becomes a temporary reverse route only after an authenticated packet from that peer is observed on its active connection, and disconnect removes that authority.
- Relay transport is TLS-only, bypasses environment proxies, refuses redirects and non-upgrade responses, and requires the authenticated protocol greeting. Normal certificate verification remains enabled unless the signed map explicitly supplies an alternate certificate name or exact SHA-256 certificate pin; those paths perform complete hostname, chain or pin, and validity checks. Region dialing starts signed nodes in order with a 200-millisecond stagger, caps concurrent TLS-through-confirmation attempts at two, and accepts only the first fully authenticated session. Each node has a four-second deadline; cancellation closes and joins all started losers, and the pre-authentication upgrade response cannot exceed 32 KiB.
- Relay servers address peers by public node key but receive only unchanged WireGuard ciphertext. They do not receive node private keys or plaintext TUN packets. Unknown source keys, malformed frames, oversized packets, and full receive queues are dropped before WireGuard processing.
- Relay sends are bounded by packet size, per-region batch depth and byte budget, global byte budget, active-region count, write deadline, connect deadline, authenticated receive-silence deadline, and jittered retry cap. A pre-codec frame guard rejects unknown, out-of-phase, truncated-shape, and oversized server frames before remote lengths allocate memory. Rapid authenticated connection churn advances rather than resets exponential retry; a connection must survive thirty seconds before the sequence resets. At capacity, only the oldest idle non-home worker without queued/in-flight traffic or reverse authority may be evicted; its complete exit precedes replacement. Closing the packet engine cancels dials, closes active sockets, unblocks reads, and joins every relay worker.
- A usable changed control-supplied home region is authoritative. If absent or unusable, the client begins with the lowest usable region from the same signed map and may report a materially faster measured region; a peer without a usable preference uses the deterministic fallback rendezvous region. Authenticated direct-path proof may replace the relay endpoint, while expiry or deactivation returns to relay without trusting an unproven address.
- The client publishes a measured home relay only with its complete endpoint state. Reachable-region changes require both a 10 ms and 20 percent improvement; a partial probe round must miss the current home twice before failover. Recent authenticated relay activity suppresses false failover during STUN loss, and a replacement region must complete authenticated connection setup before publication. Unknown state is omitted rather than encoded as region zero, while an explicit zero is reserved for a managed withdrawal. Reconnect resends the latest complete state, and the data plane waits for a validated control-plane echo before changing relay authority.
- The TUN gate checks address ownership in both directions, applies node-reduced inbound protocol/port rules, and permits return traffic only through a bounded expiring table of locally initiated TCP, UDP, and ICMP echo tuples. Security-relevant map changes clear that table; malformed and fragmented packets fail closed.
- Flow logging is opt-in and receives only ephemeral TUN packet slices. It parses only bounded IP/TCP/UDP headers, retains scalar 5-tuple/state/counter fields, and never copies payload bytes.
- Flow metadata and control-issued audit credentials are tied to one immutable network-map generation. Credential formatting is redacted; Node and Network scopes are checked before use, tokens travel in HTTPS headers, and redirects are refused.
- Flow event and upload queues are bounded and non-blocking on the packet path. Saturation or remote failure drops telemetry rather than packets; request bodies and response reads are bounded by the client/server contract.

## Known gaps before production

- macOS peer credentials and Windows named-pipe authorization are not implemented. Both remain fail closed, and daemon binaries contain no unverified-peer override.
- Linux identity records are host-key encrypted, but TPM binding, key rotation,
  recovery credentials, and encrypted backup handling are not implemented. A
  root attacker that can obtain the systemd host key remains able to decrypt
  the identity credential. State and credential backups must be handled as
  secrets.
- Authenticated control-key rotation and cross-restart replay/rollback protection are not implemented.
- Session-handle resume is not implemented; reconnect requests a complete new snapshot. Linux has an opt-in `systemd-resolved` backend, while macOS, Windows, Android, iOS, and non-resolved Linux DNS backends are not implemented.
- Capability grants are retained outside network permissions and are not implemented for general application authorization. Host-level TCP/UDP ports and ICMP are enforced; capability selectors, subnet/exit forwarding policy, fragment reassembly, and narrow port semantics for other transports remain fail closed.
- The initial fingerprint must be obtained through an independent trusted channel. A fingerprint printed by `doctor control` on the same potentially compromised path provides only trust on first use.
- Expired node keys and changed control keys fail closed. Explicit
  continuity-preserving Node-key rotation is implemented; automatic
  expiry-triggered renewal and authenticated control-key rotation are not.
- Privilege separation, pool-confined host-route transactions, Linux DNS activation, packet encryption, bounded relay transport, endpoint discovery/publication, health-gated home-relay reporting, live authenticated probe transport, and authenticated direct-path switching are implemented but remain release-ineligible until the native candidate gates pass. Traffic-aware probe suppression, IPv6-only underlay certification, subnet/exit route transactions, firewall enforcement, and rollback after abrupt kernel or process termination remain production gaps.
- A packet-parser fuzz target, bounded malformed/fragment tests, deterministic adversarial relay tests, and one bounded live two-node policy matrix are present. Extended fuzz campaigns, long-duration relay saturation tests, repeated policy matrices from immutable candidate artifacts, and cross-platform policy qualification remain release gates.
- Flow delivery has scoped HMAC authentication and bounded memory, but durable client WAL, credential rotation, application-level encryption, retention/deletion policy, per-tenant query authorization, and tamper-evident storage are not implemented.
- Windows named-pipe and macOS local-credential transports are not implemented.

## Release gates

Before a Linux compatibility release:

1. Run the Linux peer-credential test on every supported Linux architecture and verify service-manager ownership and group configuration.
2. Keep control credentials in the unprivileged daemon; give the helper no key access.
3. Pin and verify the compatibility dependency and publish required notices.
4. Run `go test -race`, `go vet`, `golangci-lint`, `govulncheck`, fuzz targets, and cross-builds.
   CI must also scan the complete Git history and checked-out filesystem with
   the pinned Gitleaks version; findings fail the build without a baseline.
   Each Linux package must carry a digest-bound CycloneDX SBOM produced from
   its extracted filesystem. A pinned, checksum-verified, symbol-aware Grype
   scan fails on High or Critical findings, while retaining the full report.
5. Test auth-key registration, browser registration plus restart completion, reconnect, direct traffic, relay traffic, exit behavior, route cleanup, DNS rollback, and malicious netmaps against disposable hosts.
6. Confirm traffic logs have no payloads, secrets, or cross-network identifiers outside server-authorized scope.

## Peer authority deadlines at the packet gate

A control transport interruption or delayed sharing withdrawal must not extend
mapped packet authority. The TUN gate checks the self and exact peer exclusive
KeyExpiry on every inbound and outbound packet, before consulting return-flow
state or ACL rules. An explicit Expired flag denies immediately. A legacy zero
deadline keeps its existing meaning; Core direct shares always publish a finite
peer deadline capped by the complete sharing authority lifetime.

Address membership alone cannot transfer a tracked flow to a replaced Device or
Node key. Identity, key, expiry or policy replacement clears tracked flows;
endpoint-only updates retain them. This change adds no timer, worker, API field,
Network selector or log data. It prevents stale access while the stream is silent;
route and peer inventory cleanup still follows authoritative map withdrawal.

## Device alias authority

A versioned peer binding is required alongside alias addresses. Exact self/peer
Node keys, contract/endpoint versions, direction, service grants and finite
exclusive deadlines are validated before publication. Unknown or ambiguous
JSON, invalid family/address ownership and regressed authority reject the
candidate. Legacy address fields alone create no access.

WireGuard checks source ownership before the TUN gate verifies the exact local
alias destination. The gate rejects raw destinations, spoofed canonical sources,
reverse initiation and expired grants before flow state or wildcard rules can
widen access. Checksum-invalid or unsupported alias packets are denied without
mutation. Admission pauses during key/route replacement; apply failure removes
packet authority. Bounds cover peers, grants, decoder depth and reply state.

This implementation is not yet advertised or deployed as sharing support.
Durable alias ownership/quarantine, Core bilateral authority and wakeups, real
encrypted overlap/isolation matrices, imported DNS and scoped alias telemetry
remain gates. See [device-alias.md](device-alias.md).
