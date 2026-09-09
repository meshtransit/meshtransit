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
- Linux reads `SO_PEERCRED` on every accepted connection and authorizes only root, the daemon UID, or explicitly configured operator UIDs.
- The socket creator will not overwrite a regular file or a responding daemon socket.
- API errors do not expose state paths or internal persistence errors.
- Control URLs reject credentials, query strings, and fragments.
- Control URLs and the TS2021 key probe permit TLS port 443 only.
- The control probe bypasses environment proxies, refuses redirects, uses TLS 1.2 or newer with standard certificate and hostname verification, limits the key response to 64 KiB, validates the typed machine key, completes Noise IK with an ephemeral machine key, and returns only a SHA-256 fingerprint.
- Identity files live under a separately opened `0700` directory, must be regular `0600` files, reject symlinks and malformed or oversized JSON, and use file plus directory `fsync` for durable updates.
- First enrollment is create-only. A caller-supplied canonical SHA-256 fingerprint must match before identity keys are created, and later operations verify both the stored raw control key and fingerprint before opening Noise.
- Secret key wrappers redact their string and Go-string representations. Identity material is never returned by the local API.
- Registration runs through the pinned Noise connection and a bounded HTTP/2 client; it refuses redirects and never falls back to plaintext transport.
- Auth keys are transient and are not written to identity state. Browser follow-up URLs must be same-origin HTTPS registration paths and are cleared after authorization.
- Each map-stream connection repeats control-key discovery and compares the persisted raw key and fingerprint before opening Noise; plaintext and proxy fallback remain disabled.
- Map frames are length-prefixed and limited to 16 MiB, response headers are bounded, and a two-minute read deadline terminates silent streams.
- Reconnect uses bounded jittered exponential backoff and requires a new validated full snapshot before accepting deltas.
- Candidate snapshots are copied and validated before atomic publication. Validation bounds peers, addresses, routes, endpoints, rules, selectors, and relay topology; rejects duplicate direct addresses, unauthorized or expired self nodes, an unexpected self key, malformed typed keys, invalid ranges, and test-only insecure relays.
- Control-supplied `PingRequest` URLs are not fetched, avoiding an unbounded SSRF surface.
- DNS updates are copied into a bounded product-owned model before publication. The adapter canonicalizes names, preserves empty local routes, rejects duplicates and resolver URLs, and initially accepts only non-loopback classic IP resolvers on port 53.
- DNS plan compilation rejects node-name ambiguity, extra-record shadowing, unrouted search domains, and oversized address sets. The Linux transaction manager exposes host routing only after UDP/TCP listeners are ready and rolls resolver/host state back on partial failure.
- The local DNS resolver bounds message sizes, forwarding concurrency, TCP connections, idle time, and query time. It randomizes upstream transaction IDs, validates the returned question, retries truncated UDP over TCP, and does not log query names.
- DNS privilege is limited to a helper-fixed endpoint and interface. The helper accepts only bounded canonical search/route domains, invokes one root-owned non-writable `resolvectl` path without a shell, disables LLMNR/mDNS on the dedicated link, and reverts partial or removed configurations.
- Linux `meshnetd` uses a separate `SOCK_SEQPACKET` socket, verifies the configured UID with `SO_PEERCRED`, bounds each message to 32 KiB, rejects unknown JSON fields and ancillary descriptors, and applies a five-second operation deadline.
- The helper's startup configuration fixes data/DNS interface names, MTU, allowed UID, non-overlapping overlay pools, DNS endpoint, and `resolvectl` path. Its four operations are `open_tun`, `open_dns`, `set_dns`, and `reset_dns`; requests cannot carry subnet/default TUN routes, commands, client-selected paths, keys, or kernel parameters.
- The helper validates requested prefixes independently of `meshd`, and `meshd` validates the returned address/route set byte-for-byte against the signed map before attaching the userspace packet engine.
- TUN descriptors are non-persistent and passed with `SCM_RIGHTS`; `meshd` closes them when no authorized peer path remains, on profile change, on control failure, and at shutdown. Control and node keys never cross the helper boundary.
- The userspace WireGuard engine binds the node private key to the signed self public key, accepts only authorized non-expired peers, signed host routes, and validated canonical endpoints, and zeroes temporary private-key configuration buffers.
- Peers without an endpoint may open only the encrypted UDP engine and their signed host routes; they receive no guessed destination and remain fail-closed until control publishes a valid endpoint.
- STUN shares the exact WireGuard UDP socket. Requests use cryptographically random transaction IDs, bounded server fan-out, one retry, and a one-second round. Responses must match the signed relay source, active-profile scope, and socket generation; malformed and late packets are consumed without reaching WireGuard.
- Candidate collection rejects unspecified, multicast, loopback, link-local, zoned, and IPv4-mapped addresses, excludes overlay interface addresses, deduplicates deterministically, and publishes at most sixteen typed endpoints. A candidate never grants a route, policy permission, peer identity, or preferred-path proof.
- Dynamic endpoint updates use the active map stream's discovery public key and a separate pinned Noise exchange. The update channel, retry loop, latest desired set, and profile generation are cancelled together, preventing a stale refresh from updating a later profile session. Every retry and map reconnect revalidates the persisted control key pin; session start and socket-generation changes explicitly withdraw stale candidates.
- The TUN gate checks address ownership in both directions, applies node-reduced inbound protocol/port rules, and permits return traffic only through a bounded expiring table of locally initiated TCP, UDP, and ICMP echo tuples. Security-relevant map changes clear that table; malformed and fragmented packets fail closed.
- Flow logging is opt-in and receives only ephemeral TUN packet slices. It parses only bounded IP/TCP/UDP headers, retains scalar 5-tuple/state/counter fields, and never copies payload bytes.
- Flow metadata and control-issued audit credentials are tied to one immutable network-map generation. Credential formatting is redacted; Node and Network scopes are checked before use, tokens travel in HTTPS headers, and redirects are refused.
- Flow event and upload queues are bounded and non-blocking on the packet path. Saturation or remote failure drops telemetry rather than packets; request bodies and response reads are bounded by the client/server contract.

## Known gaps before production

- macOS peer credentials and Windows named-pipe authorization are not implemented. Both remain fail closed unless an explicit unsafe development override is enabled; that override is forbidden in production.
- Private keys are filesystem-protected but operating-system keyring, TPM-backed sealing, and encrypted backups are not implemented. State backups must be handled as secrets.
- Authenticated control-key rotation and cross-restart replay/rollback protection are not implemented.
- Session-handle resume is not implemented; reconnect requests a complete new snapshot. Linux has an opt-in `systemd-resolved` backend, while macOS, Windows, Android, iOS, and non-resolved Linux DNS backends are not implemented.
- Capability grants are retained outside network permissions and are not implemented for general application authorization. Host-level TCP/UDP ports and ICMP are enforced; capability selectors, subnet/exit forwarding policy, fragment reassembly, and narrow port semantics for other transports remain fail closed.
- The initial fingerprint must be obtained through an independent trusted channel. A fingerprint printed by `doctor control` on the same potentially compromised path provides only trust on first use.
- Expired node keys and changed control keys fail closed. A continuity-preserving rotation and renewal protocol is not implemented.
- Privilege separation, pool-confined host-route transactions, Linux DNS activation, direct packet encryption, and endpoint discovery/publication are POC-only. Authenticated path probing/roaming, traffic-idle discovery pacing, subnet/exit route transactions, relay transport, firewall enforcement, and rollback after abrupt kernel or process termination remain production gaps.
- A packet-parser fuzz target and bounded malformed/fragment tests are present. Extended fuzz campaigns, relay adversarial tests, and full end-to-end policy matrices remain release gates.
- Flow delivery has scoped HMAC authentication and bounded memory, but durable client WAL, credential rotation, application-level encryption, retention/deletion policy, per-tenant query authorization, and tamper-evident storage are not implemented.
- Windows named-pipe and macOS local-credential transports are not implemented.

## Release gates

Before a Linux compatibility release:

1. Run the Linux peer-credential test on every supported Linux architecture and verify service-manager ownership and group configuration.
2. Keep control credentials in the unprivileged daemon; give the helper no key access.
3. Pin and verify the compatibility dependency and publish required notices.
4. Run `go test -race`, `go vet`, `golangci-lint`, `govulncheck`, fuzz targets, and cross-builds.
5. Test auth-key registration, browser registration plus restart completion, reconnect, direct traffic, relay traffic, exit behavior, route cleanup, DNS rollback, and malicious netmaps against disposable hosts.
6. Confirm traffic logs have no payloads, secrets, or cross-network identifiers outside server-authorized scope.
