# meshd

`meshd` is the MeshTransit node daemon. It owns local profile and identity state, performs pinned encrypted control registration, maintains a validated control-map stream, and exposes a versioned local API. Opt-in Linux POCs run encrypted WireGuard over authenticated relay and direct paths, MagicDNS through `systemd-resolved`, and header-only flow telemetry on explicitly authorized peer routes.

## Demo

```console
$ meshd --socket /tmp/meshd.sock --state-dir /tmp/meshd-state
{"level":"INFO","msg":"meshd started","socket":"/tmp/meshd.sock","version":"dev"}
```

Without an explicit POC flag the daemon remains control-only and reports `data_plane: not_implemented`. The packet-path POC is deliberately narrower than a production client: it keeps a bounded TLS relay path as the initial encrypted route, discovers safe host-interface and server-reflexive peer endpoints, promotes only authenticated direct candidates, installs host routes, enforces node-specific protocol/port policy, and permits only bounded replies to flows initiated by the local node. The Linux DNS POC serves MagicDNS A, AAAA, and PTR records, authoritative negative answers, classic-IP split DNS, and global forwarding without replacing local DNS unless the control map explicitly requests a default route. Subnet/exit routing, encrypted DNS transports, fragmented packets, and unsupported narrow transport semantics remain fail closed.

On a disposable Linux host, the privileged boundary can be exercised explicitly:

```console
# meshnetd --allow-user meshd \
    --allow-prefix 100.64.0.0/10 \
    --allow-prefix fd7a:115c:a1e0::/48
$ meshd --enable-wireguard-poc \
    --wireguard-listen-port 41641
```

The daemon normally derives candidates from the shared WireGuard socket and
the control-signed STUN map. `--advertise-endpoint` remains an optional,
repeatable bootstrap or diagnostic input; it is not required for direct-path
startup.

`meshnetd` fixes the allowed UID, interface names, MTU, overlay pools, DNS endpoint, and `resolvectl` path at startup. The protocol contains only bounded TUN lifecycle and per-link DNS operations; it cannot carry commands, arbitrary paths, or keys. The helper rejects subnets, duplicates, self-route overlap, every prefix outside its root-configured pools, and non-canonical DNS domains. It returns descriptors through `SCM_RIGHTS` and never receives control or node private keys. `meshd` verifies TUN responses byte-for-byte, starts userspace WireGuard, and recreates or tears down non-persistent interfaces as signed state changes.

MagicDNS is separately opt-in and requires `systemd-resolved` plus a root-owned,
non-writable `/usr/bin/resolvectl`:

```console
# meshnetd --allow-user meshd \
    --allow-prefix 100.64.0.0/10 \
    --allow-prefix fd7a:115c:a1e0::/48 \
    --enable-dns-poc
$ meshd --enable-dns-poc
```

The helper creates a dedicated non-persistent DNS link at a fixed startup
address, while the unprivileged daemon owns the UDP/TCP resolver. Host DNS is
installed only after both listeners are ready. Disabling the map, changing
profiles, a permanent control failure, or process shutdown first reverts the
per-link `systemd-resolved` state and then closes the resolver link.

Flow logging is separately opt-in:

```console
$ meshd ... --enable-flow-logs \
    --flow-log-url https://log.pingoo.click \
    --flow-log-interval 5s
```

The observer reads only IPv4/IPv6 TCP or UDP headers at the plaintext TUN boundary, aggregates 5-tuples and counters in bounded memory, and never retains packet payloads. Upload credentials are issued by the pinned control plane, scoped to the current network and node, and sent only in HTTPS headers. Logging backpressure or upload failure cannot block packet forwarding.

## Getting started

Requirements: Go 1.26.8 or newer. Go's automatic toolchain selection can use the version declared in `go.mod`.

```bash
make test
make build
./bin/meshd --socket /tmp/meshd.sock --state-dir /tmp/meshd-state
```

Production defaults are `/run/meshd/meshd.sock` and `/var/lib/meshd`. Run the daemon under a dedicated service account and restrict membership of the socket's owning group. Linux authorizes UID `0`, the daemon UID, and values supplied through repeatable `--allow-uid UID` flags. A packaged service can enable `--allow-socket-peers` so kernel-verified callers admitted by the socket's `0660` owner/group permissions are also authorized.

Non-Linux development currently lacks a verified peer-credential implementation and therefore denies API requests by default. The explicit `--unsafe-allow-unverified-local-peer` flag is for isolated development only and must not be used in production.

## Features and specification

- Atomic, mode-restricted profile persistence.
- Exactly one active profile when profiles exist.
- HTTPS-only control URLs without embedded credentials, query strings, or fragments.
- No client-supplied `network_id`; network membership is resolved by the control plane.
- Versioned JSON API available only through a Unix-domain listener.
- Linux `SO_PEERCRED` authorization for root, the daemon UID, explicit operator UIDs, or verified callers admitted by an explicitly enabled socket-group boundary.
- Bounded HTTP headers, bodies, reads, writes, and graceful shutdown.
- HTTPS-only TS2021 capability-142 control-key and Noise-handshake probe with certificate verification, redirect refusal, and fingerprint-only output.
- Explicit operator fingerprint verification before creating a control-key pin.
- Per-profile machine and node identities in create-only, atomically replaced `0600` records beneath a `0700` directory.
- Pinned Noise HTTP/2 node registration through either a same-origin browser flow or a transient auth key.
- Persisted browser follow-up state, restart registration, and fail-closed handling for key change or required key rotation.
- Long-lived, pinned Noise/HTTP2 control-map stream with a two-minute watchdog and bounded jittered reconnect.
- Product-owned network-map model with atomic full/delta application, strict size/cardinality limits, identity binding, duplicate-address rejection, policy selector validation, and insecure-relay rejection.
- Product-owned DNS model for MagicDNS, classic IP resolvers, split routes, search domains, and A/AAAA records; deterministic plan compilation rejects name shadowing and unrouted node records.
- Linux MagicDNS server with A/AAAA/PTR answers, short-name search, authoritative NXDOMAIN/NODATA, RFC 6891 EDNS0 negotiation, classic UDP/TCP forwarding, truncated-UDP retry over TCP, bounded concurrency, and transactional `systemd-resolved` rollback.
- Status-only visibility into control synchronization, latest validated revision, aggregate peer path selection, and relay-region lifecycle health; raw policy, peer identities, endpoint addresses, hostnames, keys, and packet contents are not exposed locally.
- Linux-only `meshnetd` privilege boundary with `SO_PEERCRED`, bounded `SOCK_SEQPACKET` framing, root-configured overlay pools, host-route-only dynamic TUN configuration, and descriptor passing via `SCM_RIGHTS`.
- Explicit `--enable-tun-poc` lifecycle that closes the non-persistent TUN on default-deny, profile changes, control failure, and shutdown.
- Linux userspace WireGuard direct-path POC with signed-map key binding, automatically discovered endpoints, optional configured candidates, exact dynamic helper address/route verification, node-specific inbound protocol/port filtering, and bounded stateful replies for locally initiated TCP, UDP, and ICMP echo flows.
- Shared-socket STUN endpoint publication and authenticated peer probing with session/map/socket generation binding, bounded asynchronous receive work, paced signed-endpoint scheduling, and deterministic authenticated endpoint promotion, expiry, fallback, and roaming.
- Bounded TLS relay sessions selected only from the validated control map, carrying unchanged WireGuard ciphertext and serving as the base route until a direct endpoint is cryptographically proven.
- Opt-in native flow telemetry with redacted control-issued credentials, bounded non-blocking queues, TCP handshake state, explicit per-direction counters, HTTPS-only uploads, redirect refusal, and no packet payload retention.
- No copied compatibility-reference source.

See [docs/architecture.md](docs/architecture.md),
[docs/platform-contracts.md](docs/platform-contracts.md),
[docs/release-v0.1.md](docs/release-v0.1.md),
[docs/linux-packaging.md](docs/linux-packaging.md),
[docs/relay.md](docs/relay.md), [docs/dns.md](docs/dns.md), and
[docs/security-model.md](docs/security-model.md).

## Current scope

This repository can validate a server key, explicitly pin it, persist and register a per-profile identity, maintain the active profile's control stream, atomically publish a validated network map, activate Linux MagicDNS and split-DNS routing, create a Linux TUN through a separate privileged process, reconcile signed host routes inside fixed overlay pools, enforce host-level packet policy, maintain an encrypted relay base path, publish discovered endpoints, run authenticated direct-path probes, and roam encrypted traffic between relay, public, and private paths. `doctor control` remains a non-persisting diagnostic. It does not yet implement encrypted resolver transports, subnet/exit routes, fragment reassembly, or complete port semantics for transports other than TCP and UDP.

Private identity records currently rely on the daemon account and filesystem permissions for at-rest protection. Treat `/var/lib/meshd` and its backups as secrets. OS-backed sealing is still a production release gate.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributors

MeshTransit contributors.

## License

No project license has been selected yet. Do not publish or redistribute this repository until the maintainers add a `LICENSE` file. Existing dependency obligations are recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
