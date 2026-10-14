# meshd

`meshd` is the MeshTransit node daemon. It owns local profile and identity state, performs pinned encrypted control registration, maintains a validated control-map stream, and exposes a versioned local API. The Linux implementation runs encrypted WireGuard over authenticated relay and direct paths, MeshTransit DNS through `systemd-resolved`, and header-only flow telemetry on explicitly authorized peer routes.

## Demo

```console
$ umask 077
$ head -c 32 /dev/urandom > /tmp/meshd.identity-key
$ meshd --socket /tmp/meshd.sock --state-dir /tmp/meshd-state \
    --identity-key-file /tmp/meshd.identity-key
{"level":"INFO","msg":"meshd started","socket":"/tmp/meshd.sock","version":"dev"}
```

Without `--enable-data-plane` the daemon remains control-only and reports `data_plane: not_implemented`. The current packet path is deliberately narrower than the complete v0.1 scope: it keeps a bounded TLS relay path as the initial encrypted route, discovers safe host-interface and server-reflexive peer endpoints, promotes only authenticated direct candidates, installs host routes, enforces node-specific protocol/port policy, and permits only bounded replies to flows initiated by the local node. Linux DNS serves MeshTransit DNS A, AAAA, and PTR records, authoritative negative answers, classic-IP split DNS, and global forwarding without replacing local DNS unless the control map explicitly requests a default route. Subnet/exit routing, encrypted DNS transports, fragmented packets, and unsupported narrow transport semantics remain fail closed.

On a disposable Linux host, the privileged boundary can be exercised explicitly:

```console
# meshnetd --allow-user meshd
$ meshd --enable-data-plane \
    --wireguard-listen-port 41641
```

Without `--allow-prefix` the helper admits the fixed overlay frame:
`100.64.0.0/10`, the shared-Device alias range `198.18.0.0/15` and `fd00::/8`,
where each Workspace draws its random IPv6 `/48`. Control picks the exact
prefixes inside that frame, so a new Workspace or alias pool needs no local
change. `--allow-prefix` can only narrow the frame; a prefix outside it is
refused at startup.

The daemon normally derives candidates from the shared WireGuard socket and
the control-signed STUN map. `--advertise-endpoint` remains an optional,
repeatable bootstrap or diagnostic input; it is not required for direct-path
startup.

`meshnetd` fixes the allowed UID, interface names, MTU, overlay pools, DNS endpoint, and `resolvectl` path at startup. The protocol contains only bounded TUN lifecycle, host-route replacement, and per-link DNS operations; it cannot carry commands, arbitrary paths, or keys. The helper rejects subnets, duplicates, self-route overlap, every prefix outside its overlay pools (the fixed frame or a root-configured narrower list), and non-canonical DNS domains. It returns descriptors through `SCM_RIGHTS` and never receives control or node private keys. `meshd` verifies TUN responses byte-for-byte, starts userspace WireGuard, and replaces peer routes on the live helper-owned interface when self identity and relay topology remain compatible. Address or relay-topology changes still recreate the non-persistent interface fail closed.

MeshTransit DNS is separately opt-in and requires `systemd-resolved` plus a root-owned,
non-writable `/usr/bin/resolvectl`:

```console
# meshnetd --allow-user meshd --enable-dns
$ meshd --enable-dns
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
umask 077
head -c 32 /dev/urandom > /tmp/meshd.identity-key
./bin/meshd --socket /tmp/meshd.sock --state-dir /tmp/meshd-state \
  --identity-key-file /tmp/meshd.identity-key
```

Against a live control server, the local `POST /v1/doctor/control` operation
fetches the MTCP key document and completes an MTCP handshake and ping
without registering a node. It verifies certificates, refuses redirects and
prints only the control key fingerprint. End-to-end registration, maps and
relaying run in the in-process network lab (`make natlab-matrix`).

Production defaults are `/run/meshd/meshd.sock` and `/var/lib/meshd`. Run the daemon under a dedicated service account and restrict membership of the socket's owning group. Linux authorizes UID `0`, the daemon UID, and values supplied through repeatable `--allow-uid UID` flags. A packaged service can enable `--allow-socket-peers` so kernel-verified callers admitted by the socket's `0660` owner/group permissions are also authorized. The Debian package provisions a host-encrypted systemd credential and exposes its decrypted 32-byte key only inside `meshd.service`; unpackaged development must provide an owner-only key with `--identity-key-file`.

Non-Linux development currently lacks a verified peer-credential implementation and therefore denies API requests. No unverified-peer bypass is compiled into daemon binaries; each platform must implement native kernel-backed peer identity before it can expose the local API.

## Features and specification

- Atomic, mode-restricted profile persistence.
- Exactly one active profile when profiles exist.
- HTTPS-only control URLs without embedded credentials, query strings, or fragments.
- No client-supplied `network_id`; network membership is resolved by the control plane.
- Versioned JSON API available only through a Unix-domain listener.
- Linux `SO_PEERCRED` authorization for root, the daemon UID, explicit operator UIDs, or verified callers admitted by an explicitly enabled socket-group boundary.
- Bounded HTTP headers, bodies, reads, writes, and graceful shutdown.
- HTTPS-only MTCP v1 control-key and handshake probe with certificate verification, redirect refusal, and fingerprint-only output.
- Explicit operator fingerprint verification before creating a control-key pin.
- Per-profile machine and node identities in create-only, atomically replaced
  AES-256-GCM envelopes beneath a `0700` directory, bound to the profile and
  verified before commit. The Linux package supplies their key through a
  host-encrypted systemd credential that is unavailable to `meshnetd`.
- Pinned, bounded MTCP v1 node registration through either
  a same-origin browser flow or a transient auth key.
- Persisted browser follow-up state, serialized and cancellable registration
  completion, throttled pending polls and temporary transport/server recovery,
  durable handling of verified responses at the poll-deadline boundary,
  and restart registration.
- Authenticated Node-key rotation that stages the replacement key durably before
  the remote request, retries the exact old/new key pair after interruption, and
  promotes it locally only after an authoritative control response.
- Long-lived, pinned MTCP v1 control-map stream with a keepalive watchdog
  and jittered exponential reconnect that resets only after a stable session.
- Single-owner control supervision that rejects duplicate runners before they
  can open a second map session.
- Fail-closed recovery from temporary local map-application failures: active
  TUN, route, DNS, probe, and session state is removed before a fresh full-map
  retry with bounded jittered backoff. Profile and registration changes
  interrupt that wait; trust and protocol failures require explicit repair.
- Product-owned network-map model with atomic full/delta application, strict size/cardinality limits, identity binding, duplicate-address rejection, policy selector validation, and insecure-relay rejection.
- Product-owned DNS model for MeshTransit DNS, classic IP resolvers, split routes, search domains, and A/AAAA records; deterministic plan compilation rejects name shadowing and unrouted node records.
- Linux MeshTransit DNS server with A/AAAA/PTR answers, short-name search, authoritative NXDOMAIN/NODATA, RFC 6891 EDNS0 negotiation, classic UDP/TCP forwarding, truncated-UDP retry over TCP, bounded concurrency, and transactional `systemd-resolved` rollback.
- Status-only visibility into control synchronization, latest validated revision, aggregate peer path selection, relay-region lifecycle health, and process-local network-change, endpoint-refresh, runtime-recovery, and path-probe lifecycle counters. Path-probe diagnostics distinguish map carry/retirement, pending invalidation, round completion, send failure, authenticated reply rejection, selector acceptance, queue loss, and direct-proof expiry without exposing raw policy, peer identities, endpoint addresses, hostnames, keys, or packet contents.
- Linux-only `meshnetd` privilege boundary with `SO_PEERCRED`, bounded `SOCK_SEQPACKET` framing, root-configured overlay pools, host-route-only dynamic TUN configuration, and descriptor passing via `SCM_RIGHTS`.
- Explicit `--enable-data-plane` lifecycle that closes the non-persistent TUN on default-deny, profile changes, control failure, and shutdown.
- Linux userspace WireGuard packet path with signed-map key binding, automatically discovered endpoints, optional configured candidates, exact dynamic helper address/route verification, node-specific inbound protocol/port filtering, and bounded stateful replies for locally initiated TCP, UDP, and ICMP echo flows.
- Shared-socket STUN endpoint publication and authenticated peer probing with session/map/socket generation binding, bounded asynchronous receive work, paced signed-endpoint scheduling, and deterministic authenticated endpoint promotion, expiry, fallback, and roaming.
- Linux route/link/address monitoring with snapshot filtering, event coalescing, immediate endpoint refresh, and a polling fallback; MeshTransit-owned data and DNS interfaces are excluded to prevent self-triggered refresh loops.
- Bounded TLS relay sessions selected only from the validated control map, carrying unchanged WireGuard ciphertext and serving as the base route until a direct endpoint is cryptographically proven.
- Reversible Linux qualification for direct-path loss, encrypted relay fallback,
  dual-stack traffic over relay, and later authenticated direct-path recovery.
- Bounded, repeatable Linux crash qualification for direct daemon cleanup,
  systemd automatic restart, coordinated helper/daemon generation replacement,
  resource invariants, MeshTransit DNS recovery, and stable dual-stack traffic.
- A chained Linux helper-crash/network-change gate that proves the recovered
  helper/daemon generation can immediately refresh endpoints without another
  service restart.
- A bounded Linux local-runtime fault gate that temporarily removes helper
  socket access, proves the daemon exposes a pending failure, and requires the
  same process generation to rebuild TUN and DNS after access is restored.
- A fail-fast repeated local-runtime gate that checks resource, state, route,
  resolver, socket-permission, and restart-count invariants after every sample
  and emits redacted nearest-rank p95 recovery timings.
- A traffic-bearing local-runtime gate that requires observed IPv4, IPv6, and
  uncached MeshTransit DNS outages followed by stable recovery while retaining the
  complete per-sample runtime and resource contract.
- A restart-intolerant, read-only fixed-topology Linux soak gate for service generations,
  resource cardinality, runtime/OS memory, goroutines, threads, descriptors,
  routes, resolver policy, MeshTransit DNS, and sampled dual-stack traffic. Its
  protected systemd launcher prevents unattended library maintenance from
  silently replacing the observer or resetting the evidence window.
- Reversible Linux split-DNS qualification for authoritative forward and reverse
  answers, short-name search, UDP/TCP service, host-resolver isolation, cleanup,
  and recovery.
- Opt-in native flow telemetry with redacted control-issued credentials, bounded non-blocking queues, TCP handshake state, explicit per-direction counters, HTTPS-only uploads, redirect refusal, and no packet payload retention.
- No copied compatibility-reference source.

See [architecture](../docs/architecture/client.md),
[platform contracts](../docs/client/platform-contracts.md),
[security model](../docs/client/security-model.md),
[direct paths](../docs/client/direct-path.md), [DNS](../docs/client/dns.md),
[policy](../docs/concepts/policy.md),
[Linux packaging](../docs/client/linux-packaging.md) and
[Linux qualification](../docs/client/linux-qualification.md).

## Current scope

This repository can validate a server key, explicitly pin it, persist and register a per-profile identity, maintain the active profile's control stream, atomically publish a validated network map, activate Linux MeshTransit DNS and split-DNS routing, create a Linux TUN through a separate privileged process, reconcile signed host routes inside fixed overlay pools, enforce host-level packet policy, maintain an encrypted relay base path, publish discovered endpoints, run authenticated direct-path probes, and roam encrypted traffic between relay, public, and private paths. `doctor control` remains a non-persisting diagnostic. It does not yet implement encrypted resolver transports, subnet/exit routes, fragment reassembly, or complete port semantics for transports other than TCP and UDP.

Private identity records are encrypted and authenticated at rest. On packaged
Linux, a root-only `meshcred` one-shot creates a host-encrypted systemd
credential once; systemd decrypts it only into the private credential mount of
`meshd.service`. Treat `/var/lib/meshd`, `/etc/credstore.encrypted`, and their
backups as sensitive. The current host-key backend does not protect a machine
after full root or host-key compromise, and TPM binding, native power-loss
qualification of key rotation, and encrypted backup recovery remain production
gates.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md).

## Contributors

MeshTransit contributors.

## License

Except for third-party components identified in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), `meshd` is licensed under the
[Apache License 2.0](../LICENSES/Apache-2.0.txt). The required attributions are recorded in
[NOTICE](../NOTICE).
