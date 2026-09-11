# Linux DNS design

The DNS subsystem converts one validated network-map snapshot into an immutable,
product-owned resolver plan. Protocol-specific values stay in the compatibility
adapter. The plan contains local forward records, reverse records, search
domains, locally authoritative zones, split routes, and optional classic-IP
upstream resolvers.

## Activation transaction

1. `meshd` asks `meshnetd` for the helper-fixed non-persistent DNS link.
2. The unprivileged daemon binds UDP and TCP listeners to the fixed endpoint.
3. The complete resolver plan is published atomically.
4. Only after both listeners are ready does the helper install per-link
   `systemd-resolved` state.

Disable, profile change, permanent control failure, and graceful shutdown run
the inverse transaction: revert the resolved link, clear the resolver plan,
stop owned listeners, and close the non-persistent link. A partial apply restores
the last complete state with a bounded rollback context.

## Query behavior

- Exact local names return A, AAAA, or both; overlay addresses have PTR records.
- Known names without the requested address family return authoritative NODATA.
- Unknown names in local zones return authoritative NXDOMAIN with a bounded SOA.
- Forwarding uses the most-specific route, then the optional default resolvers.
- Fallback resolvers remain compatibility metadata on split-DNS-capable Linux
  hosts. They are not silently promoted to defaults; doing so would override the
  host resolver path when the control plane requested only split DNS.
- Upstream transaction IDs are randomized and responses must match the original
  question before the client transaction ID is restored.
- Truncated UDP upstream responses are retried over TCP.
- Query size, response size, concurrent forwards, TCP connections, idle time,
  and total query time are bounded. Query names are never logged.

## EDNS0

EDNS is treated as a separate hop on each side of the resolver. When a request
contains one valid EDNS0 OPT record, the response contains one empty, sanitized
OPT record advertising the resolver's 4096-byte capacity. The UDP response still
honors a smaller requestor limit, treating values below 512 as 512. A truncated
response retains the question and OPT record so clients can retry without
downgrading the server capability. Unsupported versions return BADVERS; malformed
or duplicate OPT records return FORMERR with a sanitized OPT record when the
request can still be parsed.

Unknown options are ignored rather than reflected. This avoids turning the local
resolver into an option echo service and keeps future option support explicit.

## Current platform scope

The host backend currently targets Linux with `systemd-resolved`. Classic UDP
and TCP upstreams on port 53 are supported. Encrypted resolver transports,
non-resolved Linux hosts, macOS, Windows, Android, and iOS backends remain
unimplemented and fail closed.

## Qualification

Unit tests cover local A/AAAA/PTR/NODATA/NXDOMAIN responses, most-specific split
route selection, explicit default forwarding, fallback-resolver isolation,
transaction-ID validation, UDP truncation retry over TCP, EDNS0, bounded input,
and transactional rollback. The Linux qualification harness adds installed-host
evidence for UDP/TCP service, `systemd-resolved` search and route integration,
preservation of non-mesh DNS, removal on graceful daemon stop, and bounded
recovery after restart.

The first two-node installed-host evidence is recorded in
[linux-dns-qualification-2026-09-11.md](linux-dns-qualification-2026-09-11.md).
That run also staged and rolled back control-plane split and explicit-default
resolver configurations, proving live upstream forwarding on both Linux nodes.
