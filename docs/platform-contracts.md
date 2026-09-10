# Platform contracts

This document defines the operating-system boundary for `meshd`. It prevents
platform implementations from leaking into the common control, policy, DNS,
relay, discovery, and encrypted packet path.

It is an architectural contract, not a requirement to create one broad Go
interface. Implementations should define small consumer-owned interfaces at the
package that needs each capability.

## Design rules

- Product-owned types cross the boundary. Protocol-adapter and vendor-specific
  types do not.
- The common core computes desired state; a platform adapter applies one bounded
  transaction and returns observed state or a typed error.
- Every mutating operation accepts cancellation and has a finite deadline.
- Prepare, commit, and rollback are explicit whenever partial host mutation is
  possible.
- Repeating the same desired state is safe. Stale generations cannot replace a
  newer committed generation.
- Platform adapters do not make control-plane authorization decisions.
- Platform-specific unsafe fallbacks are excluded from production builds.
- Secrets and packet payloads never enter platform error strings or structured
  logs.

Linux is the reference implementation, Windows follows, and macOS is last. A
later adapter may improve the common contract, but it must not weaken a security
invariant already enforced by another platform.

## Local administration transport

The local API needs two independent capabilities: a bounded local listener and
an authenticated peer principal. Authorization consumes a stable product
principal, not an address or caller-supplied identity.

| Platform | Planned transport | Required peer evidence |
| --- | --- | --- |
| Linux | Unix-domain socket | kernel `SO_PEERCRED` UID/PID evidence |
| Windows | named pipe with a restrictive security descriptor | kernel access token and SID evidence; reject remote pipe clients |
| macOS | Unix-domain socket | kernel peer credentials mapped to UID/PID where available |

The listener must apply restrictive permissions before accepting requests,
bound frame/header/body sizes, and authorize every new connection. A successful
filesystem open or pipe connection alone is not sufficient authorization.

## Tunnel and route lifecycle

The common data plane supplies a validated generation containing self host
addresses, peer host routes, MTU, and a bounded packet-I/O attachment. The
platform capability must:

1. prepare a non-persistent tunnel without publishing routes;
2. validate every address and route against immutable startup constraints;
3. publish the complete desired host-route set atomically where the OS allows;
4. return a generation-bound packet I/O handle;
5. roll back partial work and remove only state owned by MeshTransit.

It must reject default routes, subnet routes, overlapping pools, arbitrary
device names, executable paths, and unrecognized fields until a future release
adds a separate reviewed contract for them.

Linux retains the split `meshd`/`meshnetd` design and descriptor passing. The
Windows phase must choose and threat-model the narrow service/adapter boundary
before tunnel code is enabled. The macOS phase must choose the entitled Network
Extension or equivalent supported system boundary before tunnel code is
enabled. Neither platform may temporarily run with unverified local callers to
claim compatibility.

## DNS transaction

The common DNS compiler produces an immutable desired plan containing local
records, ordered upstream resolvers, search domains, route domains, and explicit
default-route intent. The platform transaction must:

1. prepare and health-check the local resolver;
2. capture only the host state needed for a precise rollback;
3. commit resolver routing as one generation;
4. revert the host before stopping the local resolver;
5. recover owned stale state after a crash without overwriting administrator
   changes made later.

Linux uses the existing bounded `systemd-resolved` link transaction for the
initial Ubuntu targets. Windows will use supported DNS policy/configuration APIs
rather than shell commands. macOS will apply DNS through its selected entitled
network boundary. Query names and packet bodies are never diagnostic fields.

## Secret storage

The common identity service reads and replaces opaque secret blobs through a
small storage capability. It owns schema versioning and key rotation; the
platform adapter owns sealing and access control.

Release-eligible adapters must provide:

- create-only initialization and atomic replacement;
- confidentiality and integrity at rest using an OS- or host-bound key;
- access restricted to the intended service identity;
- explicit distinction between missing, locked, corrupt, and unsupported state;
- migration that never deletes the last readable copy before verification;
- redacted errors and zeroization of temporary mutable buffers where practical.

The Linux implementation will introduce an encrypted state envelope with a
host-bound sealing backend suitable for the supported Ubuntu service model.
Windows uses DPAPI or an equivalent service-identity-bound facility. macOS uses
Keychain access groups scoped to the signed product. Plain `0600` records remain
a development migration source, not a v0.1 release backend.

## Network-change monitor

The monitor emits coalesced generation changes rather than raw operating-system
events. It observes interface/address availability, default-route changes,
sleep/resume, and reachability hints without declaring a peer endpoint trusted.

Consumers use an event only to refresh discovery, re-evaluate relay health, and
reapply the current signed desired state. The monitor cannot alter map
authority, policy, routes, peer keys, or DNS contents. Event storms are bounded
and shutdown joins every worker.

## Service lifecycle

The native service adapter must expose consistent start, stop, reload/upgrade,
health, and rollback semantics:

| Platform | Initial service model | Initial package |
| --- | --- | --- |
| Linux | `systemd` units for an unprivileged daemon and minimal privileged helper | `.deb` |
| Windows | Windows Service identities selected by the Windows threat model | MSI |
| macOS | signed launch/service components plus the selected entitled network component | signed and notarized package |

Installers create identities and permissions before the first start. Upgrades
preserve compatible identity state, validate migrations before commit, and keep
one rollback path. Uninstall removes owned runtime network/DNS state before
removing binaries and optionally preserves identity only through an explicit
operator choice.

## Error model and observability

Common code must be able to distinguish at least:

- unsupported capability;
- permission or peer-authorization denial;
- invalid desired state;
- transient host/network failure;
- permanent host incompatibility;
- rollback failure;
- corrupt or locked secret storage.

Status reports the affected capability, safe phase, and a stable product error
code. Logs may include platform error codes and owned resource identifiers but
not raw packets, DNS query names, peer endpoint addresses, access tokens, or
private identity material.

## Contract testing

Each capability has a platform-independent conformance suite driven through a
fake adapter, plus native tests for kernel and service behavior. Native tests
must cover happy path, permission denial, cancellation, repeated application,
partial failure, rollback, stale generation, abrupt process termination, and
cleanup after reboot where applicable.

Cross-compilation proves build separation only. A platform becomes supported
after the same signed artifact passes its native functional, security,
reliability, install, upgrade, rollback, and uninstall gates defined in
[release-v0.1.md](release-v0.1.md).
