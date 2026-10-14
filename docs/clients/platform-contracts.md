# Platform contracts

The rules every operating-system adapter of `meshd` follows, so platform code
stays out of the common control, policy, DNS, relay, discovery and packet
paths. This is a contract, not one broad Go interface: each package that needs
a capability defines its own small interface.

## Design rules

- Product-owned types cross the boundary; protocol and vendor types do not.
- Common code computes the desired state; an adapter applies it as one
  bounded transaction and returns the observed state or a typed error.
- Every mutating operation takes a context and has a deadline.
- Prepare, commit and rollback are explicit wherever a partial host change is
  possible.
- Applying the same state twice is safe, and an older generation never
  replaces a newer one.
- Adapters make no authorization decisions of the control plane.
- No packaged configuration admits an unverified local caller. Where a
  platform has no sealed key store yet (macOS), the key is an owner-only file
  and the gap is documented.
- Secrets and packet payloads never appear in adapter errors or logs.

A new adapter may improve the common contract but must not weaken a security
property another platform already enforces.

## Local administration transport

The local API needs a bounded local listener and a caller identified by the
kernel or the OS, never by an address or a value the caller supplies.

| Platform | Transport | Caller evidence |
|---|---|---|
| Linux | Unix socket | `SO_PEERCRED` |
| macOS | Unix socket | `LOCAL_PEERCRED` |
| Windows | Named pipe under `ProtectedPrefix\Administrators`, remote clients refused | The caller's access token: SID, elevation, group membership |
| Android, iOS | None: the app calls `client/mobile` in process | — |

Permissions are set before the first request is accepted. The Unix socket
group may serve as the policy only because kernel credentials have already
proved the caller is local. See [security model](security-model.md#local-api).

## Tunnel and routes

The common data plane hands the adapter a validated generation: self
addresses, host routes, MTU and a packet I/O attachment. The adapter:

1. prepares a non-persistent tunnel without publishing routes;
2. checks every address and route against its startup frame;
3. publishes the host routes, adding before removing;
4. returns a packet I/O handle bound to that generation;
5. rolls back partial work and removes only what MeshTransit owns.

Default routes, subnet routes, overlapping pools, arbitrary interface names,
executable paths and unknown fields are refused until a separate reviewed
contract adds them.

| Platform | Boundary |
|---|---|
| Linux, macOS | `meshnetd` creates the TUN (`/dev/net/tun`, `utun`) and passes its descriptor to `meshd` |
| Windows | `meshd` opens the Wintun adapter and sets addresses and routes itself (LocalSystem), with the same frame checks |
| Android, iOS | The app's `VpnService` or packet tunnel supplies the descriptor; the core widens overlay routes to stable blocks |

## DNS

The common DNS compiler produces an immutable plan: local records, upstream
resolvers, search and route domains. The adapter:

1. starts and checks the local resolver;
2. records only the host state it needs to undo its change;
3. commits the host routing for mesh names as one generation;
4. reverts the host before it stops the resolver;
5. after a crash, removes its own stale state without overwriting later
   administrator changes.

| Platform | Host mechanism |
|---|---|
| Linux | A `systemd-resolved` link through `meshnetd` |
| macOS | An `scutil` supplemental resolver through `meshnetd` |
| Windows | One NRPT rule in the `DnsPolicyConfig` registry key, then a DNS cache flush |
| Android, iOS | Not implemented |

Query names and packet bodies are never diagnostic fields. See
[DNS](../concepts/dns.md).

## Secret storage

The common identity code owns record formats, versions and envelope
encryption; the adapter only supplies the host key and controls who can read
it. An adapter provides:

- create-only first provisioning;
- confidentiality at rest under an OS- or host-bound key;
- access limited to the service identity;
- distinct errors for missing, locked, corrupt and unsupported states;
- no deletion of the last readable key before its replacement is verified;
- redacted errors.

| Platform | Host key |
|---|---|
| Linux | systemd credential encrypted with the host key; rotation with a recovery copy (`meshcred`) |
| macOS | Owner-only file (`meshcred provision`); a Keychain-backed key is planned |
| Windows | DPAPI for LocalSystem |
| Android | Android Keystore, through the app |

See [security model](security-model.md#identity-at-rest).

## Network-change monitor

The monitor reports coalesced changes, not raw OS events: interfaces,
addresses and default routes. A change only triggers endpoint discovery,
relay checks and reapplying the current signed state; it never changes map
authority, policy, routes, keys or DNS records. Bursts are drained and
debounced, the MeshTransit interfaces are ignored, and shutdown joins every
worker.

| Platform | Source |
|---|---|
| Linux | Netlink route, link and address notifications |
| macOS | The routing socket |
| Windows | `NotifyIpInterfaceChange`, `NotifyUnicastIpAddressChange`, `NotifyRouteChange2` |
| Android, iOS | The app reports changes through `client/mobile` |

Every source falls back to polling if it fails. Sleep and resume are not
observed directly.

## Service lifecycle

| Platform | Service | Package |
|---|---|---|
| Linux | systemd: `meshd`, `meshnetd`, `meshcred` oneshot | `.deb`, built and verified by `make package-deb` |
| macOS | launchd daemons `net.meshtransit.meshd` and `net.meshtransit.meshnetd` | Tarball with `install.sh`; not signed or notarized yet |
| Windows | One service, `MeshTransit`, as LocalSystem | Zip with `install.ps1`; not code-signed yet, no MSI |
| Android | The app's `VpnService` | The app |

Installers create users, groups and permissions before the first start.
Upgrades keep compatible identity state. Uninstall removes MeshTransit's
network and DNS state before the binaries and keeps the identity unless the
operator asks for a purge. Per-platform steps: [Linux](linux.md),
[macOS](macos.md), [Windows](windows.md), [Android](android.md).

## Errors and observability

Common code distinguishes at least: unsupported capability, permission
denied, invalid desired state, transient host failure, permanent host
incompatibility, rollback failure, and corrupt or locked secret storage.

Status names the capability, a safe phase and a stable error code. Logs may
include platform error codes and MeshTransit's own resource identifiers, but
never packets, DNS query names, peer endpoint addresses, tokens or key
material.

## Testing

Each capability has a platform-independent test against a fake adapter and
native tests for kernel and service behaviour: success, permission denial,
cancellation, repetition, partial failure, rollback, stale generations,
abrupt termination and, where relevant, cleanup after reboot.
Cross-compilation proves only that the build is separated. The native Linux
procedures are in [Qualification](../testing/qualification.md).
