# Unified alias Device sharing live qualification

Live two-host qualification of Device sharing through the unified alias path
(schemas 92–93, consumer DNS in commit 2f6cee8). Provider, Consumer and
Isolation Networks belong to one Workspace with disjoint overlay prefixes. The
Provider and Isolation clients share one host; the Consumer runs on another.
Host addresses, origins and display identifiers are omitted. Overlay and alias
addresses below come from the product ranges (RFC 6598, RFC 2544, ULA).

| Role | Overlay | Seen by the other side as |
| --- | --- | --- |
| Provider Device | 100.64.10.8, fd07:d4de:9d87:1::8 | Resource Alias 198.18.0.2, fd02:48de:ec1b:1::2 |
| Consumer Device | 100.64.20.1, fd07:d4de:9d87:2::1 | Consumer Source Alias 198.19.0.2, fd02:48de:ec1b:2::2 |
| Isolation Device | 100.64.30.1, fd07:d4de:9d87:3::1 | nothing |

The Consumer rule allows ICMP from the Consumer Device to the imported Device.
Latencies are measured from the Console action to the first changed echo on a
200–500 ms timestamped ping; host clocks are NTP-synchronized.

## DNS

- The Consumer map carries the access name as `ExtraRecords`. meshd routes only
  that name to its local resolver link; `getent hosts` returns the Resource
  Alias for A and AAAA, and ping by name succeeds over the direct path.
- The Provider map carries no names (`DNS: inactive`); the name does not
  resolve on the Provider host.
- Removing the rule or revoking the share removes the name with the peer.

## Authority changes

| Case | Result |
| --- | --- |
| Remove rule (deny) | Echo stops in about 1 s, IPv4 and IPv6; peer and name removed. |
| Create rule (allow) | Echo resumes in about 2.4 s; direct path and name restored. |
| Revoke share | Echo stops in 0.7–0.9 s; 0 of 173 later echoes answered. Contract and endpoint `revoked`, all four alias leases `quarantined`, readiness `withdrawn`. |
| Recreated share | New aliases `.2`/`::2` are allocated; quarantined `.1`/`::1` are not reused. Endpoint stays `provisioning` until a Consumer rule exists. |

## Dependency loss

| Case | Result |
| --- | --- |
| Consumer meshd restart | Peer back in 1.4 s; DNS restored. |
| Provider meshd restart | Peer back in 0.8 s, but data stays relayed (see open issues). |
| Redis paused about 66 s | Data plane uninterrupted. Control ends map streams on presence loss; clients keep their last map and resynchronize after Redis returns without restart. Console sign-in fails (502), so no authority change is possible during the outage. |
| Wakeups lost (worker scaled to 0) | Policy publish commits; the outbox event stays `pending`. Deny reaches the client in about 11 s and allow in about 25 s through the 30 s map reconciliation. On worker return every Network revision event is delivered. |

## Creator-set labels (schema 94)

Core 8a4afe2 and Console 26fb799 were deployed after schema 94 and its
operator script; the database preflight passed. The existing unlabeled share
kept working through the rollout. It was then revoked and replaced:

- The New share form proposed the Device-name label; the creator set `poc01`.
  Core returned the derived `<label>.<provider Workspace code>.<provider
  Network code>.shared.mesh` name in the create response.
- The consumer review showed that name and had no name input. Acceptance sent
  no access name and reserved exactly the derived name.
- After enable and a Consumer rule, the name resolved to the new Resource
  Alias (`.3`/`::3`; earlier ones stay quarantined) and ping by name passed
  over IPv4 and IPv6 on the direct path.

## Isolation packet matrix

Each case sends three echoes bound to the named mesh interface. Kernel-refused
IPv6 cases were repeated with a temporary /128 route on that interface so the
packets reach the TUN; captures confirm requests enter the TUN with no reply.

| ID | From | To | Expect | Received |
| --- | --- | --- | --- | --- |
| I1/I2 | Isolation | Resource Alias v4/v6 | deny | 0/3, 0/3 |
| I3/I4 | Isolation | Consumer overlay v4/v6 | deny | 0/3, 0/3 |
| I5/I6 | Isolation | Consumer Source Alias v4/v6 | deny | 0/3, 0/3 |
| C1/C2 | Consumer | Isolation overlay v4/v6 | deny | 0/3, 0/3 |
| C3/C4 | Consumer | Provider raw overlay v4/v6 | deny | 0/3, 0/3 |
| C5/C6 | Consumer | Resource Alias v4/v6 | allow | 3/3, 3/3 |
| P1/P2 | Provider | Consumer Source Alias v4/v6 | deny | 0/3, 0/3 |
| P3/P4 | Provider | Consumer overlay v4/v6 | deny | 0/3, 0/3 |

A Consumer capture during the Isolation cases saw no Isolation-sourced packet.
The Isolation client reports 0 peers, 0 rules and inactive DNS.

Control plane: the Isolation Network lists no accepted share and offers no
shared rule destination. The runtime imported-locator query
(`readImportedPolicyLocatorsSQL`) run as `mesh_runtime` under Isolation scope
returns `[]` for the Consumer's imported Device and one row under Consumer
scope, so a rule in another Network cannot resolve the share.

## Logs

Core api, control, worker and identity logs for the test window and all client
journals contain no bearer, offer, CSRF or auth tokens, private keys, cookies,
share names, alias addresses or host addresses. Map stream failures log only
`map stream terminated` with a redacted error.

## Open issues

- Fixed in meshd a3cd965: after the Provider restarted, both sides reported a
  direct path while all data used the relay (about 500 ms RTT) and did not
  self-heal, because relayed packets in flight roamed the WireGuard endpoint
  back to the relay after each direct reassert. With roaming pinned to the
  selected endpoint, three Provider restarts each returned to a direct path
  with 1.6–1.8 ms average RTT within 5 s.
- Fixed in meshd 82657b0: a host running several clients advertised another
  client's TUN address (here the Isolation overlay address) as a UDP endpoint
  candidate, and peers probed it over the underlay. Host candidates now skip
  point-to-point interfaces and the MeshTransit overlay ranges; 25 s captures
  on both hosts show no underlay packet to an overlay or DNS-link address.
- Fixed in Console b806cfd: the rule-removal review now reports shared-Device
  access loss, and a rule pointing at an ended share is marked and must be
  removed before other rule changes instead of causing a 409 conflict.
- About 300 deployment-stream outbox events (identity, session, address pool)
  remain `pending` with no dispatcher.
- Not covered: TCP/UDP shares, cross-Workspace shares, multi-replica map
  failover, share expiry, and creator-set DNS labels.
