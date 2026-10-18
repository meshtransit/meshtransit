# Changelog

Notable changes to MeshTransit. Component histories from before the monorepo
merge (2026-10-09) are kept below.

## Unreleased

- Client and Core: a Device warns before it expires. `meshctl status` shows
  a `Device expiry` line (and `device_expires_at`, `device_expiry` in
  `--json`) that reminds the person to sign in again from 14 days before and
  urgently on the last day; the mobile status JSON carries the same two
  fields. Core exports `meshtransit_mtcp_sessions_device_expiring{within}`
  for the connected Devices expiring within 14 days and within one day.
- Core: each Network chooses how long a Device that signs in through the
  browser lives: 1 hour to 180 days, or never expires. Without a choice it
  lives 180 days instead of 30. `GET` and `PATCH …/networks/{network}/device-lifetime`
  (`network.read`, `network.update`, `If-Match`) read and set it, and each
  change is audited as `network.device_lifetime.updated`. The choice applies
  from the next sign-in; Devices already registered keep their expiry until
  their user signs in again. Schema 179 adds two empty columns, no operator
  step. The Console shows it under Network settings.
- Core: `POST …/devices/{device}/actions/revoke` removes a suspended or
  expired Device too, as removing a member already did; the suspension and
  any pending handover are cleared. Before, the request failed with a
  generic error.
- Core: removing a provider Device ends its shares. A trigger queues the open
  contracts of a Device that becomes revoked or deleted; the worker that
  finalizes expiry also moves them to `invalidated`, frees the consumer
  access name and alias, advances both Networks and audits
  `trust_contract.invalidated` (reason `provider_device_removed`) on both
  sides. Existing shares of removed Devices are queued by the migration
  (schema 178, operator step `000178` before rollout). The Console shows
  "Ended: the shared Device was removed or changed" to both sides.
- Core (breaking): every API path follows resource rules, still under `v1`,
  with no old paths kept. `POST` on a collection creates (device tags, user
  groups, Network device groups, guardrails, interchanges, invitations,
  enrollment keys, Network members); `PATCH` and `DELETE` on an item change
  and remove; group members change with `PATCH …/members`, a Device's tags
  with `PATCH …/devices/{device}/tags`; Workspaces and Devices are renamed
  with `PATCH` on the item and alias ranges changed with
  `PATCH …/alias-ranges`; a role assignment is revoked with `DELETE`. The
  audit export moves to `GET …/audit-exports`, the enforcement history to
  `GET …/networks/{network}/enforcement-history`, assignable tags to
  `GET …/networks/{network}/assignable-device-tags`. The Console's cookie
  path accepts `PATCH` and `DELETE` with a CSRF proof; a `DELETE` carries no
  body.
- Core: the Console lists Devices by name ten at a time with a name prefix
  (`q`) and an `active`/`inactive` filter, reads one Device with how it was
  enrolled and its tags (`GET …/devices/{device}`), its delivery status
  (`…/status`) and a page of the peers it reported (`…/peers`); the
  Network-wide `…/devices/distribution` read is removed (schema 177).

- Core: enrollment keys can be created, listed and revoked through the API
  (`…/networks/{network}/enrollment-keys`, `enrollment_credential.issue` and
  `.revoke`) and the Console. A key enrolls exactly one Device; its creator
  chooses how long the key can be used (5 minutes to 30 days, 24 hours by
  default) and how long the Device lives (1 hour to 180 days, or never). The
  Device belongs to the key's creator and is not affected when the key
  expires. Only a usable key can be revoked; a key that already enrolled its
  Device is refused (`409 enrollment_key_used`), and that Device is managed
  instead (schema 176). Each creation and revocation is recorded in the
  Network's activity log, and each registration records the Device lifetime
  it got. Schema 175; the `api` role reads `MESHTRANSIT_ENROLLMENT_DIGEST_*`
  to issue keys.
- Core: every `policy.published` event now records the published
  `policy_revision` and a `change_summary`: how many Access Rules were added,
  removed, changed or kept, and up to 20 of the changed rules with their
  destination (an Imported Resource by its consumer-local ID). Core computes
  the comparison itself from rule fingerprints that each release now keeps
  (schema 174, one row per release); the database does not compare compiled
  rules. A release published by an older Core has no fingerprints, so the
  next publication records `baseline: unavailable`; fingerprints that do not
  decode record `unreadable` and never block publication. The event stays
  within the 16 KiB audit bound: when it would not fit, it lists fewer
  changed rules, then fewer guardrail findings (with
  `guardrail_finding_count`), instead of failing the publication. Docs now
  say that approval is optional and `approval_policy.manage` grants nothing
  yet.
- Core: `meshcore migrate operator apply` runs the operator SQL steps from the
  binary instead of by hand with `psql`. It connects with its own
  `MESHTRANSIT_OPERATOR_*` settings as a superuser or `CREATEROLE` role, and
  refuses the migrator, runtime, worker and owner roles. It runs, in order
  and in one transaction under the migration lock, every step that does not
  hold (and the later steps again), never a step whose migration is not
  applied (`--through N` refuses one), and the steps of migrations 53 to 93,
  170 and 171 only with `--after-rollout`; it then checks that every step
  holds and rolls back otherwise. `--dry-run` rolls back always, and
  `meshcore migrate operator status` lists every step. A step holds when its
  roles, function owners and `EXECUTE` grants are in place, so steps applied
  by hand count too; nothing new is stored. `meshcore migrate verify` (with
  the migrator's settings) reports the schema state and exactly which role,
  owner or grant of which step is missing and any role membership of a
  MeshTransit role, and exits with status 3 while any of these is found. The
  command runs the statements it rebuilds from each parsed file, never the
  file's text, and each ownership file now starts with
  `-- operator-step: rollout=before|after`.
- Core: a pending operator step is now visible. Readiness stays up, since
  some steps must wait until a rollout ends, but a background read (at most
  once a minute) logs the pending steps when they change and exports
  `meshtransit_postgres_operator_steps_pending`; the policy publication,
  Imported Resource, share decision, alias worker and map reader paths
  export the function version they selected in
  `meshtransit_postgres_function_version` and log a warning naming the
  operator step while it is below the newest. The same background read exports
  `meshtransit_postgres_role_memberships` and warns when a MeshTransit role
  takes part in a membership.
- Core schema 172 and Core: every time Core persists, or compares with
  persisted state, now comes from the PostgreSQL clock: share, Resource,
  policy approval and publication, Device registration, revocation and
  Node-key rotation times, idempotency windows, invitation and browser
  registration lifetimes, session renewal, the instant authorization and
  expiry are evaluated at, relay revocation windows and Console reads. A
  Core host's clock only bounds local timeouts and backoff. Before, a host
  running ahead of or behind the database wrote rows out of order with the
  database's own writers: finalizing a just activated Private Endpoint, or
  revoking a share after its publication, failed with 23514; a new Device
  stayed out of maps until the database caught up; recent revocations could
  be left out of the relay state. Schema 172 also keeps `updated_at` in
  order on the Resource sharing rows, so a row a previous binary stamped
  ahead of the database no longer fails the next write; schema 173 logs
  each such case to the server log. Map streams measure key and projection
  deadlines from the database time of their read. No operator step.
  Every process with a PostgreSQL connection samples the database clock at
  start and every minute and exports `meshtransit_postgres_clock_skew_seconds`
  (with its round trip, sample time and a samples counter); a skew above one
  second logs `clock_skew_exceeded`. Sampling never affects readiness.
- Core schema 171: a shared Device that was suspended (or whose session or
  keys changed) gives its consumers the share back once it is active again.
  The alias worker used to quarantine the endpoint's Resource aliases for
  good, so the endpoint stayed provisioning and every consumer Device lost
  the share until it was revoked and created again. It now reserves the
  endpoint's own Resource aliases again, so the share keeps its addresses and
  DNS name, and makes each pair ready again; the old leases stay as
  quarantined history. A revoked or expired share, a deleted Device or a
  Resource that targets another Device still does not come back. Run the
  schema 171 operator step after the migration; until then the worker keeps
  the previous behaviour.
- Core schema 170: a consumer Device that was suspended (or whose session or
  keys changed) gets its shares back once it is active again. The alias
  worker used to withdraw the share for good, so the Device had no peer for
  it until the share was revoked and created again. It now reserves a new
  Consumer Source Alias and makes the pair ready again; the old alias stays
  quarantined. Run the schema 170 operator step after the migration; until
  then the worker keeps the previous behaviour.
- Core schema 169 and meshd: Device names resolve again. Every live Device
  has a DNS name, `<label>.<Workspace code>.<Network code>.<suffix>`, where
  the label is derived from the hostname and unique in the Network (numbered
  variants such as `laptop-1` when two hostnames give the same label; existing
  Devices are labeled in registration order by the migration). Maps carry an
  address record for the node itself and its same-Network peers, the suffix
  as a route the node answers itself and the Network's zone as search domain;
  `meshd` answers reverse (PTR) queries for those names. Renaming a Device to
  a hostname whose label another Device holds is refused like a taken
  hostname. Labels that hosts look up on their own (`wpad`, `isatap`,
  `localhost`, `www`, ...) are prefixed with `device-`. A Device without a
  label, or names that collide, never fail a map: they are left out and
  counted in `meshtransit_mtcp_map_names_degraded_total`. The Console Device
  inventory returns `dns_name`.
- Core: **share names change** from `….shared.mesh` to `….shared.<suffix>`
  (`….shared.mesh.internal` by default) in maps and in the management API.
  Applications that reach shared Devices by name must use the new name; a
  name sent back on accept may use either form. Names a consumer typed before
  share names were derived are unchanged.
- Core: peers of another Network no longer carry their hostname, in the map's
  name or display name: a consumer knows a shared Device only by its share
  name, a provider its consumers only by a placeholder that does not resolve.
- Core: `MESHTRANSIT_DNS_SUFFIX` (default `mesh.internal`) sets the suffix of
  Device and share names; set it on every role. It needs two labels and may
  not be a special-use zone such as `local` or `arpa`. Configuration schema 26.
- meshd: a map may carry 50,000 DNS records (was 32,768), as MTCP v1 allows.
  A locally answered route for the root or a single label from Core is
  ignored and logged.
- Core schema 168: the Private Endpoint route worker no longer applies and
  withdraws a route for an endpoint created by a MeshCore whose clock runs
  ahead of the database host. Such an endpoint waits until the database clock
  reaches its creation time; before, the readiness confirmation failed with a
  serialization error, the worker withdrew the route it had just applied and
  retried after its backoff. No operator step is needed.
- Core schema 167: guardrail saves and share changes no longer race. A
  share accepted or enabled while its Workspace's guardrails are being saved
  fails as a retryable conflict; a guardrail save that a concurrent share
  changed under is redone by Core up to three times, then fails with
  `version_conflict`, instead of missing it. Saving a guardrail no longer
  deadlocks with a share offer of another Workspace. Switching an enforced
  guardrail to audit mode or deleting it reads no share list: it wakes the
  Networks of the shares of the Networks it named, at most 1,024 at once,
  the rest at the next map reconcile interval, so it works at any size. Only
  previews and saves in enforce mode read shares, at most 20,000 (above that,
  even a loosening save in enforce mode is refused).
  `guardrail.weaken` may preview, and the map reads guardrails through
  indexes. Existing shares that enforced guardrails block leave maps within
  one reconcile interval of the new binary; no operator step is needed, but
  do not change enforce-mode guardrails while binaries from before and after
  schema 167 run together.
- Core: members can be added to and removed from an existing Network. Before,
  a Network created after people joined the Workspace held only its creator,
  so nobody else could enroll a Device into it. The new
  `network.member.manage` permission (owner, `admin`, `it_admin`; a
  Network-scope `it_admin` for its Network only) lists a Network's members,
  adds up to 150 active Workspace members at once, and removes one, handling
  their Devices in that Network with the same plan as a Workspace removal
  (move to the Workspace, hand over to another Network member, or revoke).
  Console routes: `GET /api/v1/workspaces/{workspace}/networks/{network}/members`,
  `POST .../members/actions/add` and `POST .../members/{member}/actions/remove`.
  Additions and removals are recorded on the Network's audit stream as
  `network.member.added` and `network.member.removed` (schema 166).
- Core: a policy holding a rule to a Resource, a Resource Group member or an
  Imported Resource whose Device was suspended, expired or revoked no longer
  fails every publication with a stale revision (412). Such rules publish
  like Device rules: suspended and expired Devices are accepted, a revoked
  Device only in a rule the active policy already holds unchanged, and a new
  or changed rule for a revoked Device is refused with 409
  `device_unavailable`. A kept rule now counts as unchanged only when both
  sides, the protocol, the ports and the destination match, for Device and
  group rules too (migration 165).
- Core schema 164: an enforce-mode guardrail cuts the existing shares it
  blocks. Before, guardrails were checked only when a share was made or rules
  were published, so tightening one later left existing shares open. Maps now
  leave out every share an enforced guardrail of either Workspace blocks and
  put it back once the guardrail is switched to audit mode, loosened or
  deleted; the share itself is unchanged. Saving a guardrail in enforce mode
  needs the `impact_hash` of a preview
  (`POST /api/v1/workspaces/{workspace}/guardrails/actions/preview`), which
  lists the shares the save would cut; a stale or missing hash gets
  `guardrail_impact_changed` (409). A save that cuts or restores shares wakes
  the maps of both sides, with evidence on each Network's audit stream. A
  share accepted or a rule published while the provider's guardrails are
  being saved now fails as a retryable conflict instead of waiting.
- Core: a test now refuses an operator ownership step that takes a previous
  function version away from `mesh_runtime` or `mesh_worker` (steps after
  migration 93 already keep them for rollback), and the `…_role.sql` steps
  create their role only if it is missing, so they can run again.
- Clients: a failure to apply host DNS now sets the DNS state to `failed`
  and turns the mesh names off on the host; the control session and data
  plane stay up and the next map retries. Before, the node left the mesh and reconnected to Core every few
  seconds, receiving the same map. All shared names are routed by one
  locally authoritative `shared.mesh` route instead of one route per name, so
  importing more than 256 shares no longer exceeds the host's route limit,
  and unknown names under `shared.mesh` are answered `NXDOMAIN` instead of
  going to the host's resolvers.
- Windows: `meshd` seals its identity key with DPAPI plus a fixed MeshTransit
  entropy, so a generic DPAPI unseal no longer opens it (code running as
  LocalSystem still can). A key sealed by an older `meshd` opens, is resealed
  and atomically replaced on the first start; an older `meshd` cannot open
  the resealed key, so restore the pre-upgrade key file before downgrading.
- Clients: `meshd` creates only the last folder of its state, key, socket and
  log paths and requires the parent to exist; an existing folder must be a
  real folder (not a link, junction or other reparse point) owned by the
  service (its user on Unix; SYSTEM or Administrators on Windows), or `meshd`
  refuses to start. On Windows, new folders get the restricted access list
  when they are created, `C:\ProgramData\MeshTransit` and its `logs` folder
  are restricted on every start, and a service log that is a link, has other
  hard links or grants anyone else access is replaced. Before, a junction
  planted at `C:\ProgramData\MeshTransit\logs` made the service write its
  log through it.
- Windows: `meshd` authorizes local API callers from the named-pipe
  connection's own access token, read by impersonating the client, instead
  of the token of whatever process has the client's process ID, which a
  reused ID or a handed-over pipe handle could make the wrong one.
  Anonymous clients are refused. `meshctl` now opens the pipe at the
  identification level (it used to connect anonymously), so a new `meshd`
  needs the matching `meshctl`.
- Core: a node must take each whole MTCP message within 30 s plus its size at
  64 KiB/s (at most 10 minutes), besides 10 s per record; otherwise Core
  closes the session (counted as `send_deadline` in
  `meshtransit_mtcp_session_limits_total`) and the node reconnects. A node
  reading one record every few seconds could hold a 32 MiB map in Core's
  memory for over an hour. The protocol limits table described a 16 MiB
  outbound buffer that never existed; it now states the real bounds.
- Core: policy simulation evaluates guardrails. `guardrail_findings` lists,
  for each proposed path to an Imported Resource, the guardrails publication
  would apply: the publishing Workspace's by name, and the provider's only
  where they block and without detail, with `blocks` where publication would
  refuse. `guardrail_evaluation` is no longer listed as unsupported. The
  impact hash includes the findings, so an approval request made before the
  upgrade (which lives at most 10 minutes) must be made again.
- Core schema 163: a share between Workspaces also answers to the provider's
  guardrails when the consumer accepts the offer, activates the Trust
  Contract or publishes new rules to the Imported Resource. Before, only the
  consumer's guardrails were checked, so a provider could not stop a share it
  had already offered. The consumer gets `counterpart_guardrail_violation`
  (409) without the provider's guardrail details.
- Core schema 162: Console sessions can be ended beyond one at a time. A
  person signs out everywhere (`POST /auth/v1/session/logout-all`), which ends
  every session of their Account. An administrator with `member.manage` ends
  the sessions a member signed in to their Workspace
  (`…/members/{member}/actions/revoke-sessions`). The operator ends every
  session of an Account, quarantines it (no sign-in until released) or
  releases it with `meshcore account revoke-sessions|quarantine|release`.
  Before, the Account's session generation was checked but nothing advanced
  it. Devices are not affected; each change writes an audit event.
- Core schema 161 and meshd: a revoked Device is told `REVOKED`, no longer
  `EXPIRED`. Core says so only for the exact machine and node keys it revoked
  (any other key without authority still gets `EXPIRED`, a failed lookup
  `RECONNECT`). meshd then replaces the profile's keys, if they are still the
  ones the revoked session used, and shows the profile as not registered;
  `meshctl login` registers a new Device without a `meshctl logout` first.
- Core schema 160: a Workspace invitation is accepted only by a sign-in whose
  identity provider verified the invited address (equal ignoring ASCII letter
  case; non-ASCII addresses are refused). Before, the link alone let anyone who
  completed sign-in join with the invited role. A refused sign-in creates
  nothing and leaves the invitation pending. Login profiles must request the
  `email` scope; the acceptance evidence carries a digest of the address.
- Dex broker artifact re-qualified at Go 1.26.9: `v2.45.1+compat.9`
  adds patch 0009 (`golang.org/x/net` v0.60.0 and its modules, removing the
  reachable `x/net/http2` findings GO-2026-6603, -6610, -6611, -6612 and -6617
  from the Dex dependency graph), a new source tree and binary digest, and
  regenerated SBOM, license, vulnerability, qualification and upgrade/restore
  evidence. The qualification binary is a standalone build and no longer
  depends on MeshCore's `go.mod`. The upgrade/restore script ran only from the
  old flat layout; it now uses `core/tools/qualification/dexstorage`.
- Go 1.26.9 toolchain baseline and `golang.org/x/net` v0.60.0 (with the
  `x/crypto`, `x/text`, `x/sync`, `x/mod` and `x/tools` releases it requires).
  Go 1.26.8 and `x/net` v0.58.0 carried reachable vulnerabilities, among them
  an HTTP/2 server crash, HTTP/2 memory exhaustion and HTTP/1 connection
  desynchronization (GO-2026-6599 to GO-2026-6617). Core, relay, the
  identity broker image and the clients are built with the new release. The
  Dex workspace verifier accepts a later patch release of the qualified Go
  minor line.
- Core refuses to start, and stops being ready, on a schema older than its
  binary; run the migration before rolling out a new release. A newer schema
  is still accepted, so a rollback is still a binary rollback.
- Core opens its PostgreSQL connections with join_collapse_limit and
  from_collapse_limit 4 (default 8). Searching the join orders of the
  authority functions cost 40-210 MB of planner memory on a backend's first
  call, kept until the connection closed; the largest growth one statement
  now causes is ~24 MB, and no measured statement plans worse. The platform
  integration run fails when one statement grows a backend by more than
  `PLATFORM_PG_MEMORY_GATE_MB` (64; core/tools/pgmemgate).
- Core schema 150: publishing a policy with shared Devices no longer takes
  ~210 MB of PostgreSQL planner memory per backend (it took a POC database
  at its memory limit down); the attach statement keeps its written join
  order. Publishing 3,000 shared rules takes under a second and ~30 MB.
- Core schema 151: a Device is shared into a Network at most once. A second
  live share gave the Device a second alias there and made the maps of both
  Devices invalid once rules used it; accepting one now fails with MT013
  (409 `device_already_shared`).
- MTRP MTT2 tickets (share scale step 5): a relay ticket commits to up to
  16,384 zones by digest and carries the first 32 inline; the node sends the
  rest in ZONES frames, and the relay puts the ticket in force once the list
  matches. Relays bound zones per session and relay-wide, and recheck a route
  by the zone that opened it. Core issues MTT2 to nodes in more than 31 Trust
  Contracts that negotiated `relay.zones2`, once
  `MESHTRANSIT_RELAY_TICKET_ZONES_V2` is on, so every share (up to 10,000)
  can use relays instead of the oldest 31. meshd declares `relay.zones2`.
- Core schema 149 (share scale step 4): the share map readers choose shares
  from the Device's own targets and rules (alias v6, dependencies v4) instead
  of scanning every endpoint or contract, so a providing Device's map no
  longer grows with the deployment's shares and a receiving Device's cost is
  linear. `MESHTRANSIT_CONTROL_MAP_SHARE_STATEMENT_TIMEOUT` (10 s) bounds the
  share readers of a map: a Device receiving 10,000 shares reads them in
  about 5 s. Opt-in load test: `PLATFORM_SHARE_SCALE=N`.
- meshctl down and logout (TD-CLI-04): down keeps the machine off the network
  across restarts until up; logout revokes the Device through MTCP Logout and
  gives the profile new keys, so up enrolls it again. Local API: POST /v1/down,
  /v1/up and /v1/logout.
- Core schema 143 (TD-CORE-14): a revoked Device's addresses go through a
  24-hour quarantine, then registration reuses them.
- meshnetd keeps a handed-over utun descriptor until meshd has received it,
  which fixes utuns that reached meshd unable to deliver packets on macOS.
- Merged Core, meshd and meshctl into one repository with per-directory
  licensing (core/ AGPL-3.0, client/ Apache-2.0).
- Protocol specifications for disco v2, MTRP v1, keys, NAT classification and
  the network threat model (docs/protocol).
- shared/key, shared/disco and shared/mtrp: key types, disco v2 and MTRP v1
  codecs with cross-checked test vectors and fuzz tests.
- shared/stun (RFC 8489/5780 codec) and shared/netcheck (NAT classification).
- test/natlab: in-memory NAT simulator, RFC 5780 STUN server, reference
  traversal agent and a generated traversal matrix.
- MTCP v1 specification (the MeshTransit control protocol) and its
  protobuf schema in api/mtcp/v1.
- Client enforcement evidence (R1-69): policy digest v1 (shared/policydigest,
  docs/protocol/policy-digest-v1.md); meshd reports the digest of the rules
  its packet filter enforces; Core compares it with the delivered filter and
  reports enforced, applying, mismatch or not_reported per Device.
- shared/mtcp (P4a): MTCP v1 records, Noise IK handshake between machine and
  control keys, encrypted session, fragmentation with bounded zstd, proofs of
  possession and control key fingerprints; Go types generated from
  api/mtcp/v1 without protoc (hack/protogen, `make proto`); test vectors
  cross-checked by an independent Python implementation.
- Enforcement evidence ledger (R1-69, schema 136): the enforcement-ledger
  worker records per-Device enforcement intervals, seals
  device.enforcement_mismatch and device.enforcement_restored on the Network
  audit stream, and GET …/devices/enforcement-history?at=T answers what each
  Device enforced at an instant.
- Core MTCP v1 endpoint (P4b, schema 137): with
  MESHTRANSIT_CONTROL_MTCP_ENABLED the control listener serves /mtcp/v1
  (HTTP upgrade), /mtcp/v1/ws (WebSocket fallback) and /mtcp/v1/key beside
  the legacy protocol, with the same control key. Admission before Noise, durable
  ClientHello timestamps per bound machine key, one session per machine
  key, map snapshots and deltas with an acknowledgement window, KeyUpdate,
  Lifecycle, relay tickets, endpoint and enforcement reports. Registration
  over MTCP follows in P4c.
- Registration over MTCP (P4c, schema 138): enrollment keys and browser
  approvals with resume handles, node key rotation, and Logout, which
  revokes the Device and records device.logged_out.
- meshd speaks MTCP v1 (P4d): mtcpclient registers, rotates node keys and
  streams maps over MTCP with a WebSocket fallback; `--control-protocol
  auto|mtcp|legacy` (default auto: MTCP where the control server offers
  it). Profiles keep their keys across protocols; `meshctl up
  --fingerprint` also accepts the `ck=` value of enrollment links.
- Turned off the legacy control protocol on the POC control server (P4e):
  meshd speaks MTCP only.
- Path reports (P4f): meshd reports per peer whether traffic goes direct or
  through which relay, why (`relay_reason`) and byte counters; Core keeps
  the latest report per Device and the Console Devices page shows it in a
  Connection column. The MTCP key document gains each key's `ck=`
  fingerprint, used by the Console install command.
- Port mapping (P5a): meshd asks the local gateway to forward its WireGuard
  port with PCP, NAT-PMP or UPnP IGD (`--port-mapping=auto|off`, default
  auto), renews and verifies the mapping, removes it on exit, and publishes
  it as a `port_mapping` candidate when its external address is public.
  `meshctl status` and `meshctl netcheck` show it. The NAT lab supports
  explicit mappings; symmetric/symmetric pairs go direct when one side maps.
- Cloud public addresses (P5b): on AWS (IMDSv2), GCP, Azure and DigitalOcean,
  recognised from DMI data, meshd reads the instance's public addresses from
  the metadata service and offers them as static candidates with the
  WireGuard port (`--cloud-metadata=auto|off`). `meshctl status` and
  `meshctl netcheck` show them.
- IPv6 hardening (P5c): IPv6 host candidates follow the kernel's address
  state (no tentative, duplicate or deprecated addresses; privacy addresses
  only without a stable one; at most four); CALL_ME_MAYBE sets the port
  mapped and global IPv6 flags; a peer pinging from a known address while no
  path is proven gets an immediate probe, so stateful IPv6 firewalls open
  together. meshrelay gains `--public-ipv6` for RFC 5780 attributes to IPv6
  clients. The NAT lab has IPv6 STUN and firewalled IPv6 nodes; two IPv6
  hosts behind address-and-port-dependent firewalls go direct, also when
  Core publishes no endpoints and only CALL_ME_MAYBE carries them.
- Connectivity on the Console (P5d): meshd reports its NAT classification,
  IPv6 reachability and gateway port mapping state in `EndpointReport`
  (`nat.report1`, new `port_mapping` and `nat_observed_ms` fields); Core
  stores the latest per Device and session when it changes, and the device
  distribution API returns it as `connectivity`.
- Private Interchange (P5e): a Workspace registers its own relays
  (`meshrelay --private-interchange`) and grants each to some of its
  Networks (schema 139, `interchange.read`/`interchange.manage`, management
  API under `/api/v1/workspaces/{id}/interchanges`, audit events
  `interchange.created|updated|deleted` and Network wake events). Core signs
  a relay map per Network with the granted regions marked preferred,
  accepts them as home relays, renews node grants when a Network's relays
  change, and serves each relay its grant sealed to its key at
  `/relay/v1/grant`.
- meshd prefers Private Interchange regions as its home relay (P5f): it
  leaves a preferred region only when that region fails and returns when it
  recovers.

- Relay revocation within seconds (P7): Core checks revocations every
  second and signs a new relay state at once when they change; relays hold
  a long poll (`GET /relay/v1/state?wait=N`, N ≤ 25 s) and apply it as soon
  as it is signed, falling back to 10-second polls against a Core that does
  not hold polls (mtrp-v1 §9).
- Fuzz targets for the MTCP handshake, session records, message records and
  packet filter digest, meshd's map state and cloud metadata parsing, and
  `hack/fuzz-long.sh` to run every fuzz target for a set time.

- Relay failover within seconds (P7): a meshd relay session that hears
  nothing for 1.2 s probes its relay every 0.8 s and declares it dead after
  three unanswered probes; the failure re-chooses the home relay at once,
  and a failed home relay connection is replaced on the first observation
  instead of after two missed refreshes (was up to about a minute).
  A home relay change now moves on the live relay pool instead of
  recreating the WireGuard device and TUN, so connected regions, WireGuard
  sessions and direct paths survive it. A peer endpoint change reloads only
  connectivity in Core (one query instead of a full map snapshot per
  stream). POC drill: silent home relay loss to a working new home in
  4.7 s, double loss to the next region in 5.9 s.
- The relay accepts its key as a systemd credential (`LoadCredential=`,
  mode 0440 inside `$CREDENTIALS_DIRECTORY`); elsewhere the key file must
  still be 0600.
- Core scale-out, step S1 (schema 140): each control replica reads a
  Network's live Devices once per revision into a shared, immutable,
  hash-indexed inventory (singleflight per Network) and builds every
  stream's map from it instead of one peer-candidate query per Device.
  `MESHTRANSIT_CONTROL_MAP_SHARED_INVENTORY` (default true) and
  `MESHTRANSIT_CONTROL_MAP_INVENTORY_STATEMENT_TIMEOUT` (30 s) control it.
  Metrics: `meshtransit_map_snapshots_total{source}`,
  `meshtransit_map_inventory_reads_total`,
  `meshtransit_map_inventory_policy_mismatches_total`. Snapshot build for
  10,000 peers: 312 ms to 96 µs.
- Core scale-out, step S2 (schemas 141, 142): the inventory carries the
  Network's packet policy at selector level (Device, Device Group, Identity
  Group, tag) and expands it per Device in O(rules + output) without
  pairing group members. A revision wakeup refreshes a running stream
  entirely from the shared view (no per-Device transaction); Devices with
  direct shares or that left the view still take the full read. Integration
  tests require the shared and derived maps to equal the direct read.
  Coalesced stream wakeups keep the highest announced revision so a refresh
  never settles for an older view. Scale test at 2000 Devices: revision
  fan-out p95 1.6 s to 404 ms, Postgres pool wait down 11x, stream opens
  59/s to 95/s. Metric `meshtransit_map_snapshots_total{source="derived"}`.
- Less memory per control session: the MTCP record reader starts with a
  1 KiB buffer and grows only for a large record (it held 64 KiB per
  session), the browser-approval watcher starts only when an approval is
  pending (it was a goroutine and a ticker per session), and a stream of
  one Network reads its wakeup sources directly instead of through a
  forwarding goroutine. 2000 sessions: heap 212 MB to 104 MB, RSS 934 MB to
  563 MB, goroutines 10,016 to 6,016. `MESHTRANSIT_PROFILE_ADDRESS` serves
  pprof on loopback for operators.
- Cheap reconcile (scale-out S6): a reread of a Network's shared view that
  finds exactly the same Devices, policy and header keeps the previous
  objects, and a stream's periodic refresh first asks whether its snapshot
  still comes from that latest view (same objects, revision, policy
  revision, header and relay directory, no deadline near). If so it only
  moves to the latest connectivity, in O(1), instead of rebuilding the map;
  the Network is still read once per reconcile interval per replica, so
  changes that do not advance the revision are caught as before. Metric
  `meshtransit_map_snapshots_total{source="unchanged"}`.
- Peer limit (scale-out S6): a map carries at most
  `MESHTRANSIT_CONTROL_MAP_PEER_LIMIT` peers (default 10,000). A Device
  authorized for more receives explicit Device shares first, then peers
  online now, then a stable order; a change of the chosen peers at the same
  revision is sent as an authority delta. The delivery record keeps
  `peer_limit` (sent of authorized), the Devices page shows "Peers limited",
  and the policy preview (also when too large to preview Device by Device)
  returns `peer_estimate`: the largest number of peers one Device would see
  and how many Devices pass 5,000 and the limit, counted per rule side
  without expanding group rules. Connectivity reads for a map are batched,
  so a Device authorized for more than 10,000 peers no longer fails.
- Core scale-out, step S5 (scale-out): control replicas publish their
  MTCP session counts to a Redis registry (`meshtransit:v1:control:replicas`,
  expiry by Redis time); a replica above its fair share sheds a bounded
  number of sessions per step with Lifecycle RECONNECT and a jittered
  retry, so new replicas fill up and the load evens out. Shutdown tells
  every session to reconnect within `MESHTRANSIT_CONTROL_DRAIN_WINDOW`
  instead of all at once. `GET /scale/v1/sessions` on the health port
  answers the cluster total for KEDA's metrics-api scaler; the chart's
  `autoscaling.provider: keda` renders a ScaledObject (CPU, plus sessions
  for control) and leaves the replica count to the autoscaler. The session
  cap may go to 16384. The Redis ACL needs the registry key and `HGETALL`,
  `HDEL`. Scale test: 1000 sessions on one replica settle at 545/455 on
  two in 13 s with exactly 455 reconnects.
- Core scale-out, step S3: each control replica keeps one connectivity
  table per Network with streams, a persistent hash array mapped trie of
  Node to endpoints, home relay and presence, versioned with a bounded
  change log. One worker per Network reads a burst of wakeups from Redis in
  one call and wakes each stream once; a stream moves to the new version
  and builds its delta from the logged Nodes alone. A connectivity change
  costs one Redis read per replica and about 3 µs per stream regardless of
  the Network's size (was a full peer reread and map rebuild per stream,
  6 ms at 5000 peers before Redis). Tables are reread every reconcile
  interval and after a mailbox overflow to repair lost wakeups.
  `MESHTRANSIT_CONTROL_MAP_SHARED_CONNECTIVITY` (default true); metrics
  `meshtransit_map_connectivity_*`. Scale test at 2000 Devices, switch off
  vs on: connectivity fan-out p95 190 ms to 41 ms, Redis connectivity
  reads 266,870 to 5,180, stream opens 95/s to 540/s, process CPU 56 s to
  38 s, and no coalesced (possibly lost) wakeups.
- Core scale-out, step S4: a hostname family may hold 200,000 names (was
  1024); the outbox worker coalesces deliveries per Network and drains
  full batches back to back (batch 32, poll 200 ms); the Postgres pool
  waits for released connections on shutdown. Scale test at 2000 Devices
  in one Network: 26 registrations/s, revision p95 1.6 s.

### Fixed

- A Device registering into a Network with no free address was told to
  retry every two seconds, forever; it is now rejected (NOT_PERMITTED,
  "the Network has no free address") and meshd reports it.
- Rebalancing no longer moves sessions younger than 30 seconds: it could
  end a session in the middle of a registration, and move a node that had
  just arrived.

- meshd reported `control_session: synchronized` while Core was
  unreachable: the MTCP stream reconnects internally and kept the last map
  without telling the daemon. The stream now reports losing and regaining
  its control connection, and the status reads `reconnecting` meanwhile
  (the last map and the tunnels stay up; the daemon stays online).

- Core scale test findings (opt-in `TestRoleControlProcessScalesMapStreams`,
  `MESHTRANSIT_SCALE_SESSIONS=N`): address allocation scanned only the first
  256 addresses of a prefix (the candidate limit), so a Network stopped
  registering Devices at about 253 per prefix with a retryable "registration
  unavailable". Postgres now finds the lowest free address under the
  allocator lock and the search starts there. MTCP map stream ends are
  counted in `meshtransit_mtcp_map_stream_ends_total{reason}` and logged
  when control ended them (they were silent). Per-source MTCP handshake
  admission is configurable (`MESHTRANSIT_CONTROL_MTCP_HANDSHAKE_RATE`,
  `_BURST`; defaults 10/s, 50) for sites where many Devices share one NAT.
- Relay authority hardening (security review): Core rate limits relay
  endpoints per IPv4 address or IPv6 /64 and evicts the least recently seen
  source when its table is full, instead of refusing every new source for
  a minute (one host could lock relays out of revocations); a source holds
  at most four long polls; a data race on the signing window of Network
  maps and grants is gone; a connectivity-only map refresh never issues a
  new relay grant (the full refresh checks the Device first). The relay
  reads no session before its first relay state (bounded wait of 20 s),
  retries a failed poll after about a second instead of 20 s, and backs off
  on persistent UDP read errors.
- Relay failover review: a relay health snapshot naming a region the home
  selector had not been given yet stopped the whole meshd session; only the
  home region's loss triggers a discovery round; the failure hook is in
  place before the home region is dialled.
- A peer endpoint change no longer drops the node's relay grant: the
  connectivity-only reload rebuilt the snapshot without the grant, and the
  node then lost every relay until its next full refresh.
- Every response of the browser auth and management servers carries
  `Cache-Control: no-transform` (plus `no-store` when the handler set none),
  so a proxy in front never compresses responses holding secrets (BREACH).
  Inventory, distribution and session scope responses had no Cache-Control
  and were compressed by Cloudflare.
- Outbox events without a Network scope (identity, session, deployment and
  Workspace events) have no consumer and stayed pending forever, so the
  outbox backlog only grew. The worker role's new outbox-unrouted-retirer
  closes them every minute as `terminal` with error class `no_consumer`,
  keeping the rows; Network revision events are untouched.
- Control key expiry is observable: the control role exports
  `meshtransit_mtcp_control_key_not_after_timestamp_seconds` (latest key) and
  warns in its log 60 days ahead instead of 30.
- Control key rotation without re-enrolling Devices (mtcp-v1 §11). Core
  takes a next key (`MESHTRANSIT_CONTROL_NOISE_NEXT_PRIVATE_KEY_FILE`,
  `MESHTRANSIT_CONTROL_MTCP_NEXT_KEY_NOT_AFTER`), lists it in `/mtcp/v1/key`
  and in every KeyUpdate, and answers handshakes made with it. meshd stores
  the announced next key in its encrypted identity record and switches to
  it when Core stops offering the current key, during a session or, after
  being offline, at its next connection. Records with a staged next key
  cannot be read by older meshd builds.

### Removed

- The legacy control protocol and the third-party protocol library it used
  (P6). Core's control listener (`core/internal/adapter/controllistener`)
  serves only MTCP v1 and the relay authority; other paths answer 404.
  MTCP is always on and needs `MESHTRANSIT_CONTROL_MTCP_KEY_NOT_AFTER`;
  `MESHTRANSIT_CONTROL_MTCP_ENABLED` may only be `true`, and
  `MESHTRANSIT_CONTROL_MAX_STREAMS_PER_SESSION`, `_PING_TIMEOUT` and
  `_WRITE_TIMEOUT` are refused. meshd speaks only MTCP:
  `--control-protocol` accepts `auto` or `mtcp`, and `legacy` is refused.
  STUN probes use `shared/stun` without a SOFTWARE attribute.
  `make check-boundaries` fails when go.mod requires a module missing from
  the reviewed allowlist `hack/allowed-modules.txt`.

## meshd (before the merge)

### Unreleased

### Added

- v0.1 release contract, platform priority, native validation matrix, and
  operating-system adapter boundaries.
- Linux quality, vulnerability, opt-in CodeQL, and cross-platform build
  workflows with pinned action and tool versions.
- Digest-bound CycloneDX SBOMs and symbol-aware Grype reports for Linux
  packages, with checksum-pinned tooling and a High/Critical CI gate.
- Go 1.26.8 toolchain baseline.
- Reproducible amd64/arm64 Debian package builder with hardened split-privilege
  systemd services and package lifecycle scripts.
- Debian service-state preservation across upgrade, removal, and reinstall,
  alternate-root-safe purge behavior, and disposable package lifecycle tests.
- Bounded Linux restart qualification for service, TUN, MeshTransit DNS, and dual-stack
  traffic recovery, with redacted machine-readable reports and parser fixtures.
- Bounded two-node Linux reboot qualification for service, route, identity,
  MeshTransit DNS, and dual-stack traffic recovery with explicit target confirmation.
- Linux route/link/address monitoring with bounded netlink event coalescing,
  polling fallback, immediate endpoint refresh, redacted status counters, and a
  reversible network-change qualification harness.
- Bounded Linux direct-path loss qualification with UDP-only peer isolation,
  measured relay fallback, dual-stack relay traffic proof, direct recovery, and
  automatic nftables cleanup.
- Linux host-policy qualification now records bounded `meshd` memory evidence
  and fails a phase if the service restarts on either node.
- WireGuard peer sessions now survive control-map endpoint-authority refreshes;
  stale direct selections return to the relay path without replacing the peer.
- Separate owner-writable runtime directories for the operator API and
  privileged-helper sockets.
- Initial daemon composition root.
- Atomic profile store with one-active-profile enforcement.
- Versioned local Unix-socket API for health, status, profile creation, listing, and selection.
- Initial architecture and security model.
- Pinned capability-142 adapter for bounded HTTPS control-key and authenticated Noise-handshake probes.
- BSD 3-Clause attribution for the compatibility dependency.
- Fail-closed Linux local API authorization based on kernel `SO_PEERCRED` credentials.
- Optional Linux socket-group authorization for kernel-verified local callers,
  plus service-account resolution for the privileged helper.
- Per-profile persistent machine/node identities with confined, atomic `0600` storage.
- Explicit control-key fingerprint pinning with Noise possession verification and no implicit rotation.
- Pinned Noise HTTP/2 registration, transient auth-key login, and persisted same-origin browser follow-up.
- Local API status fields and endpoints for control trust and registration.
- Pinned capability-142 network-map streaming with frame bounds, watchdog deadlines, and bounded jittered reconnect.
- Upstream-independent validated network snapshots with atomic delta updates and deny-by-default policy state.
- Control-session, netmap-revision, and peer-count status fields.
- Process-local aggregate runtime-recovery status for native fault qualification.
- Bounded, reversible Linux helper-socket fault qualification that requires
  in-process TUN and DNS recovery without a service restart.
- Fail-fast repeated Linux local-runtime recovery qualification with per-sample
  resource invariants, bounded kernel-resource convergence, and redacted
  nearest-rank p95 recovery timings; explicit peer routes and global self
  addresses are checked independently from address-derived kernel routes, and
  aggregate peer-count changes are classified as topology changes.
- Traffic-bearing Linux local-runtime recovery qualification with continuous
  IPv4, IPv6, and uncached MeshTransit DNS probes, mandatory outage observation,
  stable-recovery timing, and nested per-sample runtime/resource validation.

### Changed

- Authenticated direct paths now keep only their remaining proof lease across
  otherwise identical control-map revisions. Routine endpoint publications no
  longer force a relay fallback and immediate re-promotion, while lease expiry,
  socket changes, and peer or endpoint-authority changes still fail closed to
  the signed base path.
- Signed peer home-relay changes now replace the retained fallback metadata
  without overwriting a compatible authenticated direct endpoint. The existing
  proof deadline is unchanged, and expiry restores the newest signed relay
  base while identity, route, authority, socket, and topology changes retain
  fail-closed behavior.
- A temporary local map-application failure now tears down TUN, routes, DNS,
  path probes, and session secrets before the daemon retries from a fresh full
  snapshot. Recovery uses interruptible jittered exponential backoff capped at
  thirty seconds; a profile or registration change bypasses the wait, while
  permanent control trust and protocol failures remain blocked. An ambiguous
  cleanup exits the supervisor instead of reusing uncertain local state.
- Control-map reconnect backoff now resets only after a validated stream stays
  established for thirty seconds, preventing rapid map-then-disconnect loops
  from holding retries at the minimum delay. The watchdog and reconnect policy
  now have deterministic transport-fault coverage.
- Browser-login completion treats bounded transport timeouts, truncated
  exchanges, HTTP 408/425/429, and HTTP 5xx as temporary. Pending state is
  retained, both pending responses and temporary failures consume the
  three-second completion window to throttle retries, and caller cancellation
  still wins immediately. A verified response that races the poll deadline is
  persisted under the caller context instead of being discarded, temporary
  key copies are cleared after registration, and trust or protocol failures
  remain terminal.
- Control supervision now enforces one active runner per daemon service, and
  browser/auth-key registration transitions are serialized with cancellable
  waiting so concurrent local clients cannot create duplicate control sessions
  or reuse the same pending authorization concurrently.
- Linux host-credential provisioning and staged key rotation now tolerate an
  ambiguous return after directory synchronization: retries verify and accept
  the completed state without generating another key or deleting recovery
  material early.
- Top-level online status now reflects a synchronized control session even for
  a peerless Network; data-plane and DNS readiness remain separate fields.
- Compatible peer and policy changes now replace WireGuard peers, relay peer
  authority, and helper-confined host routes without recreating the TUN or UDP
  transport. The privileged route operation is bound to an interface opened by
  the same helper generation, requires unchanged self addresses, and rolls
  completed netlink changes back on failure. Live peer updates omit the private
  key and listen port so the userspace engine cannot rebind its socket.
- Peerless reduced maps now install an empty peer and route configuration while
  retaining the encrypted UDP presence transport. Socket-generation changes
  replace endpoint advertisements only after current-socket discovery, and
  periodic discovery pauses while no peers are visible. This prevents
  transient endpoint withdrawal from driving control-map and tunnel churn.
- Successful network-triggered endpoint refreshes are counted before their
  resulting endpoint update becomes observable.
- Semantically unchanged control-map deltas are revalidated without publishing
  a new local generation, avoiding unnecessary probe, data-plane, and DNS
  reconfiguration while preserving expiry enforcement and reconnect isolation.

## meshctl (before the merge)

### Unreleased

### Added

- `meshctl up`: one idempotent command that finds or creates the profile,
  activates it, pins the control key (built-in for MeshTransit Cloud) and
  registers, waiting for browser approval.
- Linux quality, vulnerability, opt-in CodeQL, and cross-platform build
  workflows with pinned action and tool versions.
- Go 1.26.8 toolchain baseline.
- Reproducible amd64/arm64 Debian package builder and package inspection gate.
- Initial `status`, `version`, and profile commands.
- Versioned Unix-socket client with bounded JSON responses.
- Human-readable and JSON output modes.
- Stable usage and runtime exit-code separation.
- `doctor control` command for capability and control-key fingerprint checks.
- Explicit control-key trust with an operator-supplied SHA-256 fingerprint.
- Browser and standard-input auth-key login workflows.
- Bounded browser-login waiting with automatic completion, cancellation, and
  resumable timeout behavior.
- Control-trust, registration, and pinned-key status fields.
- Control-session, validated netmap-revision, and peer-count status output.
- Aggregate direct/relay path counts and redacted relay-region health.
- Aggregate host-network-change and completed endpoint-refresh status counters.
- Aggregate daemon runtime health in human-readable and JSON status output.
- Process-local runtime failure, completed recovery, and pending status with
  backward-compatible handling of older v1 daemons.
