# Phase 2 M5a: interactive Mesh Client registration contract

Status: schema migrations 59–71 and the Workspace-first browser flow pass the
full Go and PostgreSQL/Redis integration gates. The private login page checks
the SSO cookie, requires an explicit Workspace choice, lists eligible Networks
in that Workspace, and accepts an origin- and CSRF-checked approval POST.
PostgreSQL rechecks the exact chosen Workspace/Network pair at approval and
completion, commits one Device with keys and IP leases, and replays a lost
success response to the same Noise machine. Audit and outbox evidence commit
with each mutation. The schema-71 POC artifact is deployed; both clients from
the earlier real registration gate remain online and synchronized. See the
qualification sections below for the exact scope of evidence.

Date: 2026-10-01

## Pinned client observation

`meshd` commit `484cb397cde7d1a9e199035cd1360127189319c2` sends capability 142
`POST /machine/register` over the pinned Noise connection. With no auth key,
the first request has no `Auth` object, a zero `OldNodeKey`, and an empty
`Followup`. When Core returns `AuthURL`, the client validates HTTPS, port 443,
the exact control origin, no query or fragment, and a path containing
`/register/`. It persists that URL and sends it back as `Followup` on bounded
completion polls. The client never sends a Network ID. An authorized response
must set `MachineAuthorized` and omit `AuthURL`; a pending response does the
opposite. Node-key rotation also has no `Auth`, but carries a nonzero old Node
key and must remain a separate, machine-authenticated operation.

## Required authority and state

1. The Noise-proven machine key and requested Node key bind one pending browser
   intent before a Network is known. The intent has a 256-bit URL token and
   stores only its purpose-separated digest as a lookup key. To reproduce the
   same URL on an initial-request retry, derive that token with a dedicated
   HMAC key from a random, persisted 256-bit intent nonce and immutable intent
   identity. Store the key ID, retain a previous key until every issued intent
   expires, and never treat the nonce or public ID alone as a bearer. The
   intent expires on a bounded deadline. Repeating the same machine/Node
   request converges on the same active intent and URL.
2. The browser opens the exact same-origin `/register/` URL. Existing Core SSO
   establishes a human Account Session when needed. A GET is read-only and
   `no-store`. The first page requires an explicit Workspace choice; the second
   page lists only that Workspace's eligible Networks. These GET choices do not
   mutate authority. Connecting the exact Workspace/Network pair is a
   CSRF-protected POST; neither stage automatically selects its only option.
3. The chooser lists only active Networks with current, exact enrollment
   eligibility for that Principal. Even with one eligible Network, the browser
   confirms the exact choice. A browser-supplied Network ID is a choice,
   never authority. The final POST rechecks active Account, Session, Workspace,
   Network membership, Enrollment Profile, recovery epoch, and any Device Group
   assignment ceiling inside the committing transaction. Administrative
   management-scope projection is not enrollment eligibility.
4. Browser approval records the exact Principal, Network, profile, machine key,
   Node key, expiry, and one-use result with audit and outbox evidence. No IdP
   token, Console cookie, or browser bearer reaches `meshd`.
5. A `Followup` poll must match the exact issued URL and the same Noise machine
   and Node keys. Pending returns the same `AuthURL`. Authorized commits or
   replays one Device registration in the selected Network. Expired, rejected,
   mismatched, or stale authority fails closed without changing Network.

Core's current `mesh.pending_registration` already reserves interactive
authorization fields but requires Network and Enrollment Profile from creation.
The pre-choice intent therefore has separate durable state in migration 60.
Migration 59 adds exact Network enrollment membership, and migration 61 adds an
explicit, default-off interactive Enrollment Profile gate. Migration 62 reads
only Networks meeting these gates for a current Account Session. Migration 63
issues or reuses one active machine-bound intent under the current Deployment
recovery epoch and rejects a changed Node key. Neither a
Workspace membership nor a management role is Network enrollment permission.
Migration 64 admits a follow-up read only when the URL token, authenticated
machine, Node key, hostname, Deployment, and recovery epoch all match.
Migration 65 admits the browser landing read only when both the URL token and
a current SSO Account Session match the Deployment and recovery epoch. The
read reveals only the request hostname, state, and expiry.
Migration 66 locks and rechecks the exact pending intent, SSO Session,
membership, Network, and interactive Profile at approval. Migration 67 commits
the authorized pending registration and its immutable approval Session and Network links;
the adapter appends matching audit/outbox evidence before commit.
Migration 68 locks an approved Followup under the exact Noise machine/Node
identity and rechecks the recorded Session, membership, Profile, Network, and
request hash. The adapter commits Device, key epochs, IP leases, revision,
intent completion, and audit/outbox as one transaction. A bounded replay read
uses the immutable approved Workspace and Network to restore RLS scope and
returns only an already committed, still-active Device to the same machine.
Migrations 59–68 were deployed to the POC for the first two successful real
client registrations. Existing legacy Network records cannot be inferred to
exist in MeshCore.

### Workspace-first selection

The approved product flow allows an account to hold several unrelated Workspace
memberships, including membership in a Workspace owned by another account.
Ownership is not a listing or enrollment condition. A pending invitation must
first become an active membership; the chooser itself never accepts an
invitation or creates membership.

Migration 69 adds a bounded Session-bound Workspace list and a Network list with
an explicit selected Workspace. The current Session provider/client must be
accepted by the target Workspace's active route with matching minimum ACR.
Organization-bound routes fail closed because the current Session stores no
matching organization evidence. A Workspace requiring a different SSO route is
not admitted by this Session. The original login context is not changed.

Migration 70 adds version 2 approval functions with an explicit Workspace
filter, exact Network membership and current target SSO-route locks. Migration
71 reauthorizes completion using the immutable approved Workspace/Network pair,
including target membership, route, assurance, Session and recovery fences.
Version 1 functions remain unchanged for the supported rollback artifact.
Both stages use deterministic public-ID cursors and bounded pages; returning to
the Workspace stage removes the prior Network choice.

The browser POST carries `csrf`, `workspace` and `network`. These public IDs are
untrusted filters. The Noise registration and Followup wire contracts remain
unchanged, and the client never sends a trusted Workspace or Network ID.

This follows the custom Headscale behavior observed in the local reference:
the server derives eligible Networks from membership, the browser chooses one
after SSO, and the client carries no Network ID. Headscale's earlier behavior
of selecting the first Network from multiple memberships was removed.

The original POC baseline used MeshCore Network authority. At schema 58, it had one
active Workspace Membership for Principal 11 and one active Enrollment Profile
for Network 201, owned by the same Principal. Migration 59 creates an empty
Network Membership table, and migration 61 defaults interactive enrollment to
disabled. The operator must explicitly grant that Principal membership in
Network 201 and enable the interactive profile before choices appear. The
Console management-scope result cannot grant this eligibility.

## Trust boundaries and STRIDE review

Assets are the machine/Node identity, browser intent bearer, Account Session,
Network membership, Enrollment Profile, Device identity and address, and audit
evidence. Attackers may control an unauthenticated client request, a browser
navigation, a stale or stolen URL, a different authenticated Account Session,
or a competing client using another Noise machine key. Core and PostgreSQL are
the authority boundary; Redis and the browser are not.

| Threat | Required guard |
| --- | --- |
| Spoofing | Bind every poll to the Noise-proven machine and requested Node keys; bind approval to a current SSO Account Session. |
| Tampering | Treat the selected Workspace and Network as untrusted filters; resolve exact current membership, target SSO route, eligibility and profile inside the final transaction. |
| Repudiation | Commit Principal, Session, Network, Device, decision, audit, and outbox evidence together. |
| Information disclosure | Keep the URL token out of logs, metrics, redirects, referrers, cache, diagnostics, and client map responses. |
| Denial of service | Bound bodies, pending intents, polling, chooser requests, expiry, and concurrent approvals per machine/source. |
| Elevation of privilege | Recheck membership, lifecycle, recovery epoch, and Session generations at approval and completion; a Workspace or management role alone never enrolls. |

The URL token plus a current SSO Account Session allows a browser to view a
pending request, but cannot by itself approve or complete a Device
registration. A stolen Account Session cannot
authorize a different machine intent without the exact URL and CSRF proof;
possession of both still requires current Network eligibility.

## Failure and resource bounds

- Bound request bodies, URL length, active intents per machine/source, polling
  frequency, browser sessions, and intent lifetime. Rate-limit both Noise and
  browser paths; no unbounded goroutine or in-memory authority.
- Never log token paths, raw `Followup`, keys, IdP claims, cookies, or Network
  inventory. Return `Cache-Control: no-store` and suppress ingress query/path
  logging for the token route.
- Recheck authority on completion, not just on the chooser GET. Concurrent
  approvals, retries, expiry, and replica restarts must converge on one result.
- If PostgreSQL, Redis, SSO, or the final authority check is unavailable,
  registration remains pending or fails closed. Redis is never the authority.

## Acceptance matrix

- One browser login selects one eligible Network, and `meshd` completes without
  receiving an IdP credential or sending a Network ID.
- Two independent clients can select different eligible Networks. One client
  cannot use the other's URL or machine-bound `Followup`.
- One Account Session can select different admitted Workspace memberships
  before choosing a Network. A Network in another Workspace, lost Workspace
  membership, suspended provider route or increased target assurance is denied
  at approval and completion. Workspace selection does not change the original
  Account Session login context. Pagination does not expose another account's
  memberships or another Workspace's Networks.
- No Session, wrong Principal, wrong Workspace, cross-Network choice, removed
  membership, suspended Network, stale profile, expired token, reused token,
  mismatched machine/Node, and concurrent approval are denied or converge as
  specified.
- Retry after a lost response does not create a second Device, consume another
  enrollment use, or allocate another address. Restart and two Core replicas
  retain the same outcome.
- The browser route, SQL transaction, legacy wire adapter, and a real `meshd`
  against PostgreSQL/Redis pass before POC rollout is claimed complete.

## POC real-client gate (2026-10-01)

The Linux/amd64 Core image reports config schema 25. The POC database was
upgraded from schema 58 to 68, and API/Control now use the same published
image digest. The browser-token Secret, exact Network Membership, and
interactive Profile were installed. The POC operator explicitly waived a
database backup for this rollout; this is not a production backup waiver.

Both supplied Ubuntu hosts have `meshd` active and their existing profiles
point to the reviewed HTTPS POC origin. Their installed daemon is
`0.1.0~poc62`, commit
`745db5193def2db0d8a1946eb762e75f898ddef0`. The pinned source commit is
one descendant commit later; the only changed files are license, packaging
notices, and README content. No client protocol code changed. Both existing
profiles previously reported registration `registered`, control session
`blocked`, and state `offline`. New profiles preserved those identities during
the browser-login test.

Both real clients completed SSO-bound Network selection, browser approval,
and Noise follow-up on 2026-10-01. They report `registered`, `online`, and
Control session `synchronized` on the selected POC Network. PostgreSQL has two
completed intents, two `registration.browser.approved` events, and two
`device.registered` events. Each completed intent resolves to one Device and
one IPv4/IPv6 lease pair. Current policy grants neither new Device peer access;
the observed empty peer sets do not establish packet connectivity.

The initial native form did not advance in the in-app browser. The deployed
chooser uses an external same-origin script for explicit approval, a bounded
15-second request, duplicate activation suppression, and generic unknown-outcome
feedback. It never automatically posts on page load, follows redirects, reads
cookies, or inserts response HTML. The successful response reloads the
authoritative server view. Eleven deterministic script tests and the Core
race/shuffle, vet, lint, dependency, and vulnerability gates passed. Real tests
currently cover two clients selecting the same eligible Network; different
eligible Networks and packet policy remain later qualification work.

The chart's POC browser overlay routes `/register/v1` to the API private-login
listener, admits that route through NetworkPolicy port 9443, and requires API
and Control to use the same digest-pinned Core image. It keeps the current
Console image digest. `helm lint` and rendered route/policy/image checks pass
when a candidate image digest is supplied. The POC-only
`scripts/poc-browser-registration-bootstrap` tool checks schema 68 and exact
POC scope before a mutation. `--apply` creates the Principal's Network
Membership and enables the interactive Profile with canonical audit hashes and
outbox events. It must run after the migration, from a migration-role database
connection; its default invocation is read-only.

## Workspace-first qualification (2026-10-01)

The schema-71 POC uses the Linux/amd64 artifact
`poc-browser-m5a-20261001-fix3`, digest
`sha256:c57cf2706a90a475728cd827638ae5bdd8a14987584407b6b6952b5cd7b2e14c`.
API and Control use that same digest. Both existing real-client registrations
remain online and synchronized with their previous address leases.

The browser was qualified with a fresh client intent and a current SSO Session:
it requires the Workspace step, lists the eligible Network in that chosen
Workspace, and returns to the Workspace step through Change Workspace. A single
option is not automatically selected. This UI qualification stopped before
creating another Device; it does not claim a third real-client completion.

PostgreSQL/Redis integration on schema 71 qualifies multiple active Workspace
memberships, a chosen Workspace different from the Session's original login
context, exact target Network registration and replay, and completion denial
after target membership, route or assurance changes. The live browser account
currently has one eligible Workspace; the multiple-Workspace evidence is from
disposable integration fixtures.

The first deployed Workspace query exposed an outer-dispatcher rejection: the
private server closed the connection for a valid chooser query. A real TLS
server regression test reproduces the missing response before the fix and
requires both chooser stages to return HTTP 200 afterward. The dispatcher now
admits only GET chooser requests accepted by the existing canonical page
validator; malformed queries and POST queries remain rejected before authority
reads. Full race/shuffle, vet, lint, dependency and vulnerability gates pass
for fix3. The SQL integration gate passed before this dispatcher-only fix.

## Delivery order

1. Check in a sanitized versioned client wire fixture and decoder tests for
   initial, pending, `Followup`, authorized, and malformed requests.
2. Add durable pre-choice intent and exact enrollment eligibility. Qualify
   clean install, schema upgrade, forced RLS, replay, expiry, and concurrency.
3. Add browser chooser and approval with existing SSO Session admission,
   CSRF, no-store, and final transaction reauthorization.
4. Complete Noise polling and Device registration, then qualify with two real
   `meshd` instances. Deploy only after the required database and image gates.
