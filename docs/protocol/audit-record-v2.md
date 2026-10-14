# Audit record v2 and seal v2

Draft 1, 2026-10-14. Implementation: `core/internal/domain/audit` (record and
seal), `core/internal/domain/audit/exportformat` (exports), the database
trigger in `core/migrations/000116_audit_event_seal_v2.up.sql`, and the
independent verifier `core/tools/auditverify`.

Every change Core makes to a Workspace, a Network or the Deployment is an
audit event. This document fixes how an event looks outside the database and
how anyone can check that it was not changed: the read API, exports and any
search index carry this record, so a record from any of them can be checked
against its seal without access to Core.

## 1. Principles

- **PostgreSQL holds the records and the seal chain.** A search index is
  derived data; it can be dropped and rebuilt, and no evidence depends on it.
- **The database computes the seal**, in a `BEFORE INSERT` trigger on
  `mesh_audit.audit_event`. Every writer is covered, and a writer that tries
  to fill in a seal itself is refused (SQLSTATE `23514`).
- **Records are self-describing.** Each stream belongs to one scope (the
  Deployment, one Workspace, or one Network of a Workspace) and every record
  carries that scope as public identifiers, inside the seal. Filtering a
  record by tenant needs no join.

## 2. Streams

Events are grouped into streams. A stream has a UUIDv7 `stream_id` and one
scope. Within a stream, `sequence` starts at 1 and grows by exactly 1 with
every event; Core assigns it under a lock on the stream, so a stream never has
gaps or duplicates.

Events written before seal v2 existed are `legacy_unsealed`. In a stream that
has such events, sealing starts at the first event written after the upgrade,
so the first sealed event may have a `sequence` above 1. A legacy event never
follows a sealed one.

## 3. Record

A record is a JSON object with these fields. Identifiers are canonical
lowercase UUID text; hashes are 64 lowercase hex characters.

| Field | Type | Meaning |
|---|---|---|
| `record_version` | integer | Always `2`. |
| `event_id` | UUID | The event. Unique; suitable as a document ID in an index. |
| `event_time` | string | UTC with exactly six fractional digits, `2026-10-07T04:05:06.123456Z`. It is the start of the transaction that wrote the event. |
| `stream_id` | UUID | The stream (§2). |
| `sequence` | integer | Position in the stream, from 1. |
| `workspace_id` | UUID, optional | Absent for Deployment streams. |
| `network_id` | UUID, optional | Present only for Network streams, which always have a `workspace_id`. |
| `change_id` | UUID | One change may produce several events; they share it. |
| `actor_kind` | string | `principal`, or `system` when Core acted on its own. |
| `actor_principal_id` | UUID, optional | Present exactly when `actor_kind` is `principal`. Only the identifier: a name can change and is personal data. |
| `action` | label | What happened, for example `policy.published`. |
| `permission` | label | The permission the action required, for example `policy.publish`. |
| `result` | string | `succeeded`, `denied` or `failed`. |
| `target_kind` | label | The kind of object acted on, for example `policy`. |
| `target_id` | UUID | The object acted on. |
| `correlation_id` | UUID, optional | Links events of one request. |
| `before_semantic_hash`, `after_semantic_hash` | hash, optional | The object's semantic hash before and after. A hash of 32 zero bytes is a present value, distinct from an absent one. |
| `payload_version` | integer | Version of the payload's shape, from 1. |
| `payload` | object | The payload, parsed, for display and search. Not sealed. |
| `payload_canonical` | string | For a sealed record, the exact payload text that was sealed: PostgreSQL's `jsonb` text form, 2 to 16,384 bytes of UTF-8. For a legacy record, the same text form of the payload, never sealed. |
| `integrity.status` | string | `sealed`, `legacy_unsealed`, or `seal_mismatch` (below). |
| `integrity.hash_version` | integer | `2`; absent for legacy records. |
| `integrity.previous_seal` | hash | The seal of the previous event in the stream; 32 zero bytes for the first sealed event. Absent for legacy records. |
| `integrity.seal` | hash | This event's seal (§4). Absent for legacy records. |

The read API checks every sealed record it returns and reports one whose seal
does not recompute as `seal_mismatch`, so the Console can flag it. Exports
never use `seal_mismatch`: they carry records as stored, and the verifier
decides.

A label is 1 to 128 bytes of `a`–`z`, `0`–`9`, `.`, `_` and `-`.

`payload_canonical` is the sealed form; `payload` only mirrors it. A verifier
MUST use `payload_canonical` byte for byte and MUST NOT re-serialize
`payload`: spacing and key order are part of the sealed text.

## 4. Seal v2

```
seal = SHA-256( "meshtransit/audit-event/v2" || 0x00
              || F(previous_seal)  || F(stream_id)    || F(sequence)
              || F(event_id)       || F(event_time)   || F(workspace_id)
              || F(network_id)     || F(change_id)    || F(actor_principal_id)
              || F(action)         || F(permission)   || F(target_kind)
              || F(target_id)      || F(result)       || F(correlation_id)
              || F(before_semantic_hash) || F(after_semantic_hash)
              || F(payload_version)      || F(payload_canonical) )
```

- `F(x)` is the length of `x` in bytes as an 8-byte big-endian unsigned
  integer, followed by `x`.
- A UUID is its 16 bytes, a hash its 32 bytes, a label or string its UTF-8
  bytes.
- `sequence` and `payload_version` are 8-byte big-endian two's complement
  integers.
- `event_time` is microseconds since the Unix epoch as an 8-byte big-endian
  integer.
- An absent optional field is encoded as `F` of zero bytes (the eight bytes
  `00…00`), never as zeros of the field's usual size.
- `actor_kind` is not encoded on its own: it follows from whether
  `actor_principal_id` is present.

### 4.1 Verifying a stream

Sort each stream's records by `sequence`, not by `event_time`: events of
concurrent transactions can commit in a different order than they started.
Then check that:

1. `sequence` grows by exactly 1, with no duplicates;
2. no `legacy_unsealed` record follows a `sealed` one;
3. every sealed record has `hash_version` 2 and its recomputed seal equals
   `integrity.seal`;
4. every sealed record after the first sealed one has `previous_seal` equal to
   the previous record's `seal`.

If the first sealed record's `previous_seal` is all zero, sealing starts
there. Otherwise the export begins in the middle of the chain, and the link to
earlier events is checked with an export that covers them.

What a verified export proves is limited:

- Within the export, the chain detects a changed, inserted or removed event.
- It cannot detect events cut from the **end** of a stream, nor events before
  the export's first sealed record, whose `previous_seal` is taken as given.
- The seal is an unkeyed hash. Someone able to rewrite the database could
  recompute every seal and link, so one export proves consistency, not that
  the history is the original.

Each of these needs an anchor kept outside Core: an earlier export that the
reader kept, compared with a later one over the same streams, shows any
rewrite of the events both contain.

### 4.2 Test vector

The record below has seal
`016575104ed2b058570bcfcea2bbdb826a1b7ea4f0ba0aba6f177ebbffa9429a`
(`TestSealMatchesPinnedVector` in `core/internal/domain/audit/seal_test.go`).

| Field | Value |
|---|---|
| `previous_seal` | 32 zero bytes |
| `stream_id` | `01928f6e-7a10-7000-8000-000000000002` |
| `sequence` | `42` |
| `event_id` | `01928f6e-7a10-7000-8000-000000000001` |
| `event_time` | `2026-10-07T04:05:06.123456Z` |
| `workspace_id` | `01928f6e-7a10-7000-8000-000000000003` |
| `network_id` | `01928f6e-7a10-7000-8000-000000000004` |
| `change_id` | `01928f6e-7a10-7000-8000-000000000005` |
| `actor_principal_id` | `01928f6e-7a10-7000-8000-000000000006` |
| `action` | `policy.published` |
| `permission` | `policy.publish` |
| `target_kind` | `policy` |
| `target_id` | `01928f6e-7a10-7000-8000-000000000007` |
| `result` | `succeeded` |
| `correlation_id` | absent |
| `before_semantic_hash` | absent |
| `after_semantic_hash` | 31 zero bytes then `01` |
| `payload_version` | `1` |
| `payload_canonical` | `{"reason": "maintenance window", "revision": 7}` |

## 5. Exports

The Console's Activity page exports a Workspace's or a Network's events. It
calls `GET /api/v1/workspaces/{workspace}/audit-events/export`, an operation of
the Console's private API: it needs a signed-in browser Account Session, not
an API token. Its query parameters, each at most once, are `format` (`json` or
`csv`, default `json`), `network_id`, `since` and `until`.

- The caller needs `audit.export` on the Workspace, or, for an export of one
  Network, on the Workspace or that Network. Without it the answer is 403
  `permission_denied`.
- An export holds the Workspace's streams, or the one Network's stream;
  Deployment streams are never exported.
- `since` and `until` are RFC 3339 times; the window holds events with
  `since <= event_time < until`. Without `until` it ends now; without `since`
  it covers the 90 days before `until`. A window longer than 93 days answers
  400 `invalid_request`.

An export holds **every** event of the scope in the window, oldest first, with
no content filters: a filtered file would have sequence gaps that a verifier
cannot tell apart from deleted events. An export holds at most 10,000 records
and about 14 MiB; a larger window answers 422 `audit_export_too_large` instead
of a truncated file, and the caller asks for a shorter one.

An export is read in chunks of 500 records, each in its own transaction, so it
is not a snapshot. `event_time` is when a transaction started, and the event
becomes visible only when that transaction commits: an export of a window
that ends now can miss events that commit while it runs, which a later export
of the same window includes. Export adjacent windows that ended some minutes
ago to cover a period completely.

### 5.1 JSON

```json
{
  "export_version": 1,
  "generated_at": "…",
  "workspace_id": "…",
  "network_id": "…",
  "since": "…",
  "until": "…",
  "record_count": 2,
  "actors": {"<principal id>": "<display name>"},
  "Records": [ … ]
}
```

`generated_at`, `since` and `until` are RFC 3339 UTC times with as many
fractional digits as needed (not the fixed six of `event_time`). `network_id`
is present only for a Network export. `actors` maps principal IDs to display
names for the principals who are or were members of the Workspace; it is
informative and not sealed, and a principal of another Workspace (§6) is not
in it. `Records` (capitalized) holds the records of §3, oldest first, and
`record_count` is their number.

### 5.2 CSV

One header row, then one row per record, with these columns in this order:

```
event_time, event_id, stream_id, sequence, workspace_id, network_id, change_id,
actor_kind, actor_principal_id, actor_name, action, permission, result,
target_kind, target_id, correlation_id, before_semantic_hash,
after_semantic_hash, payload_version, payload_canonical, integrity_status,
hash_version, previous_seal, seal
```

Cells are quoted as in RFC 4180 where needed, and rows end with a line feed.
An absent optional field, and `hash_version`, `previous_seal` and `seal` of a
legacy record, is an empty cell. Every sealed field is a column, so a CSV
export verifies like the JSON one.
`actor_name` is informative and not sealed; when it starts with `=`, `+`, `-`,
`@`, a tab or a carriage return, the export prefixes it with `'` so that a
spreadsheet does not run it as a formula. Sealed cells are never rewritten.

## 6. Sharing decisions

A share joins a provider Network and a consumer Network, which may belong to
different Workspaces. Each decision about it (`share_offer.created`,
`share_offer.accepted`, `share_offer.rejected`, `share_offer.revoked`,
`trust_contract.activated`, `trust_contract.revoked`) is recorded in both
Networks' streams, so each side holds its own chain of evidence:

- The record in the acting side's stream has the full payload, including the
  stated reason, the Account Session and the role evidence.
- The record in the other side's stream has only the relation between the
  two sides (`scope_relation`, `authority_side`, `evidence_network`,
  `provider_network`, `consumer_network`) and
  `acting_side_details: "recorded_in_acting_network"`. Its
  `actor_principal_id` names the acting principal, who may belong to the
  other Workspace.

Each Workspace's export holds the records of its own streams, sealed as
stored.

## 7. auditverify

`core/tools/auditverify` checks an export with the Go standard library only.
It implements §4 from this document rather than from Core's code, so the
party holding an export can read and build it themselves:

```bash
go run ./core/tools/auditverify meshtransit-audit-export.json
go run ./core/tools/auditverify -format csv meshtransit-audit-export.csv
```

It applies the checks of §4.1 to every stream in the file and prints one
line per stream and `result: VERIFIED` or one `FAIL` line per problem. Exit
status is 0 when everything verifies, 1 when any check fails and 2 when the
file cannot be read or parsed. Files larger than 64 MiB are refused.
