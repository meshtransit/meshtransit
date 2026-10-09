# Enforcement report v1

> Legacy: this extension rides on the TS2021 compatibility protocol and will be
> replaced by `EnforcementReport` in MTCP v1 (section 8.4). Kept until the
> TS2021 adapters are removed.

A node reports the [policy digest](../policy-digest-v1.md) of the rules its
packet filter enforces, so Core can compare it with the filter it delivered.

## Request

Inside a Noise-authenticated TS2021 session (any control replica):

```
POST /machine/meshtransit/enforcement
Content-Type: application/json

{"version":1,
 "node_key":"nodekey:<64 hex>",
 "digest":"sha256:<64 hex>",
 "grants":5,
 "applied_at":"2026-10-09T12:00:00Z"}
```

- The body is at most 1 KiB, has exactly these members, no duplicates.
- `node_key` MUST be the node key of the session's current map stream and
  belong to the authenticated machine key.
- `applied_at` is when the filter installed the rules. Core refuses values
  more than one minute in the future and clamps smaller skew to its own time.

## Responses

| Status | Meaning | Node behaviour |
|---|---|---|
| 204 | Stored against the node's current map session | Resend once after 30 s, then every 5 min |
| 400 | Malformed | Wait for the next filter change or heartbeat |
| 404 | Core does not support reports | Retry after 30 min |
| 409 | No current map session for this node key and machine | Retry with backoff (2 s doubling to 1 min) |
| 503 | Core could not store the report | Retry with backoff |

A report never ends or delays the map session.

## Core side

Core keeps, per Device, the digest of the packet filter it last delivered on
the current session and the latest report of that session. A new session
clears the report. The comparison is `enforced` (equal), `applying` (different
but delivered less than 60 s ago), `mismatch` (different past 60 s) or
`not_reported` (no report past 60 s; for example an older meshd).

The enforcement-ledger worker records each change between `enforced` and
`mismatch` as a validity interval, and seals the change into or out of
`mismatch` as an audit event on the Network stream.
