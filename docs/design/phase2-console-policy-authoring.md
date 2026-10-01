# Console Device ping policy workflow

## Scope and invariants

This vertical slice exposes production simulation and publication through Console. The initial form creates exactly two ICMP Device rules, one in each direction. It replaces the complete active rule set; the user must review removals in the compiler's impact preview before applying the change. The 2026-10-01 product decision in [Authorized publisher direct publication](phase2-policy-publisher-direct-publication.md) replaces the original mandatory proposal/independent-approval sequence with direct publication by a current `policy.publish` holder. Existing approved proposals remain a separate optional import workflow.

Core remains the sole authority for scope, compilation, baseline revisions, publication, optional supplied approval evidence and audit/outbox. Console grants nothing from projected permissions. Every action prepares fresh Session CSRF proof and uses one explicit strong revision precondition. Publication is attempted once. Ambiguous mutation outcomes disable another submission and require authoritative reconciliation.

Migration 74 only adds `policy.validate` and `policy.publish` to the existing management projection allowlist. It preserves current Session, subject, provider, Workspace membership and exact Network RoleBinding checks. It grants no permissions and changes no active policy.

The form uses real Device inventory, excludes revoked or expired registrations, and retains stable rule IDs from simulation through publication. The current policy revision is an explicit concurrency input until the general policy read API is implemented.

The Console presents source and destination selection before preview and keeps publication in a separate step. An approval-only account sees an explicit explanation instead of an empty editor. Account switching starts the existing fresh-CSRF SSO flow without logging out the previous AccountSession. This is necessary when one browser tests independent approval and publication: the approving Session must still pass the existing publication gate. Its normal expiry and authority checks remain unchanged. Sign out retains its explicit revocation semantics. Unsaved proposals are not transferred silently between accounts.

## Trust transitions and STRIDE cases

- Spoofed Network, Device, publisher or approval IDs: Console validates typed IDs and bundle scope; Core reauthorizes and recompiles the full request. Client metadata never substitutes for durable authority.
- Tampered preview or imported draft: validate bounded exact schemas, revision vectors, candidate and impact hashes. Direct publication requires current exact-scope `policy.publish` authority. In the optional approved-proposal workflow, bind the acknowledgement to its simulation and independently verify immutable approval evidence at publication.
- Optional independent approval: retain its separate Principal and AccountSession requirements when evidence is supplied. Ordinary direct publication requires no separate approver. No qualification bypass is exposed.
- Lost mutation acknowledgement or double click: disable controls synchronously, preserve an explicit uncertain state, never automatically retry a mutation.
- Information disclosure: no tokens, cookies or Session handles enter downloaded draft bundles, JavaScript storage or logs. Draft transfer is an explicit user download/import; nothing is persisted silently between accounts.
- Resource exhaustion: one bounded inventory page at a time, two rules only, bounded input/output and existing edge/Core body, deadline, rate and concurrency limits.
- Stale or incomplete impact: block publication on truncated, stale or uncertain results; changing Device selection or revision discards the previous preview.

## Delivery gates

Cover unsupported permissions, scope substitution, malformed previews, optional proposal/binding mismatch, wrong publication hash/revision, expiration, stale selections, uncertainty and exact edge routes. Run the repository Go gates, affected PostgreSQL projection integration tests, Console quality gates and real SSO/direct-publication verification before claiming connectivity. Retain the approved-proposal regression gates for the optional workflow.
