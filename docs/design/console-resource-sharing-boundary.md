# Console Resource and sharing boundary

The cookie profile admits the existing Resource collection (GET/POST), Resource
item (GET), share-offer collection (GET/POST), share-offer item (GET), explicit
accept/reject/revoke actions, and contract activate/revoke actions. It delegates
to the same management services and durable authorization as the Bearer profile.
Resource groups, Resource lifecycle, rebind and authority transfer are not admitted.

## Threat model and invariants

- Spoofing/elevation: the current cookie Session authenticates every operation.
  Requested Workspace/Network is an exact filter, never identity or membership.
  Resource and sharing services recheck their separate permissions in PostgreSQL.
  Imported-resource compilation uses the sharing resolver and cannot flatten or
  re-export an imported target as a local Device.
- Tampering: same origin and Session channel are mandatory. Mutations require the
  existing Session-bound CSRF proof, canonical request, bounded JSON body,
  idempotency evidence and the existing ETag contract. Collection query parameters
  are admitted only on GET and validated by the owning management parser. Item
  queries and unsupported methods/actions fail before effects.
- Disclosure: no Bearer fallback, redirects, cookies, URLs or logs carry offer
  tokens. Creation returns the one-time token only through the authenticated JSON
  response; private response release revalidates Session freshness. Unknown scope
  remains concealed by the resource/sharing authorization service.
- Repudiation: existing immutable audit, revisions and transactional outbox remain
  the only mutation evidence. An uncertain response is not permission to repeat
  with a different idempotency key.
- DoS: reuse shared source/Session budgets, finite HTTP/SQL deadlines, concurrency,
  body/header/page limits and cancellation. No new queue, worker or external I/O
  occurs during transaction locks.

Acceptance: cookie reads reach the exact scoped catalog; proof-protected writes
reach the existing service; missing/stale proof, Bearer headers, foreign origin,
wrong methods, mutation queries and unsupported Resource operations have no
application effect. Production composition requires all three Resource ports.
No schema or packet permission is changed by admitting these API operations.
