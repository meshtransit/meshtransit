# Browser Device re-login

## Contract

A new, finite SSO enrollment approval may renew an existing Device only in the
approved Workspace and Network, with its current owner, the same Enrollment
Profile, authenticated machine material, and active Node key. Device expiry
alone does not delete the Device. Re-login retains the public Device ID,
hostname, owner, groups, key epochs and active primary address leases.

Suspension, deletion, revoked or expired key epochs, different owners or
profiles, changed Node keys and stale membership or Session evidence deny.
This operation cannot rotate keys, transfer ownership or move a Device between
Networks. Those transitions require their own authenticated operations.

The current Enrollment Profile determines the renewed finite lifetime. Profile
lifetime and ephemeral mode are reread under authority locks. SQL wall time is
used after lock acquisition. A fresh authority check immediately precedes
mutation, so expiry while waiting for Device/address/audit locks fails closed.

Renewal, the completed intent, Network and inventory revisions, canonical
`device.resumed` audit evidence, and outbox are one transaction. A lost response
replays the exact committed Device and revision without another lifetime or
revision change. Redis cannot grant or renew identity. Existing sharing
readiness remains subject to its own current session/key/lease pins.

## Threats and bounds

- Spoofing: Noise machine, Node key and fresh approved SSO identity must all match.
- Tampering/elevation: owner, profile, state and typed scope are checked again;
  a historical revoked machine is not treated as a fresh Device.
- Repudiation: canonical audit/outbox and deferred mutation coverage commit atomically.
- Disclosure: no key material or tokens enter logs or diagnostics.
- Denial of service: existing transaction deadlines, bounded address/hostname
  snapshots and exact indexed machine lookup remain in force. No external I/O
  or new goroutine occurs under locks.

No migration, RLS policy, grant or wire format changes are required. Creation
keeps its existing response; renewal uses the already defined `resumed`
disposition. Qualification covers PostgreSQL runtime/RLS creation, renewal,
replay, lease retention and changed-key denial plus owner/key/state unit cases.
