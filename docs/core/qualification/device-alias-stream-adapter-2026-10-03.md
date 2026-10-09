# Device alias stream and PostgreSQL adapter qualification

This increment adds bounded bilateral notification refresh and the typed alias
record decoder/store seam. `EnableDeviceAliases` remains false by default and
is not enabled by composition. It requires the separately qualified alias SQL
reader and worker publication path before runtime activation.

Each stream owns one notification multiplexer and at most 257 exact Network
subscriptions for each feed: the local Network plus up to 256 remote sharing
scopes. PostgreSQL-derived accepted-contract dependencies may subscribe before
the first consumer rule. Dependencies grant no peers, packet rules or database
read capability. Remote revision numbers are never compared with the local
Network revision. Queue saturation coalesces to a full PostgreSQL reread;
periodic reconciliation repairs lost notifications. Changed dependencies
replace subscriptions and shutdown cancels and joins the multiplexer before
releasing feeds. Invalid or stopped feeds withdraw an existing sharing map.

The alias adapter reads inside the existing read-only repeatable-read map
transaction. Same-Workspace direct records and cross-Workspace alias records
use distinct decoders. Alias proofs bind current self/peer keys, sessions,
contract, endpoint generation, recovery epoch, exact host-route pairs and an
exclusive deadline. Foreign canonical addresses are not accepted as aliases.
Any malformed proof rolls back the entire map read.

Uncached race tests cover first-rule dependency refresh without packet grants,
remote rule removal at unchanged local revision, obsolete-scope cleanup,
notification bursts, wrong-Network hints, immutable dependency slices and
alias scope/address/family/deadline mismatches. Full repository quality passed.
The client packet fixture matrix at meshd `b76ba3c` separately passed actual
Linux TUN/encrypted IPv4/IPv6 TCP/UDP/ICMP, narrowing, removal, expiry and cleanup.
That evidence is not live Core/SSO authorization or Redis latency evidence.

Remaining activation gates: guarded alias reserve/readiness/withdrawal worker,
SQL/RLS negative integration cases, accepted-contract dependency reader,
configuration/composition, client flow identity/version advertisement and live
Core-to-client qualification. Imported DNS remains a following gate.
