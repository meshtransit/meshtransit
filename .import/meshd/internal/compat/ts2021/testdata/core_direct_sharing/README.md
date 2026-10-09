# Synthetic Core direct sharing frames

Source: Core revision `368122f9b3d74ce68e94e1feec8666b0e3d2b362`.
Profile: legacy-ts2021-cap142-v1. These fixed public identities, reserved names,
host prefixes and timestamps contain no live topology or credentials.

Generated explicitly by `TestExportDirectSharingFrames` through the actual Core
adapter encoder. `manifest.json` pins the producer and SHA-256 of each frame.
Fixtures cover provider/consumer full maps, full/delta share removal, and terminal
self withdrawal. Consumer initiation grants no reverse inbound policy; both peer
deadlines end at 2026-09-14 04:30:00 UTC.

Decode conformance runs with a fixed evaluation clock. Packet-gate tests verify
the exclusive deadline independently, including silence, tracked replies and
identity/key replacement. These fixtures do not qualify live database authority,
Redis convergence, encrypted sharing traffic or DNS.
