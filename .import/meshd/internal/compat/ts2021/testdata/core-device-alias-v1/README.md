# Core-owned Device alias v1 fixtures

These six full maps originate from Core's explicit
`TestExportDeviceAliasFrames` fixture producer. They are synthetic public-key
protocol evidence for both sides and both canonical address families; no
production packet, secret, account or host is present. Canonical self addresses
are identical across the two Workspaces, and only aliases become peer routes.

Source: Core encoder commit `ee067629e41133f02690dbbfe46d1a3172ebbf93`. Client qualification checks
these same bytes through the strict compatibility accumulator. Copy only the
reviewed protocol fixture bytes, never Core internal source or runtime state.

These fixtures prove codec agreement. They do not prove SQL authorization,
feature admission, real encryption, route installation or live revocation.
