# Console sharing scope projection — 2026-09-30

## Change

The previously added Console Deployment capability migration (57) was absent
from the compiled migration catalog. It is now registered, so fresh deployments
install the function used by the live Session bootstrap.

Migration 58 replaces the private Console management-scope projection with a
current role-binding read. It returns each active Network that has at least one
of `policy.approve`, `share.accept`, `share.offer`, `share.read`, or
`share.revoke`. Permissions are distinct and sorted; only authorized Networks
enter pagination. Existing Account Session, Workspace membership, recovery,
role, and Network state checks remain in the SQL function. Only `mesh_runtime`
can execute it. The private OpenAPI profile and Go response validator accept
only this exact, canonically ordered permission set.

## Evidence and boundary

The PostgreSQL integration fixture exercises a mixed approval/sharing role, a
sharing-only role in two Networks, and Session revocation. It checks that the
security-definer function restores transaction-local RLS settings and exposes
no execute privilege to other runtime roles or PUBLIC. Catalog tests verify
both migrations are registered and ordered. These checks establish scope
projection behavior in the disposable platform environment; the server still
rechecks current authority on every sharing or approval request.

Deployed browser Sessions, two-person approval, and MeshClient publication and
traffic remain separate qualification gates.
