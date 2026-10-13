-- Schema 150: attaching Imported Resource destinations to a policy release
-- no longer costs ~200 MB of planner memory. The attach functions resolve
-- every compiled rule against its authority in one statement that joins
-- eleven relations with dozens of equality conditions; with the default
-- join_collapse_limit PostgreSQL searches the join orders of that statement
-- on every first call in a backend, which took about 210 MB however few
-- rules a policy had (and a POC database at its memory limit was killed
-- while publishing). The statement is written in its execution order
-- (compiled rules, then the authority Core resolved, then the rows each one
-- names by key), so fixing that order removes the search; each join is
-- still planned on its own.
ALTER FUNCTION mesh_ops.attach_policy_imported_resource_destinations_internal_v1(
    UUID, TIMESTAMPTZ, JSONB, JSONB
) SET join_collapse_limit = 1 SET from_collapse_limit = 1;
ALTER FUNCTION mesh_ops.attach_policy_imported_resource_destinations_internal_v2(
    UUID, TIMESTAMPTZ, JSONB, JSONB
) SET join_collapse_limit = 1 SET from_collapse_limit = 1;
