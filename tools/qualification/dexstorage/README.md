# Embedded identity-broker storage qualification

`dexstorage` is a `dexbroker && qualification` build-tagged, offline operator
helper for the disposable
identity-broker upgrade/restore lane. It is compiled only through the
manifest-verified broker workspace.

`-mode migrate` uses the dependency's migration-capable storage open and must
run with the dedicated migration role. `-mode verify` uses the patched
prepared-schema open, performs no migration, and must run with the runtime
role. Both modes require PostgreSQL TLS `verify-full`, a protected password
file, and an explicit CA bundle. Output contains only the operation and pass
status; database addresses, roles, paths, credentials, and driver errors are
not emitted.

The command imports only MeshCore's broker adapter. The dependency-owned
migration API remains confined to that adapter and exists only under the
additional `qualification` build tag. The helper is not part of the ordinary
MeshCore binary. Its compile boundary is intentional: an incompatible broker
upgrade must fail the verified workspace gate before the upgrade/restore
fixture can run.
