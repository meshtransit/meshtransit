package migrations

import _ "embed"

//go:embed operator/000051_resource_sharing_function_ownership.sql
var resourceSharingFunctionOwnershipSQL string

//go:embed operator/000052_policy_imported_resource_function_ownership.sql
var policyImportedResourceFunctionOwnershipSQL string

//go:embed operator/000053_resource_sharing_access_name_function_ownership.sql
var resourceSharingAccessNameFunctionOwnershipSQL string

// ResourceSharingFunctionOwnershipSQL returns the operator-only post-migration
// hardening step that transfers the two-authority functions to a NOLOGIN owner
// before exposing their bounded entry points to the runtime role.
func ResourceSharingFunctionOwnershipSQL() string {
	return resourceSharingFunctionOwnershipSQL
}

// PolicyImportedResourceFunctionOwnershipSQL returns the operator-only step
// that transfers the read-only bilateral resolver to its NOLOGIN owner.
func PolicyImportedResourceFunctionOwnershipSQL() string {
	return policyImportedResourceFunctionOwnershipSQL
}

// ResourceSharingAccessNameFunctionOwnershipSQL returns the operator-only step
// that closes the v1 mutation entry points and exposes the access-name-aware
// v2 functions through the Resource Sharing NOLOGIN owner.
func ResourceSharingAccessNameFunctionOwnershipSQL() string {
	return resourceSharingAccessNameFunctionOwnershipSQL
}
