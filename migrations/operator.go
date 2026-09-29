package migrations

import _ "embed"

//go:embed operator/000051_resource_sharing_function_ownership.sql
var resourceSharingFunctionOwnershipSQL string

//go:embed operator/000052_policy_imported_resource_function_ownership.sql
var policyImportedResourceFunctionOwnershipSQL string

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
