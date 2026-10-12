package migrations

import _ "embed"

//go:embed operator/000051_resource_sharing_function_ownership.sql
var resourceSharingFunctionOwnershipSQL string

//go:embed operator/000052_policy_imported_resource_function_ownership.sql
var policyImportedResourceFunctionOwnershipSQL string

//go:embed operator/000053_resource_sharing_access_name_function_ownership.sql
var resourceSharingAccessNameFunctionOwnershipSQL string

//go:embed operator/000054_resource_sharing_private_endpoint_function_ownership.sql
var resourceSharingPrivateEndpointFunctionOwnershipSQL string

//go:embed operator/000055_resource_sharing_private_endpoint_publication_ownership.sql
var resourceSharingEndpointPublicationOwnershipSQL string

//go:embed operator/000079_direct_device_endpoint_function_ownership.sql
var directDeviceEndpointFunctionOwnershipSQL string

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

// ResourceSharingPrivateEndpointFunctionOwnershipSQL returns the operator-only
// step that closes activation/revocation bypasses and exposes the endpoint-aware
// mutation entry points through the Resource Sharing NOLOGIN owner.
func ResourceSharingPrivateEndpointFunctionOwnershipSQL() string {
	return resourceSharingPrivateEndpointFunctionOwnershipSQL
}

// ResourceSharingEndpointPublicationOwnershipSQL returns the operator-only
// step that closes the v3 revocation bypass and exposes DNS-aware revocation.
func ResourceSharingEndpointPublicationOwnershipSQL() string {
	return resourceSharingEndpointPublicationOwnershipSQL
}

//go:embed operator/000080_direct_device_map_function_ownership.sql
var directDeviceMapFunctionOwnershipSQL string

// DirectDeviceMapFunctionOwnershipSQL assigns the bounded authenticated reader
// to its isolated NOLOGIN owner. The operator provisions that role before migration 80.
func DirectDeviceMapFunctionOwnershipSQL() string { return directDeviceMapFunctionOwnershipSQL }

// DirectDeviceEndpointFunctionOwnershipSQL enables exact-scope direct readiness
// and joint withdrawal while preserving supported rollback writer entry points.
func DirectDeviceEndpointFunctionOwnershipSQL() string {
	return directDeviceEndpointFunctionOwnershipSQL
}

//go:embed operator/000082_device_alias_client_ownership.sql
var deviceAliasClientOwnershipSQL string

// DeviceAliasClientOwnershipSQL assigns compatibility observation to its
// isolated NOLOGIN owner before granting the authenticated runtime entry point.
func DeviceAliasClientOwnershipSQL() string { return deviceAliasClientOwnershipSQL }

//go:embed operator/000083_device_alias_map_ownership.sql
var deviceAliasMapOwnershipSQL string

// DeviceAliasMapOwnershipSQL confines alias reads to an isolated function owner.
func DeviceAliasMapOwnershipSQL() string { return deviceAliasMapOwnershipSQL }

//go:embed operator/000084_device_sharing_dependencies_ownership.sql
var deviceSharingDependenciesOwnershipSQL string

// DeviceSharingDependenciesOwnershipSQL confines refresh hints to the authenticated reader.
func DeviceSharingDependenciesOwnershipSQL() string { return deviceSharingDependenciesOwnershipSQL }

//go:embed operator/000085_device_alias_worker_ownership.sql
var deviceAliasWorkerOwnershipSQL string

// DeviceAliasWorkerOwnershipSQL enables only guarded worker entry points.
func DeviceAliasWorkerOwnershipSQL() string { return deviceAliasWorkerOwnershipSQL }

//go:embed operator/000086_device_alias_withdrawal_ownership.sql
var deviceAliasWithdrawalOwnershipSQL string

// DeviceAliasWithdrawalOwnershipSQL enables no-grant worker lifecycle entry points.
func DeviceAliasWithdrawalOwnershipSQL() string { return deviceAliasWithdrawalOwnershipSQL }

//go:embed operator/000087_device_alias_work_ownership.sql
var deviceAliasWorkOwnershipSQL string

// DeviceAliasWorkOwnershipSQL enables bounded no-grant candidate discovery.
func DeviceAliasWorkOwnershipSQL() string { return deviceAliasWorkOwnershipSQL }

//go:embed operator/000088_imported_policy_simulation_reader_ownership.sql
var importedPolicySimulationReaderOwnershipSQL string

// ImportedPolicySimulationReaderOwnershipSQL confines immutable provenance
// reconstruction to the existing bilateral reader and authorized baseline.
func ImportedPolicySimulationReaderOwnershipSQL() string {
	return importedPolicySimulationReaderOwnershipSQL
}

//go:embed operator/000089_expired_unprovisioned_share_cleanup_ownership.sql
var expiredUnprovisionedShareCleanupOwnershipSQL string

// ExpiredUnprovisionedShareCleanupOwnershipSQL exposes only the current
// revocation entry point through the isolated Resource Sharing writer.
func ExpiredUnprovisionedShareCleanupOwnershipSQL() string {
	return expiredUnprovisionedShareCleanupOwnershipSQL
}

//go:embed operator/000091_resource_sharing_never_expiry_ownership.sql
var resourceSharingNeverExpiryOwnershipSQL string

// ResourceSharingNeverExpiryOwnershipSQL confines the new sharing mutation
// entry points to the isolated Resource Sharing writer.
func ResourceSharingNeverExpiryOwnershipSQL() string {
	return resourceSharingNeverExpiryOwnershipSQL
}

//go:embed operator/000092_unified_device_alias_ownership.sql
var unifiedDeviceAliasOwnershipSQL string

// UnifiedDeviceAliasOwnershipSQL exposes the Network-scoped alias entry points
// and closes the earlier cross-Workspace-only and direct activation ones.
func UnifiedDeviceAliasOwnershipSQL() string { return unifiedDeviceAliasOwnershipSQL }

//go:embed operator/000093_alias_map_reader_ownership.sql
var aliasMapReaderOwnershipSQL string

// AliasMapReaderOwnershipSQL moves the runtime alias map entry point to the
// bounded-planning reader and closes the previous one.
func AliasMapReaderOwnershipSQL() string { return aliasMapReaderOwnershipSQL }

//go:embed operator/000094_share_offer_access_label_ownership.sql
var shareOfferAccessLabelOwnershipSQL string

// ShareOfferAccessLabelOwnershipSQL exposes the labeled offer creation and the
// derived-name decision entry points to runtime through the sharing writer.
func ShareOfferAccessLabelOwnershipSQL() string { return shareOfferAccessLabelOwnershipSQL }

//go:embed operator/000112_trust_contract_expiry_ownership.sql
var trustContractExpiryOwnershipSQL string

// TrustContractExpiryOwnershipSQL moves the expiry finalizer entry points to
// the sharing writer and exposes them to the worker role only.
func TrustContractExpiryOwnershipSQL() string { return trustContractExpiryOwnershipSQL }

//go:embed operator/000114_alias_map_reachable_shares_ownership.sql
var aliasMapReachableSharesOwnershipSQL string

// AliasMapReachableSharesOwnershipSQL moves the reachable-share alias map
// reader to its NOLOGIN owner and exposes it to runtime.
func AliasMapReachableSharesOwnershipSQL() string { return aliasMapReachableSharesOwnershipSQL }

//go:embed operator/000146_device_sharing_dependencies_v2_ownership.sql
var deviceSharingDependenciesV2OwnershipSQL string

// DeviceSharingDependenciesV2OwnershipSQL moves the narrowed sharing
// dependency reader (schema 146) to the alias map reader and exposes it to
// runtime; v1 stays executable for rollback.
func DeviceSharingDependenciesV2OwnershipSQL() string { return deviceSharingDependenciesV2OwnershipSQL }
