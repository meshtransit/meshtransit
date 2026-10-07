// Package openapi supplies compiled management contracts, not runtime admission.
package openapi

import (
	_ "embed"
	"encoding/json"
	"errors"
)

// ManagementProfile selects a server-owned source document, never client negotiation.
// The zero value and unknown future profiles are invalid, not authentication defaults.
type ManagementProfile string

const (
	// ManagementProfileBearerV1 preserves the released management document exactly.
	ManagementProfileBearerV1 ManagementProfile = "account-session-bearer-v1"
	// ManagementProfileConsoleCookiePrivateV1 is disabled private source preparation.
	// Rendering it mounts no handler or documentation endpoint and enables no SSO.
	ManagementProfileConsoleCookiePrivateV1 ManagementProfile = "console-cookie-csrf-private-v1"
	// Bounds every compiled document; the composed Console contract is ~260 KiB.
	maximumManagementDocumentBytes     = 384 << 10
	consoleSessionPreparePath          = "/auth/v1/session/prepare"
	consoleSessionLogoutPath           = "/auth/v1/session/logout"
	consoleSessionManagementScopesPath = "/auth/v1/session/management-scopes"
	consoleDeploymentCapabilitiesPath  = "/v1/system/capabilities"
	deviceRevokePath                   = "/api/v1/workspaces/{workspace_id}/networks/{network_id}/" +
		"devices/{device_id}/actions/revoke"
	policyPublishPath = "/api/v1/workspaces/{workspace_id}/networks/{network_id}/" +
		"policy/actions/publish"
	policyReadPath     = "/api/v1/workspaces/{workspace_id}/networks/{network_id}/policy"
	policySimulatePath = "/api/v1/workspaces/{workspace_id}/networks/{network_id}/" +
		"policy/actions/simulate"
	policyApprovalRequestPath = "/api/v1/workspaces/{workspace_id}/networks/{network_id}/" +
		"policy/approval-requests"
	policyApprovalItemPath = "/api/v1/workspaces/{workspace_id}/networks/{network_id}/" +
		"policy/approval-requests/{approval_request_id}"
	policyApprovalApprovePath = "/api/v1/workspaces/{workspace_id}/networks/{network_id}/" +
		"policy/approval-requests/{approval_request_id}/actions/approve"
	accessGraphExplainPath = "/api/v1/workspaces/{workspace_id}/networks/{network_id}/" +
		"access-graph/actions/explain"
	accessGraphListPath = "/api/v1/workspaces/{workspace_id}/networks/{network_id}/access-graph"
)

// ErrInvalidManagementProfile conceals unknown selection or compiled-contract drift.
var ErrInvalidManagementProfile = errors.New("openapi: invalid management profile")

// Strings keep compiled assets immutable at the API boundary. No runtime files/cache.
//
//go:embed management_v1.json
var managementV1Contract string

//go:embed management_console_private_v1.profile.json
var consolePrivateProfile string

type consoleManagementProfile struct {
	ID                     ManagementProfile          `json:"id"`
	Format                 string                     `json:"format"`
	Description            string                     `json:"description"`
	SecuritySchemes        map[string]json.RawMessage `json:"securitySchemes"`
	Parameters             map[string]json.RawMessage `json:"parameters"`
	Schemas                map[string]json.RawMessage `json:"schemas"`
	Prepare                json.RawMessage            `json:"prepare"`
	Logout                 json.RawMessage            `json:"logout"`
	ManagementScopes       json.RawMessage            `json:"managementScopes"`
	DeploymentCapabilities json.RawMessage            `json:"deploymentCapabilities"`
	DeviceInventory        json.RawMessage            `json:"deviceInventory"`
	WorkspaceRename        json.RawMessage            `json:"workspaceRename"`
	WorkspaceMembers       json.RawMessage            `json:"workspaceMembers"`
	WorkspaceRoleAssign    json.RawMessage            `json:"workspaceRoleAssign"`
	WorkspaceRoleRevoke    json.RawMessage            `json:"workspaceRoleRevoke"`
	WorkspaceCreate        json.RawMessage            `json:"workspaceCreate"`
	NetworkCreate          json.RawMessage            `json:"networkCreate"`
	SessionWorkspaces      json.RawMessage            `json:"sessionWorkspaces"`
	SessionWorkspaceSwitch json.RawMessage            `json:"sessionWorkspaceSwitch"`
	ShareTargetResolve     json.RawMessage            `json:"shareTargetResolve"`
	NetworkAliasRanges     json.RawMessage            `json:"networkAliasRanges"`
	NetworkAliasRangeEdit  json.RawMessage            `json:"networkAliasRangeUpdate"`
	WorkspaceAuditEvents   json.RawMessage            `json:"workspaceAuditEvents"`
	WorkspaceAuditExport   json.RawMessage            `json:"workspaceAuditExport"`
}

// ManagementDocument returns independently owned deterministic OpenAPI bytes.
// Only reviewed compile-time assets are accepted; this is not a generic JSON patch.
// The private Console document describes the same resource API and no-grant proof
// preparation. Production factories, complete login routes, explicit runtime auth
// selection and operational acceptance are separate gates. Errors release no bytes.
func ManagementDocument(profile ManagementProfile) ([]byte, error) {
	switch profile {
	case ManagementProfileBearerV1:
		if len(managementV1Contract) == 0 || len(managementV1Contract) > maximumManagementDocumentBytes {
			return nil, ErrInvalidManagementProfile
		}
		return []byte(managementV1Contract), nil
	case ManagementProfileConsoleCookiePrivateV1:
		return composeConsoleManagementDocument(managementV1Contract, consolePrivateProfile)
	default:
		return nil, ErrInvalidManagementProfile
	}
}

func composeConsoleManagementDocument(base, fragment string) ([]byte, error) {
	if len(base) == 0 || len(base) > maximumManagementDocumentBytes {
		return nil, ErrInvalidManagementProfile
	}
	document, err := managementObject([]byte(base))
	if err != nil {
		return nil, ErrInvalidManagementProfile
	}
	validVersion := string(document["openapi"]) == `"3.1.0"`
	if !validVersion || document["security"] != nil {
		return nil, ErrInvalidManagementProfile
	}
	paths, err := managementObject(document["paths"])
	if err != nil || len(paths) != 31 {
		return nil, ErrInvalidManagementProfile
	}
	if len(fragment) == 0 || len(fragment) > maximumManagementDocumentBytes {
		return nil, ErrInvalidManagementProfile
	}
	var profile consoleManagementProfile
	if err := json.Unmarshal([]byte(fragment), &profile); err != nil {
		return nil, ErrInvalidManagementProfile
	}
	validIdentity := profile.ID == ManagementProfileConsoleCookiePrivateV1 &&
		profile.Format == "meshtransit-management-auth-profile/v1"
	validTransport := len(profile.SecuritySchemes) == 2 && len(profile.Parameters) == 3
	validShape := len(profile.Schemas) == 5 && len(profile.Prepare) > 0 && len(profile.Logout) > 0 &&
		len(profile.ManagementScopes) > 0 && len(profile.DeploymentCapabilities) > 0 &&
		len(profile.DeviceInventory) > 0 && consoleWorkspaceRenameOperation(profile.WorkspaceRename) &&
		consoleCookieOperation(profile.WorkspaceMembers, "get", "listWorkspaceMembers", false) &&
		consoleCookieOperation(profile.WorkspaceRoleAssign, "post", "assignWorkspaceRole", true) &&
		consoleCookieOperation(profile.WorkspaceRoleRevoke, "post", "revokeWorkspaceRole", true) &&
		consoleCookieOperation(profile.WorkspaceCreate, "post", "createWorkspace", true) &&
		consoleCookieOperation(profile.NetworkCreate, "post", "createNetwork", true) &&
		consoleCookieOperation(profile.SessionWorkspaces, "get", "listSessionWorkspaces", false) &&
		consoleCookieOperation(profile.SessionWorkspaceSwitch, "post", "switchSessionWorkspace", true) &&
		consoleCookieOperation(profile.ShareTargetResolve, "get", "resolveShareTarget", false) &&
		consoleCookieOperation(profile.NetworkAliasRanges, "get", "getNetworkAliasRanges", false) &&
		consoleCookieOperation(profile.NetworkAliasRangeEdit, "post", "updateNetworkAliasRanges", true) &&
		consoleCookieOperation(profile.WorkspaceAuditEvents, "get", "listWorkspaceAuditEvents", false) &&
		consoleCookieOperation(profile.WorkspaceAuditExport, "get", "exportWorkspaceAuditEvents", false)
	if !validIdentity || !validTransport || !validShape {
		return nil, ErrInvalidManagementProfile
	}
	if !consoleManagementScopeOperation(profile.ManagementScopes) {
		return nil, ErrInvalidManagementProfile
	}
	if !consoleDeploymentCapabilitiesOperation(profile.DeploymentCapabilities) {
		return nil, ErrInvalidManagementProfile
	}
	if !consoleDeviceInventoryOperation(profile.DeviceInventory) {
		return nil, ErrInvalidManagementProfile
	}
	components, err := managementObject(document["components"])
	if err != nil || !managementBearerScheme(components["securitySchemes"]) {
		return nil, ErrInvalidManagementProfile
	}
	type consoleOperation struct {
		path, method, operationID string
		mutation                  bool
	}
	operations := []consoleOperation{
		{"/api/v1/workspaces/{workspace_id}/networks/{network_id}/trust-contracts/{trust_contract_id}", "get", "getTrustContract", false},
		{"/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources", "get", "listResources", false},
		{"/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources", "post", "createResource", true},
		{"/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources/{resource_id}", "get", "getResource", false},
		{"/api/v1/workspaces/{workspace_id}/networks/{network_id}/share-offers", "get", "listShareOffers", false},
		{"/api/v1/workspaces/{workspace_id}/networks/{network_id}/share-offers", "post", "createShareOffer", true},
		{"/api/v1/workspaces/{workspace_id}/networks/{network_id}/share-offers/{share_offer_id}", "get", "getShareOffer", false},
		{"/api/v1/workspaces/{workspace_id}/networks/{network_id}/share-offers/{share_offer_id}/actions/{share_offer_action}", "post", "decideShareOffer", true},
		{"/api/v1/workspaces/{workspace_id}/networks/{network_id}/trust-contracts/{trust_contract_id}/actions/revoke", "post", "revokeTrustContract", true},
		{"/api/v1/workspaces/{workspace_id}/networks/{network_id}/trust-contracts/{trust_contract_id}/actions/activate", "post", "activateTrustContract", true},
		{deviceRevokePath, "post", "revokeDevice", true},
		{policyPublishPath, "post", "publishPolicy", true},
		{policySimulatePath, "post", "simulatePolicy", true},
		{policyReadPath, "get", "getActivePolicy", false},
		{policyApprovalRequestPath, "get", "listPolicyApprovalRequests", false},
		{policyApprovalRequestPath, "post", "requestPolicyApproval", true},
		{policyApprovalItemPath, "get", "getPolicyApprovalRequest", false},
		{policyApprovalApprovePath, "post", "approvePolicyApprovalRequest", true},
		{accessGraphExplainPath, "post", "explainActivePolicy", true},
		{accessGraphListPath, "get", "listAccessGraph", false},
	}
	consolePathItems := make(map[string]map[string]json.RawMessage, 7)
	for _, specification := range operations {
		operation, err := consoleManagementOperation(
			paths[specification.path], specification.method, specification.operationID, specification.mutation,
		)
		if err != nil {
			return nil, ErrInvalidManagementProfile
		}
		item := consolePathItems[specification.path]
		if item == nil {
			item = make(map[string]json.RawMessage, 2)
			consolePathItems[specification.path] = item
		}
		if item[specification.method] != nil {
			return nil, ErrInvalidManagementProfile
		}
		item[specification.method] = operation
	}
	for section, additions := range map[string]map[string]json.RawMessage{
		"parameters": profile.Parameters, "schemas": profile.Schemas,
	} {
		existing, err := managementObject(components[section])
		if err != nil {
			return nil, ErrInvalidManagementProfile
		}
		for name, value := range additions {
			if _, found := existing[name]; found {
				return nil, ErrInvalidManagementProfile
			}
			existing[name] = value
		}
		components[section], err = json.Marshal(existing)
		if err != nil {
			return nil, ErrInvalidManagementProfile
		}
	}
	components["securitySchemes"], err = json.Marshal(profile.SecuritySchemes)
	if err != nil {
		return nil, ErrInvalidManagementProfile
	}
	consolePaths := make(map[string]json.RawMessage, len(consolePathItems)+4)
	for path, item := range consolePathItems {
		consolePaths[path], err = json.Marshal(item)
		if err != nil {
			return nil, ErrInvalidManagementProfile
		}
	}
	consolePaths["/api/v1/workspaces/{workspace_id}/actions/rename"] = profile.WorkspaceRename
	consolePaths["/api/v1/workspaces"] = profile.WorkspaceCreate
	consolePaths["/api/v1/workspaces/{workspace_id}/networks"] = profile.NetworkCreate
	consolePaths["/auth/v1/session/workspaces"] = profile.SessionWorkspaces
	consolePaths["/auth/v1/session/workspace"] = profile.SessionWorkspaceSwitch
	consolePaths["/api/v1/workspaces/{workspace_id}/networks/{network_id}/share-targets/{network_display_code}"] = profile.ShareTargetResolve
	consolePaths["/api/v1/workspaces/{workspace_id}/members"] = profile.WorkspaceMembers
	consolePaths["/api/v1/workspaces/{workspace_id}/networks/{network_id}/alias-ranges"] = profile.NetworkAliasRanges
	consolePaths["/api/v1/workspaces/{workspace_id}/networks/{network_id}/alias-ranges/actions/update"] = profile.NetworkAliasRangeEdit
	consolePaths["/api/v1/workspaces/{workspace_id}/audit-events"] = profile.WorkspaceAuditEvents
	consolePaths["/api/v1/workspaces/{workspace_id}/audit-events/export"] = profile.WorkspaceAuditExport
	consolePaths["/api/v1/workspaces/{workspace_id}/role-assignments"] = profile.WorkspaceRoleAssign
	consolePaths["/api/v1/workspaces/{workspace_id}/role-assignments/{assignment_id}/actions/revoke"] = profile.WorkspaceRoleRevoke
	consolePaths[consoleSessionPreparePath] = profile.Prepare
	consolePaths[consoleSessionLogoutPath] = profile.Logout
	consolePaths[consoleSessionManagementScopesPath] = profile.ManagementScopes
	consolePaths[consoleDeploymentCapabilitiesPath] = profile.DeploymentCapabilities
	consolePaths["/api/v1/workspaces/{workspace_id}/networks/{network_id}/devices"] = profile.DeviceInventory
	document["paths"], err = json.Marshal(consolePaths)
	if err != nil {
		return nil, ErrInvalidManagementProfile
	}
	document["components"], err = json.Marshal(components)
	if err != nil {
		return nil, ErrInvalidManagementProfile
	}
	info, err := managementObject(document["info"])
	if err != nil {
		return nil, ErrInvalidManagementProfile
	}
	info["description"], err = json.Marshal(profile.Description)
	if err != nil {
		return nil, ErrInvalidManagementProfile
	}
	document["info"], err = json.Marshal(info)
	if err != nil {
		return nil, ErrInvalidManagementProfile
	}
	document["servers"] = json.RawMessage(`[{"url":"https://console.example.test"}]`)
	document["x-meshtransit-auth-profile"] = json.RawMessage(`"console-cookie-csrf-private-v1"`)
	document["x-meshtransit-runtime-status"] = json.RawMessage(`"private-source-only"`)
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil || len(body) > maximumManagementDocumentBytes {
		return nil, ErrInvalidManagementProfile
	}
	return body, nil
}

func consoleManagementOperation(
	item json.RawMessage,
	method string,
	operationID string,
	mutation bool,
) (json.RawMessage, error) {
	methods, err := managementObject(item)
	if err != nil || len(methods) < 1 || len(methods) > 2 {
		return nil, ErrInvalidManagementProfile
	}
	if method != "get" && method != "post" {
		return nil, ErrInvalidManagementProfile
	}
	operation, err := managementObject(methods[method])
	if err != nil {
		return nil, ErrInvalidManagementProfile
	}
	var currentID string
	var security []map[string][]string
	if err := json.Unmarshal(operation["operationId"], &currentID); err != nil || currentID != operationID {
		return nil, ErrInvalidManagementProfile
	}
	if err := json.Unmarshal(operation["security"], &security); err != nil || len(security) != 1 {
		return nil, ErrInvalidManagementProfile
	}
	if len(security[0]) != 1 {
		return nil, ErrInvalidManagementProfile
	}
	scopes, present := security[0]["accountSessionBearer"]
	validScopes := scopes != nil && len(scopes) == 0
	if !present || !validScopes {
		return nil, ErrInvalidManagementProfile
	}
	var parameters []json.RawMessage
	if err := json.Unmarshal(operation["parameters"], &parameters); err != nil || len(parameters) == 0 {
		return nil, ErrInvalidManagementProfile
	}
	parametersToAdd := []string{"ConsoleOrigin", "ConsoleSessionChannel"}
	if mutation {
		parametersToAdd = append(parametersToAdd, "ConsoleSessionProof")
	}
	for _, name := range parametersToAdd {
		parameters = append(parameters, json.RawMessage(`{"$ref":"#/components/parameters/`+name+`"}`))
	}
	operation["parameters"], err = json.Marshal(parameters)
	if err != nil {
		return nil, ErrInvalidManagementProfile
	}
	operation["security"] = json.RawMessage(`[{"accountSessionCookie":[]}]`)
	if mutation {
		operation["security"] = json.RawMessage(`[{"accountSessionCookie":[],"sessionCSRF":[]}]`)
	}
	return json.Marshal(operation)
}

func managementObject(body []byte) (map[string]json.RawMessage, error) {
	if len(body) == 0 || len(body) > maximumManagementDocumentBytes {
		return nil, ErrInvalidManagementProfile
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil || object == nil {
		return nil, ErrInvalidManagementProfile
	}
	return object, nil
}

func managementBearerScheme(body json.RawMessage) bool {
	schemes, err := managementObject(body)
	if err != nil || len(schemes) != 1 {
		return false
	}
	var scheme struct {
		Type   string `json:"type"`
		Scheme string `json:"scheme"`
	}
	if err := json.Unmarshal(schemes["accountSessionBearer"], &scheme); err != nil {
		return false
	}
	return scheme.Type == "http" && scheme.Scheme == "bearer"
}

func consoleManagementScopeOperation(item json.RawMessage) bool {
	methods, err := managementObject(item)
	if err != nil || len(methods) != 1 {
		return false
	}
	operation, err := managementObject(methods["get"])
	if err != nil || operation["requestBody"] != nil {
		return false
	}
	var operationID string
	if err := json.Unmarshal(operation["operationId"], &operationID); err != nil ||
		operationID != "listConsoleManagementScopes" {
		return false
	}
	var security []map[string][]string
	if err := json.Unmarshal(operation["security"], &security); err != nil || len(security) != 1 ||
		len(security[0]) != 1 {
		return false
	}
	scopes, present := security[0]["accountSessionCookie"]
	if !present || scopes == nil || len(scopes) != 0 {
		return false
	}
	var parameters []json.RawMessage
	return json.Unmarshal(operation["parameters"], &parameters) == nil && len(parameters) == 4
}

func consoleDeploymentCapabilitiesOperation(item json.RawMessage) bool {
	methods, err := managementObject(item)
	if err != nil || len(methods) != 1 {
		return false
	}
	operation, err := managementObject(methods["get"])
	if err != nil || operation["requestBody"] != nil {
		return false
	}
	var operationID string
	if err := json.Unmarshal(operation["operationId"], &operationID); err != nil ||
		operationID != "getConsoleDeploymentCapabilities" {
		return false
	}
	var security []map[string][]string
	if err := json.Unmarshal(operation["security"], &security); err != nil || len(security) != 1 ||
		len(security[0]) != 1 {
		return false
	}
	scopes, present := security[0]["accountSessionCookie"]
	if !present || scopes == nil || len(scopes) != 0 {
		return false
	}
	var parameters []json.RawMessage
	return json.Unmarshal(operation["parameters"], &parameters) == nil && len(parameters) == 2
}

func consoleDeviceInventoryOperation(item json.RawMessage) bool {
	methods, err := managementObject(item)
	if err != nil || len(methods) != 1 {
		return false
	}
	operation, err := managementObject(methods["get"])
	if err != nil || operation["requestBody"] != nil {
		return false
	}
	var operationID string
	if json.Unmarshal(operation["operationId"], &operationID) != nil || operationID != "listConsoleDevices" {
		return false
	}
	var security []map[string][]string
	if json.Unmarshal(operation["security"], &security) != nil || len(security) != 1 || len(security[0]) != 1 {
		return false
	}
	scopes, present := security[0]["accountSessionCookie"]
	if !present || scopes == nil || len(scopes) != 0 {
		return false
	}
	var parameters []json.RawMessage
	return json.Unmarshal(operation["parameters"], &parameters) == nil && len(parameters) == 6
}

// consoleCookieOperation checks one single-method Console operation: its ID,
// cookie authentication, and CSRF proof plus a request body for mutations.
func consoleCookieOperation(item json.RawMessage, method, operationID string, mutation bool) bool {
	methods, err := managementObject(item)
	if err != nil || len(methods) != 1 {
		return false
	}
	operation, err := managementObject(methods[method])
	if err != nil || (operation["requestBody"] != nil) != mutation {
		return false
	}
	var id string
	if json.Unmarshal(operation["operationId"], &id) != nil || id != operationID {
		return false
	}
	schemes := []string{"accountSessionCookie"}
	if mutation {
		schemes = append(schemes, "sessionCSRF")
	}
	var security []map[string][]string
	if json.Unmarshal(operation["security"], &security) != nil || len(security) != 1 || len(security[0]) != len(schemes) {
		return false
	}
	for _, name := range schemes {
		scopes, present := security[0][name]
		if !present || scopes == nil || len(scopes) != 0 {
			return false
		}
	}
	return true
}

func consoleWorkspaceRenameOperation(item json.RawMessage) bool {
	methods, err := managementObject(item)
	if err != nil || len(methods) != 1 {
		return false
	}
	operation, err := managementObject(methods["post"])
	if err != nil || string(operation["operationId"]) != `"renameWorkspace"` || operation["requestBody"] == nil {
		return false
	}
	var security []map[string][]string
	if json.Unmarshal(operation["security"], &security) != nil || len(security) != 1 || len(security[0]) != 2 {
		return false
	}
	for _, name := range []string{"accountSessionCookie", "sessionCSRF"} {
		scopes, present := security[0][name]
		if !present || scopes == nil || len(scopes) != 0 {
			return false
		}
	}
	var parameters []struct {
		Reference string `json:"$ref"`
	}
	if json.Unmarshal(operation["parameters"], &parameters) != nil || len(parameters) != 5 {
		return false
	}
	for index, name := range []string{"WorkspaceID", "IfMatch", "ConsoleOrigin", "ConsoleSessionChannel", "ConsoleSessionProof"} {
		if parameters[index].Reference != "#/components/parameters/"+name {
			return false
		}
	}
	return true
}
