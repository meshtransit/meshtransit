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
	maximumManagementDocumentBytes                            = 128 << 10
	consoleSessionPreparePath                                 = "/auth/v1/session/prepare"
	deviceRevokePath                                          = "/api/v1/workspaces/{workspace_id}/networks/{network_id}/" +
		"devices/{device_id}/actions/revoke"
	policyPublishPath = "/api/v1/workspaces/{workspace_id}/networks/{network_id}/" +
		"policy/actions/publish"
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
	ID              ManagementProfile          `json:"id"`
	Format          string                     `json:"format"`
	Description     string                     `json:"description"`
	SecuritySchemes map[string]json.RawMessage `json:"securitySchemes"`
	Parameters      map[string]json.RawMessage `json:"parameters"`
	Schemas         map[string]json.RawMessage `json:"schemas"`
	Prepare         json.RawMessage            `json:"prepare"`
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
	if err != nil || len(paths) != 2 {
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
	validShape := len(profile.Schemas) == 2 && len(profile.Prepare) > 0
	if !validIdentity || !validTransport || !validShape {
		return nil, ErrInvalidManagementProfile
	}
	components, err := managementObject(document["components"])
	if err != nil || !managementBearerScheme(components["securitySchemes"]) {
		return nil, ErrInvalidManagementProfile
	}
	for path, operationID := range map[string]string{
		deviceRevokePath: "revokeDevice", policyPublishPath: "publishPolicy",
	} {
		operation, err := consoleManagementOperation(paths[path], operationID)
		if err != nil {
			return nil, ErrInvalidManagementProfile
		}
		paths[path] = operation
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
	paths[consoleSessionPreparePath] = profile.Prepare
	document["paths"], err = json.Marshal(paths)
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

func consoleManagementOperation(item json.RawMessage, operationID string) (json.RawMessage, error) {
	methods, err := managementObject(item)
	if err != nil || len(methods) != 1 {
		return nil, ErrInvalidManagementProfile
	}
	operation, err := managementObject(methods["post"])
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
	for _, name := range []string{"ConsoleOrigin", "ConsoleSessionChannel", "ConsoleSessionProof"} {
		parameters = append(parameters, json.RawMessage(`{"$ref":"#/components/parameters/`+name+`"}`))
	}
	operation["parameters"], err = json.Marshal(parameters)
	if err != nil {
		return nil, ErrInvalidManagementProfile
	}
	operation["security"] = json.RawMessage(`[{"accountSessionCookie":[],"sessionCSRF":[]}]`)
	methods["post"], err = json.Marshal(operation)
	if err != nil {
		return nil, ErrInvalidManagementProfile
	}
	body, err := json.Marshal(methods)
	if err != nil {
		return nil, ErrInvalidManagementProfile
	}
	return body, nil
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
