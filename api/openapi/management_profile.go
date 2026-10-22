// Package openapi supplies compiled management contracts, not runtime admission.
package openapi

import (
	_ "embed"
	"encoding/json"
	"errors"
	"strings"
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
	// Bounds every compiled document; the composed Console contract passed
	// 512 KiB with member suspension and invitations (schemas 127 and 128)
	// and 1 MiB with DNS names (schema 215).
	maximumManagementDocumentBytes     = 2 << 20
	consoleSessionPreparePath          = "/auth/v1/session/prepare"
	consoleSessionLogoutPath           = "/auth/v1/session/logout"
	consoleSessionLogoutAllPath        = "/auth/v1/session/logout-all"
	consoleSessionManagementScopesPath = "/auth/v1/session/management-scopes"
	consoleDeploymentCapabilitiesPath  = "/v1/system/capabilities"
	consoleProfileFormat               = "meshtransit-management-auth-profile/v2"
)

// ErrInvalidManagementProfile conceals unknown selection or compiled-contract drift.
var ErrInvalidManagementProfile = errors.New("openapi: invalid management profile")

// Strings keep compiled assets immutable at the API boundary. No runtime files/cache.
//
//go:embed management_v1.json
var managementV1Contract string

//go:embed management_console_private_v1.profile.json
var consolePrivateProfile string

// consoleManagementProfile adds the Console's cookie-only operations to the
// bearer document and names the bearer operations the Console also uses.
type consoleManagementProfile struct {
	ID               ManagementProfile                     `json:"id"`
	Format           string                                `json:"format"`
	Description      string                                `json:"description"`
	SecuritySchemes  map[string]json.RawMessage            `json:"securitySchemes"`
	Parameters       map[string]json.RawMessage            `json:"parameters"`
	Schemas          map[string]json.RawMessage            `json:"schemas"`
	BearerOperations []string                              `json:"bearerOperations"`
	Paths            map[string]map[string]json.RawMessage `json:"paths"`
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

// consoleMethods are the HTTP methods a Console operation may use.
var consoleMethods = map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true}

func composeConsoleManagementDocument(base, fragment string) ([]byte, error) {
	if len(base) == 0 || len(base) > maximumManagementDocumentBytes ||
		len(fragment) == 0 || len(fragment) > maximumManagementDocumentBytes {
		return nil, ErrInvalidManagementProfile
	}
	document, err := managementObject([]byte(base))
	if err != nil || string(document["openapi"]) != `"3.1.0"` || document["security"] != nil {
		return nil, ErrInvalidManagementProfile
	}
	var profile consoleManagementProfile
	if err := json.Unmarshal([]byte(fragment), &profile); err != nil {
		return nil, ErrInvalidManagementProfile
	}
	if profile.ID != ManagementProfileConsoleCookiePrivateV1 || profile.Format != consoleProfileFormat ||
		len(profile.SecuritySchemes) != 2 || len(profile.Parameters) != 3 || len(profile.Paths) == 0 {
		return nil, ErrInvalidManagementProfile
	}
	components, err := managementObject(document["components"])
	if err != nil || !managementBearerScheme(components["securitySchemes"]) {
		return nil, ErrInvalidManagementProfile
	}
	consolePaths, err := consoleBearerOperations(document["paths"], profile.BearerOperations)
	if err != nil {
		return nil, ErrInvalidManagementProfile
	}
	for path, item := range profile.Paths {
		if len(item) == 0 {
			return nil, ErrInvalidManagementProfile
		}
		for method, operation := range item {
			if !consoleMethods[method] || consolePaths[path][method] != nil ||
				!consoleProfileOperation(path, method, operation) {
				return nil, ErrInvalidManagementProfile
			}
			if consolePaths[path] == nil {
				consolePaths[path] = make(map[string]json.RawMessage, len(item))
			}
			consolePaths[path][method] = operation
		}
	}
	if !uniqueOperationIDs(consolePaths) {
		return nil, ErrInvalidManagementProfile
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
		if components[section], err = json.Marshal(existing); err != nil {
			return nil, ErrInvalidManagementProfile
		}
	}
	if components["securitySchemes"], err = json.Marshal(profile.SecuritySchemes); err != nil {
		return nil, ErrInvalidManagementProfile
	}
	if document["paths"], err = json.Marshal(consolePaths); err != nil {
		return nil, ErrInvalidManagementProfile
	}
	if document["components"], err = json.Marshal(components); err != nil {
		return nil, ErrInvalidManagementProfile
	}
	info, err := managementObject(document["info"])
	if err != nil {
		return nil, ErrInvalidManagementProfile
	}
	if info["description"], err = json.Marshal(profile.Description); err != nil {
		return nil, ErrInvalidManagementProfile
	}
	if document["info"], err = json.Marshal(info); err != nil {
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

// consoleBearerOperations copies each named bearer operation, exactly once,
// onto cookie authentication.
func consoleBearerOperations(body json.RawMessage, operationIDs []string) (map[string]map[string]json.RawMessage, error) {
	paths, err := managementObject(body)
	if err != nil || len(operationIDs) == 0 {
		return nil, ErrInvalidManagementProfile
	}
	wanted := make(map[string]bool, len(operationIDs))
	for _, id := range operationIDs {
		if id == "" || wanted[id] {
			return nil, ErrInvalidManagementProfile
		}
		wanted[id] = true
	}
	result := make(map[string]map[string]json.RawMessage)
	for path, raw := range paths {
		item, err := managementObject(raw)
		if err != nil {
			return nil, ErrInvalidManagementProfile
		}
		for method, rawOperation := range item {
			if !consoleMethods[method] {
				continue
			}
			var header struct {
				OperationID string `json:"operationId"`
			}
			if json.Unmarshal(rawOperation, &header) != nil || !wanted[header.OperationID] {
				continue
			}
			operation, err := consoleManagementOperation(rawOperation, method != "get")
			if err == nil && method == "delete" {
				// A DELETE names its target in the path and carries no body.
				if fields, decodeErr := managementObject(rawOperation); decodeErr != nil || fields["requestBody"] != nil {
					err = ErrInvalidManagementProfile
				}
			}
			if err != nil {
				return nil, ErrInvalidManagementProfile
			}
			delete(wanted, header.OperationID)
			if result[path] == nil {
				result[path] = make(map[string]json.RawMessage, len(item))
			}
			result[path][method] = operation
		}
	}
	if len(wanted) != 0 {
		return nil, ErrInvalidManagementProfile
	}
	return result, nil
}

// consoleManagementOperation moves one bearer operation onto the Console's
// cookie, adding the CSRF proof for mutations.
func consoleManagementOperation(item json.RawMessage, mutation bool) (json.RawMessage, error) {
	operation, err := managementObject(item)
	if err != nil {
		return nil, ErrInvalidManagementProfile
	}
	var security []map[string][]string
	if err := json.Unmarshal(operation["security"], &security); err != nil || len(security) != 1 ||
		len(security[0]) != 1 {
		return nil, ErrInvalidManagementProfile
	}
	scopes, present := security[0]["accountSessionBearer"]
	if !present || scopes == nil || len(scopes) != 0 {
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
	if operation["parameters"], err = json.Marshal(parameters); err != nil {
		return nil, ErrInvalidManagementProfile
	}
	operation["security"] = json.RawMessage(`[{"accountSessionCookie":[]}]`)
	if mutation {
		operation["security"] = json.RawMessage(`[{"accountSessionCookie":[],"sessionCSRF":[]}]`)
	}
	return json.Marshal(operation)
}

// consoleProfileOperation checks one cookie-only operation: a read carries the
// cookie and no body; a change also carries the CSRF proof, and a body unless
// it deletes. Proof preparation is the one change without a proof.
func consoleProfileOperation(path, method string, item json.RawMessage) bool {
	operation, err := managementObject(item)
	if err != nil {
		return false
	}
	var id string
	if json.Unmarshal(operation["operationId"], &id) != nil || id == "" {
		return false
	}
	preparation := path == consoleSessionPreparePath && method == "post"
	mutation := method != "get"
	proof := mutation && !preparation
	if (operation["requestBody"] != nil) != (mutation && method != "delete") {
		return false
	}
	schemes := []string{"accountSessionCookie"}
	if proof {
		schemes = append(schemes, "sessionCSRF")
	}
	var security []map[string][]string
	if json.Unmarshal(operation["security"], &security) != nil || len(security) != 1 ||
		len(security[0]) != len(schemes) {
		return false
	}
	for _, name := range schemes {
		scopes, present := security[0][name]
		if !present || scopes == nil || len(scopes) != 0 {
			return false
		}
	}
	var parameters []struct {
		Reference string `json:"$ref"`
	}
	if json.Unmarshal(operation["parameters"], &parameters) != nil {
		return false
	}
	required := map[string]bool{"ConsoleOrigin": false, "ConsoleSessionChannel": false, "ConsoleSessionProof": !proof}
	for _, parameter := range parameters {
		name, local := strings.CutPrefix(parameter.Reference, "#/components/parameters/")
		if !local {
			continue
		}
		if seen, known := required[name]; known {
			if seen {
				return false
			}
			required[name] = true
		}
	}
	for _, seen := range required {
		if !seen {
			return false
		}
	}
	return true
}

// uniqueOperationIDs reports whether no two operations share an ID.
func uniqueOperationIDs(paths map[string]map[string]json.RawMessage) bool {
	seen := make(map[string]bool)
	for _, item := range paths {
		for _, raw := range item {
			var header struct {
				OperationID string `json:"operationId"`
			}
			if json.Unmarshal(raw, &header) != nil || header.OperationID == "" || seen[header.OperationID] {
				return false
			}
			seen[header.OperationID] = true
		}
	}
	return true
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
