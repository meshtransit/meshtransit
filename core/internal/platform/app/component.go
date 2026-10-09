package app

// Component identifies one process dependency whose state participates in
// readiness. Values and strings are stable operator-facing metadata.
type Component uint8

const (
	// ComponentUnknown is the invalid zero value.
	ComponentUnknown Component = iota
	// ComponentPostgreSQL is the durable system-of-record dependency.
	ComponentPostgreSQL
	// ComponentRedis is the ephemeral coordination and cache dependency.
	ComponentRedis
	// ComponentPrivateLogin is required only by the configured private API profile.
	ComponentPrivateLogin
	// ComponentIdentityPostgreSQL is the isolated broker system of record.
	ComponentIdentityPostgreSQL
	// ComponentIdentityConfiguration is the approved immutable broker configuration.
	ComponentIdentityConfiguration
	// ComponentIdentitySigner proves token issuance and published JWKS agree.
	ComponentIdentitySigner
)

// String returns the stable operator-facing component name.
func (component Component) String() string {
	switch component {
	case ComponentPostgreSQL:
		return "postgresql"
	case ComponentRedis:
		return "redis"
	case ComponentPrivateLogin:
		return "private_login"
	case ComponentIdentityPostgreSQL:
		return "identity_postgresql"
	case ComponentIdentityConfiguration:
		return "identity_configuration"
	case ComponentIdentitySigner:
		return "identity_signer"
	default:
		return "unknown"
	}
}

// RequiredComponents returns the deduplicated dependency union for concrete
// active roles. The returned slice is owned by the caller.
func RequiredComponents(roles []Role) ([]Component, error) {
	if err := validateActiveRoles(roles); err != nil {
		return nil, err
	}

	requiresStorage := false
	requiresIdentityStorage := false
	for _, role := range roles {
		switch role {
		case RoleAPI, RoleControl, RoleWorker:
			requiresStorage = true
		case RoleIdentity:
			requiresIdentityStorage = true
		case RoleRelay:
		}
	}
	components := make([]Component, 0, 5)
	if requiresStorage {
		components = append(components, ComponentPostgreSQL, ComponentRedis)
	}
	if requiresIdentityStorage {
		components = append(
			components,
			ComponentIdentityPostgreSQL,
			ComponentIdentityConfiguration,
			ComponentIdentitySigner,
		)
	}
	if len(components) == 0 {
		return nil, nil
	}
	return components, nil
}
