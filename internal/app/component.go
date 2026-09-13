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
)

// String returns the stable operator-facing component name.
func (component Component) String() string {
	switch component {
	case ComponentPostgreSQL:
		return "postgresql"
	case ComponentRedis:
		return "redis"
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
	for _, role := range roles {
		switch role {
		case RoleAPI, RoleControl, RoleWorker:
			requiresStorage = true
		case RoleRelay:
		}
	}
	if !requiresStorage {
		return nil, nil
	}
	return []Component{ComponentPostgreSQL, ComponentRedis}, nil
}
