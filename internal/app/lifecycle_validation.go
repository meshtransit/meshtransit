package app

import "reflect"

const maxServiceNameLength = 64

func validOwnedServices(services []OwnedService) bool {
	if len(services) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(services))
	for _, owned := range services {
		if !validServiceName(owned.Name) || isNilLifecycleDependency(owned.Service) {
			return false
		}
		if _, duplicate := seen[owned.Name]; duplicate {
			return false
		}
		seen[owned.Name] = struct{}{}
	}
	return true
}

func validServiceName(name string) bool {
	if len(name) == 0 || len(name) > maxServiceNameLength {
		return false
	}
	for index := range len(name) {
		character := name[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			(index > 0 && (character == '-' || character == '_')) {
			continue
		}
		return false
	}
	return true
}

func validateActiveRoles(roles []Role) error {
	if len(roles) == 0 {
		return ErrInvalidApplication
	}
	seen := make(map[Role]struct{}, len(roles))
	for _, role := range roles {
		switch role {
		case RoleAPI, RoleControl, RoleWorker, RoleRelay, RoleIdentity:
		default:
			return ErrInvalidApplication
		}
		if _, exists := seen[role]; exists {
			return ErrInvalidApplication
		}
		seen[role] = struct{}{}
	}
	return nil
}

func roleNames(roles []Role) []string {
	names := make([]string, len(roles))
	for index, role := range roles {
		names[index] = role.String()
	}
	return names
}

func isNilLifecycleDependency(dependency any) bool {
	if dependency == nil {
		return true
	}
	value := reflect.ValueOf(dependency)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
