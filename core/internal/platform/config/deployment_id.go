package config

import "meshtransit.net/core/internal/domain/deployment"

// envDeploymentPublicID is the installation's Deployment ID for every
// setting that names it (V1-11 S2e): a role's feature that needs the ID and
// does not set its own takes this one. A feature's own setting must equal
// it. Features stay off unless configured: the ID alone turns none on (the
// relay's ticket ID, which turns tickets on, is never defaulted).
const envDeploymentPublicID = "MESHTRANSIT_DEPLOYMENT_PUBLIC_ID"

// loadInstallationID parses MESHTRANSIT_DEPLOYMENT_PUBLIC_ID; nil when unset.
func loadInstallationID(lookup LookupFunc) (*deployment.ID, error) {
	value, present := lookup(envDeploymentPublicID)
	if !present {
		return nil, nil
	}
	id, err := deployment.ParseID(value)
	if err != nil {
		return nil, settingError(envDeploymentPublicID)
	}
	return &id, nil
}

// requireSameDeploymentID refuses idKey set to another ID than
// MESHTRANSIT_DEPLOYMENT_PUBLIC_ID, without ever filling it (an opt-in ID).
func requireSameDeploymentID(lookup LookupFunc, idKey string) error {
	base, hasBase := lookup(envDeploymentPublicID)
	own, hasOwn := lookup(idKey)
	if hasBase && hasOwn && own != base {
		return settingError(idKey)
	}
	return nil
}

// withDeploymentID answers idKey with MESHTRANSIT_DEPLOYMENT_PUBLIC_ID when
// the feature is configured and idKey is unset; both set and different is
// refused.
func withDeploymentID(lookup LookupFunc, idKey string, configured func() bool) (LookupFunc, error) {
	base, hasBase := lookup(envDeploymentPublicID)
	if !hasBase {
		return lookup, nil
	}
	if _, err := deployment.ParseID(base); err != nil {
		return nil, settingError(envDeploymentPublicID)
	}
	own, hasOwn := lookup(idKey)
	if hasOwn {
		if own != base {
			return nil, settingError(idKey)
		}
		return lookup, nil
	}
	if !configured() {
		return lookup, nil
	}
	return func(key string) (string, bool) {
		if key == idKey {
			return base, true
		}
		return lookup(key)
	}, nil
}

// settingTrue is configured when key is "true" (a worker's enabled flag).
func settingTrue(lookup LookupFunc, key string) func() bool {
	return func() bool {
		value, _ := lookup(key)
		return value == "true"
	}
}

// anySettingPresent is configured when any of keys is set (an
// all-or-nothing group).
func anySettingPresent(lookup LookupFunc, keys ...string) func() bool {
	return func() bool {
		for _, key := range keys {
			if _, present := lookup(key); present {
				return true
			}
		}
		return false
	}
}
