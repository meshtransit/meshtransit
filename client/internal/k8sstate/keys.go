package k8sstate

import (
	"fmt"
	"strings"
)

const (
	// IdentityKeyPrefix and ProfileKeyPrefix name each store's keys in the
	// Secret, so one Secret holds both stores' files.
	IdentityKeyPrefix = "identity."
	ProfileKeyPrefix  = "profile."

	// profileFile and identityDir are where profile.Open and identity.Open
	// keep their files under the state directory.
	profileFile = "profiles.json"
	identityDir = "identities"
	// identityIDLength is the length of a profile ID, which names its
	// identity record.
	identityIDLength = 32
)

// stateFile is where a Secret key lives under the state directory.
type stateFile struct {
	// dir is "" for the state directory itself, or identityDir.
	dir  string
	name string
}

// parseKey maps a Secret key to its file. Keys under the stores' prefixes
// must name a file the stores write, since anything else could leave the
// directory; known is false for keys under other prefixes, which a newer
// version may have written and an older one skips. A future version must
// therefore put new files under new prefixes, or a rollback past it fails
// to start.
func parseKey(key string) (file stateFile, known bool, err error) {
	switch {
	case key == ProfileKeyPrefix+profileFile:
		return stateFile{name: profileFile}, true, nil
	case strings.HasPrefix(key, IdentityKeyPrefix):
		name := strings.TrimPrefix(key, IdentityKeyPrefix)
		if !isIdentityFile(name) {
			return stateFile{}, false, fmt.Errorf("k8sstate: %q does not name an identity record", key)
		}
		return stateFile{dir: identityDir, name: name}, true, nil
	case strings.HasPrefix(key, ProfileKeyPrefix):
		return stateFile{}, false, fmt.Errorf("k8sstate: %q does not name the profile state", key)
	default:
		return stateFile{}, false, nil
	}
}

// isIdentityFile reports whether name is an identity record's file name: a
// profile ID of lowercase hex and ".json".
func isIdentityFile(name string) bool {
	id, ok := strings.CutSuffix(name, ".json")
	if !ok || len(id) != identityIDLength {
		return false
	}
	for i := range len(id) {
		if c := id[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
