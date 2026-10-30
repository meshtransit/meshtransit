package kubeprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// scopeHashDomain separates a scope's hash from a profile's and every other.
const scopeHashDomain = "meshtransit.net/kubescope/v1\x00"

// ScopeHash is the hash a gateway's map names a scope by (mtcp-v1 §7.12): of
// the profile's content hash, the rule's namespaces (every one: "*" alone)
// and whether the rule turns the cluster part on. It checks the namespaces
// as NewScope does.
func ScopeHash(profile [32]byte, namespaces []string, clusterPart bool) ([32]byte, error) {
	names, err := checkNamespaces(namespaces)
	if err != nil {
		return [32]byte{}, err
	}
	encoded, err := json.Marshal(struct {
		Format      int      `json:"format"`
		Profile     string   `json:"profile"`
		Namespaces  []string `json:"namespaces"`
		ClusterPart bool     `json:"cluster_part"`
	}{Format: 1, Profile: hex.EncodeToString(profile[:]), Namespaces: names, ClusterPart: clusterPart})
	if err != nil {
		return [32]byte{}, invalid("the scope does not encode")
	}
	return sha256.Sum256(append([]byte(scopeHashDomain), encoded...)), nil
}
