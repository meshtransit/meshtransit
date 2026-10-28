package kubecluster

// The Kubernetes groups a rule to a cluster grants (K1a3): names of groups the
// cluster administrator declares in the gateway's Helm values, each mapped to
// a ServiceAccount mt-<group>. Core never sends one to the API server; a name
// only selects a ServiceAccount (K1-I12).
const (
	// MaximumRuleKubernetesGroups bounds the groups one rule grants.
	MaximumRuleKubernetesGroups = 16
	// MaximumClusterKubernetesGroups bounds the distinct groups the rules of
	// one cluster grant in a release, as many as a gateway may report.
	MaximumClusterKubernetesGroups = 64
	maximumKubernetesGroupLength   = 63
)

// ValidKubernetesGroup reports an RFC 1123 DNS label: 1 to 63 lowercase
// letters, digits and hyphens, starting and ending with a letter or digit.
func ValidKubernetesGroup(name string) bool {
	if name == "" || len(name) > maximumKubernetesGroupLength {
		return false
	}
	for index := range len(name) {
		character := name[index]
		alphanumeric := character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
		if !alphanumeric && (character != '-' || index == 0 || index == len(name)-1) {
			return false
		}
	}
	return true
}
