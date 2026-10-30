// Package kubeprofile decides what a Kubernetes access profile lets through a
// cluster's gateway (K2 design). A profile only narrows: what reaches the
// API server still carries the token of the cluster group, so the cluster's
// RBAC stays the ceiling (K2-I1). Its rules read as RBAC's PolicyRule and match as the RBAC
// authorizer does, except where the design is stricter on purpose (S1–S7).
// The gateway, Core's Explain and the Console's preview share this package
// so that the three never disagree.
package kubeprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Bounds of a profile (K2 §7.4).
const (
	maximumRules    = 64
	maximumElements = 32
	maximumBytes    = 16 << 10
	maximumName     = 253
)

// hashDomain separates a profile's content hash from every other hash.
const hashDomain = "meshtransit.net/kubeprofile/v1\x00"

// ErrInvalid reports a profile or scope that breaks the format.
var ErrInvalid = errors.New("kubeprofile: invalid")

// Profile is what a rule may do: Namespaced in the namespaces of the Policy
// rule that uses it, Cluster on cluster-scoped resources and paths when the
// rule turns that part on.
type Profile struct {
	Name       string `json:"name"`
	Namespaced []Rule `json:"namespaced,omitempty"`
	Cluster    []Rule `json:"cluster,omitempty"`
}

// Rule is RBAC's PolicyRule: a resource rule (APIGroups, Resources, maybe
// ResourceNames) or, in the cluster part only, a path rule
// (NonResourceURLs).
type Rule struct {
	APIGroups       []string `json:"apiGroups,omitempty"`
	Resources       []string `json:"resources,omitempty"`
	Verbs           []string `json:"verbs,omitempty"`
	ResourceNames   []string `json:"resourceNames,omitempty"`
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`
}

// Normalize returns a copy with every list sorted and without duplicates,
// and the rules of each part sorted and distinct: the same rights in any
// order normalize alike. It does not check the profile.
func Normalize(profile Profile) Profile {
	return Profile{Name: profile.Name, Namespaced: normalizeRules(profile.Namespaced),
		Cluster: normalizeRules(profile.Cluster)}
}

func normalizeRules(rules []Rule) []Rule {
	if len(rules) == 0 {
		return nil
	}
	type keyed struct {
		rule Rule
		key  []byte
	}
	out := make([]keyed, 0, len(rules))
	for _, rule := range rules {
		normalized := Rule{APIGroups: sortedSet(rule.APIGroups), Resources: sortedSet(rule.Resources),
			Verbs: sortedSet(rule.Verbs), ResourceNames: sortedSet(rule.ResourceNames),
			NonResourceURLs: sortedSet(rule.NonResourceURLs)}
		key, _ := json.Marshal(normalized) // A Rule always encodes.
		out = append(out, keyed{rule: normalized, key: key})
	}
	slices.SortFunc(out, func(left, right keyed) int { return bytes.Compare(left.key, right.key) })
	out = slices.CompactFunc(out, func(left, right keyed) bool { return bytes.Equal(left.key, right.key) })
	normalized := make([]Rule, len(out))
	for index, rule := range out {
		normalized[index] = rule.rule
	}
	return normalized
}

func sortedSet(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := slices.Clone(values)
	slices.Sort(out)
	return slices.Compact(out)
}

// Validate reports ErrInvalid, wrapped with the reason, unless the profile
// keeps the format and bounds of K2 §5.1 and §7.4 once normalized.
func Validate(profile Profile) error {
	_, err := canonical(profile)
	return err
}

// ContentHash is the SHA-256 a Policy release pins: of the format, the name
// and both parts, normalized.
func ContentHash(profile Profile) ([32]byte, error) {
	encoded, err := canonical(profile)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append([]byte(hashDomain), encoded...)), nil
}

// canonical validates the normalized profile and returns its encoding. The
// raw counts are bounded first: duplicates do not buy a larger input, nor
// work before the bounds (review K2a M2).
func canonical(profile Profile) ([]byte, error) {
	if err := checkCounts(profile); err != nil {
		return nil, err
	}
	normalized := Normalize(profile)
	if err := checkProfile(normalized); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(struct {
		Format int `json:"format"`
		Profile
	}{Format: 1, Profile: normalized})
	if err != nil {
		return nil, invalid("the profile does not encode")
	}
	if len(encoded) > maximumBytes {
		return nil, invalid("the profile is over %d bytes", maximumBytes)
	}
	return encoded, nil
}

func checkCounts(profile Profile) error {
	if len(profile.Namespaced) > maximumRules || len(profile.Cluster) > maximumRules {
		return invalid("a part has more than %d rules", maximumRules)
	}
	for _, rules := range [][]Rule{profile.Namespaced, profile.Cluster} {
		for _, rule := range rules {
			for _, values := range [][]string{rule.APIGroups, rule.Resources, rule.Verbs, rule.ResourceNames,
				rule.NonResourceURLs} {
				if len(values) > maximumElements {
					return invalid("a rule lists more than %d entries", maximumElements)
				}
			}
		}
	}
	return nil
}

func checkProfile(profile Profile) error {
	if !dnsLabel(profile.Name) {
		return invalid("the name is not a DNS label")
	}
	if len(profile.Namespaced)+len(profile.Cluster) == 0 {
		return invalid("the profile has no rule")
	}
	if len(profile.Namespaced) > maximumRules || len(profile.Cluster) > maximumRules {
		return invalid("a part has more than %d rules", maximumRules)
	}
	for _, rule := range profile.Namespaced {
		if len(rule.NonResourceURLs) > 0 {
			return invalid("a path rule is in the namespaced part")
		}
		if err := checkResourceRule(rule); err != nil {
			return err
		}
	}
	for _, rule := range profile.Cluster {
		var err error
		if len(rule.NonResourceURLs) > 0 {
			err = checkPathRule(rule)
		} else {
			err = checkResourceRule(rule)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func checkResourceRule(rule Rule) error {
	if err := checkVerbs(rule.Verbs); err != nil {
		return err
	}
	if err := checkList("apiGroups", rule.APIGroups, apiGroup); err != nil {
		return err
	}
	if err := checkList("resources", rule.Resources, resource); err != nil {
		return err
	}
	if len(rule.ResourceNames) > maximumElements {
		return invalid("resourceNames has more than %d entries", maximumElements)
	}
	for _, name := range rule.ResourceNames {
		if !resourceName(name) {
			return invalid("resource name %q is not allowed", name)
		}
	}
	return nil
}

func checkPathRule(rule Rule) error {
	if len(rule.APIGroups)+len(rule.Resources)+len(rule.ResourceNames) > 0 {
		return invalid("a path rule names resources")
	}
	if err := checkVerbs(rule.Verbs); err != nil {
		return err
	}
	return checkList("nonResourceURLs", rule.NonResourceURLs, nonResourceURL)
}

func checkVerbs(verbs []string) error {
	return checkList("verbs", verbs, func(verb string) bool {
		return verb == verbAll || len(verb) <= 32 && lowercaseWord(verb)
	})
}

func checkList(field string, values []string, valid func(string) bool) error {
	if len(values) == 0 || len(values) > maximumElements {
		return invalid("%s needs 1 to %d entries", field, maximumElements)
	}
	for _, value := range values {
		if !valid(value) {
			return invalid("%s entry %q is not allowed", field, value)
		}
	}
	return nil
}

func invalid(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, arguments...))
}

// apiGroup is the core group (""), any group or a DNS subdomain.
func apiGroup(group string) bool {
	if group == "" || group == apiGroupAll {
		return true
	}
	if len(group) > maximumName {
		return false
	}
	for label := range strings.SplitSeq(group, ".") {
		if !dnsLabel(label) {
			return false
		}
	}
	return true
}

// resource is "*", "*/subresource", "resource" or "resource/subresource".
// "resource/*" is refused: RBAC matches it only literally.
func resource(value string) bool {
	if value == resourceAll {
		return true
	}
	name, subresource, hasSubresource := strings.Cut(value, "/")
	if !hasSubresource {
		return dnsLabel(name)
	}
	return (name == resourceAll || dnsLabel(name)) && dnsLabel(subresource)
}

// htmlEscaped are the characters Go's JSON encoder escapes beyond '"' and
// '\\': refused, so that the canonical form needs no encoder's choice
// (mtcp-v1 §7.12).
func htmlEscaped(character byte) bool {
	return character == '<' || character == '>' || character == '&'
}

// resourceName is an object's name: printable ASCII without '/', '%', '<',
// '>' or '&'.
func resourceName(name string) bool {
	if name == "" || len(name) > maximumName {
		return false
	}
	for index := range len(name) {
		character := name[index]
		if character <= ' ' || character > '~' || character == '/' || character == '%' || htmlEscaped(character) {
			return false
		}
	}
	return true
}

// nonResourceURL is "*" or an absolute path, a '*' only at its end; no '%',
// '<', '>' or '&'.
func nonResourceURL(path string) bool {
	if path == nonResourceAll {
		return true
	}
	if !strings.HasPrefix(path, "/") || len(path) > maximumName {
		return false
	}
	for index := range len(path) {
		character := path[index]
		if character <= ' ' || character > '~' || character == '%' || htmlEscaped(character) ||
			character == '*' && index != len(path)-1 {
			return false
		}
	}
	return true
}

func dnsLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for index := range len(label) {
		character := label[index]
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
			return false
		}
	}
	return true
}

func lowercaseWord(word string) bool {
	if word == "" {
		return false
	}
	for index := range len(word) {
		if word[index] < 'a' || word[index] > 'z' {
			return false
		}
	}
	return true
}
