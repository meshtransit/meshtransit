package installsecrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
)

const maximumPlanBytes = 64 << 10

var (
	// fullname is the chart's fullname or release: a DNS subdomain (Helm
	// allows dots) of at most 63 characters, so the longest item name still
	// fits 253 and a label value 63.
	fullname = regexp.MustCompile(`^[a-z0-9]([-.a-z0-9]{0,61}[a-z0-9])?$`)
	// secretName is a Kubernetes object name (DNS subdomain).
	secretName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	// secretKey is a Secret data key.
	secretKey = regexp.MustCompile(`^[-._a-zA-Z0-9]{1,253}$`)
)

// Plan is what the chart renders for the bootstrap: the profile, the
// release's fullname, the features on, and a Secret the installer brings
// for any item (BYO).
type Plan struct {
	Profile Profile `json:"profile"`
	// Release is the Helm release: Secrets an earlier chart made as hooks
	// carry it, and the bootstrap takes those over.
	Release  string              `json:"release"`
	Fullname string              `json:"fullname"`
	Features []Feature           `json:"features"`
	Secrets  map[string]Override `json:"secrets"`
	// AllowNewRetainedKeys names the retained items the bootstrap may
	// generate for a database that exists: a deliberate reset of each.
	// Remove an item once its key is made; a run reports what it made.
	AllowNewRetainedKeys []string `json:"allowNewRetainedKeys"`
}

// Override names the installer's Secret and key for an item.
type Override struct {
	ExistingSecret string `json:"existingSecret"`
	Key            string `json:"key"`
}

// Resolved is an item with the Secret and key it lives in.
type Resolved struct {
	Item
	SecretName string
	SecretKey  string
	// BYO is an installer's Secret: checked, never created.
	BYO bool
}

// ParsePlan reads and checks a plan; unknown fields are refused.
func ParsePlan(data []byte) (Plan, error) {
	if len(data) == 0 || len(data) > maximumPlanBytes {
		return Plan{}, fmt.Errorf("%w: size", ErrPlan)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var plan Plan
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, fmt.Errorf("%w: %w", ErrPlan, err)
	}
	if decoder.More() {
		return Plan{}, fmt.Errorf("%w: trailing data", ErrPlan)
	}
	if !fullname.MatchString(plan.Fullname) {
		return Plan{}, fmt.Errorf("%w: fullname", ErrPlan)
	}
	if !fullname.MatchString(plan.Release) || len(plan.Release) > 53 {
		return Plan{}, fmt.Errorf("%w: release", ErrPlan)
	}
	if _, err := plan.Resolve(); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

// Resolve lists the plan's items with their Secrets, in creation order.
func (plan Plan) Resolve() ([]Resolved, error) {
	items, err := Items(plan.Profile, plan.Features)
	if err != nil {
		return nil, err
	}
	resolved := make([]Resolved, 0, len(items))
	used := map[string]string{}
	for id, override := range plan.Secrets {
		if !slices.ContainsFunc(items, func(item Item) bool { return item.ID == id }) {
			return nil, fmt.Errorf("%w: secrets.%s is not an item of this plan", ErrPlan, id)
		}
		if !secretName.MatchString(override.ExistingSecret) || len(override.ExistingSecret) > 253 ||
			!secretKey.MatchString(override.Key) {
			return nil, fmt.Errorf("%w: secrets.%s", ErrPlan, id)
		}
	}
	for _, id := range plan.AllowNewRetainedKeys {
		if !slices.ContainsFunc(items, func(item Item) bool { return item.ID == id && item.Retained }) {
			return nil, fmt.Errorf("%w: allowNewRetainedKeys: %s is not a retained item of this plan", ErrPlan, id)
		}
	}
	for _, item := range items {
		entry := Resolved{Item: item, SecretName: SecretName(plan.Fullname, item), SecretKey: item.Key}
		if override, ok := plan.Secrets[item.ID]; ok {
			entry.SecretName, entry.SecretKey, entry.BYO = override.ExistingSecret, override.Key, true
		}
		// Two items in one place would share a value.
		place := entry.SecretName + "/" + entry.SecretKey
		if other, taken := used[place]; taken {
			return nil, fmt.Errorf("%w: %s and %s share %s", ErrPlan, other, item.ID, place)
		}
		used[place] = item.ID
		resolved = append(resolved, entry)
	}
	return resolved, nil
}

// PublicKeysConfigMap is the ConfigMap the public halves are written to.
func PublicKeysConfigMap(fullnameValue string) string { return fullnameValue + "-public-keys" }
