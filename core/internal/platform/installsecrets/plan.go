package installsecrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"

	"meshtransit.net/core/internal/domain/deployment"
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
	// DeploymentPublicID is the installation's Deployment ID when the
	// installer sets one; empty takes the database's or the recorded one.
	DeploymentPublicID string `json:"deploymentPublicID"`
	// Login, when set, makes the bootstrap keep the login route's IDs for a
	// version 5 login profile: it finds them in the database by these
	// names, or makes new ones for a new installation.
	Login *LoginPlan `json:"login,omitempty"`
}

// LoginPlan names the login route the database knows its provider by.
type LoginPlan struct {
	Issuer       string `json:"issuer"`
	OIDCClientID string `json:"oidcClientID"`
}

var oidcClientID = regexp.MustCompile(`^[\x21-\x7e]{1,256}$`)

func (login LoginPlan) valid() bool {
	issuer, err := url.Parse(login.Issuer)
	return err == nil && issuer.Scheme == "https" && issuer.Host != "" && issuer.User == nil &&
		issuer.RawQuery == "" && issuer.Fragment == "" && len(login.Issuer) <= 2048 &&
		oidcClientID.MatchString(login.OIDCClientID)
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
	if plan.DeploymentPublicID != "" {
		if _, err := deployment.ParseID(plan.DeploymentPublicID); err != nil {
			return Plan{}, fmt.Errorf("%w: deploymentPublicID", ErrPlan)
		}
	}
	if plan.Login != nil && !plan.Login.valid() {
		return Plan{}, fmt.Errorf("%w: login", ErrPlan)
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

// InstallConfigMap is the ConfigMap the installation's Deployment ID is
// recorded in, immutable, for the pods.
func InstallConfigMap(fullnameValue string) string { return fullnameValue + "-install" }

// LoginIDsConfigMap holds the login route's provider and client IDs,
// immutable.
func LoginIDsConfigMap(fullnameValue string) string { return fullnameValue + "-login-ids" }

// LoginStateConfigMap holds the login provider's generation and the
// recovery epoch, which follow the database.
func LoginStateConfigMap(fullnameValue string) string { return fullnameValue + "-login-state" }

// PublicKeysConfigMap is the ConfigMap the public halves are written to.
func PublicKeysConfigMap(fullnameValue string) string { return fullnameValue + "-public-keys" }
