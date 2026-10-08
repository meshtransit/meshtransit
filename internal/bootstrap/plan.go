// Package bootstrap builds the reviewed installation plan for an empty or
// partially bootstrapped Deployment (ADR-050 implementation step 4).
//
// The plan combines the private login route (provider, client, issuer and
// endpoints come from the same file meshcore serves, so the rows always match
// what login checks) with a small accounts file naming the provisioned
// identities. Applying the plan is idempotent: existing rows are verified,
// never changed, and missing rows are created with audit evidence.
package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/workspace/settings"
)

// Format is the only accepted accounts file format.
const Format = "meshtransit-bootstrap/v1"

const (
	// MaxPlanBytes bounds the accounts file.
	MaxPlanBytes   = 64 << 10
	maxAccounts    = 100
	maxNameBytes   = 128
	maxSubjectSize = 255
	maxAssurance   = 255
)

// ErrInvalidPlan reports a malformed accounts file or route. It never echoes
// subjects or names.
var ErrInvalidPlan = errors.New("bootstrap: invalid plan")

// Account is one provisioned identity and its Default Workspace.
type Account struct {
	DisplayName   string
	WorkspaceName string
	SubjectDigest oidcauth.SubjectDigest
}

// Plan is a validated installation plan. Only NewPlan constructs it.
type Plan struct {
	Profile          deployment.Profile
	Route            oidcauth.Route
	MinimumAssurance string
	Accounts         []Account
}

type accountsFile struct {
	Format           string        `json:"format"`
	Profile          string        `json:"profile"`
	MinimumAssurance *string       `json:"minimum_assurance"`
	Accounts         []accountLine `json:"accounts"`
}

// accountLine names one Account by its raw OIDC subject, or by the subject
// digest already stored for it (lowercase hex). The digest form re-creates an
// Account whose raw subject was never retained, for example when a deployment
// is rebuilt with the same provider and subject key; it must have been
// computed with the active subject key.
type accountLine struct {
	Subject       string `json:"subject,omitempty"`
	SubjectDigest string `json:"subject_digest,omitempty"`
	DisplayName   string `json:"display_name"`
	WorkspaceName string `json:"workspace_name"`
}

// NewPlan parses the accounts file and derives each subject digest with the
// active login subject key, exactly as login will.
func NewPlan(contents []byte, route oidcauth.Route, key oidcauth.SubjectKey) (Plan, error) {
	if len(contents) == 0 || len(contents) > MaxPlanBytes || !route.IsValid() {
		return Plan{}, ErrInvalidPlan
	}
	var file accountsFile
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&file) != nil || file.Format != Format {
		return Plan{}, ErrInvalidPlan
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Plan{}, ErrInvalidPlan
	}
	profile := deployment.Profile(file.Profile)
	// A Cloud deployment may start without Accounts: people sign up. A
	// self-hosted one needs its first owner here.
	noAccountsAllowed := profile == deployment.ProfileCloud
	if !profile.IsValid() || (len(file.Accounts) == 0 && !noAccountsAllowed) || len(file.Accounts) > maxAccounts {
		return Plan{}, ErrInvalidPlan
	}
	plan := Plan{Profile: profile, Route: route, Accounts: make([]Account, 0, len(file.Accounts))}
	if file.MinimumAssurance != nil {
		if !validLabel(*file.MinimumAssurance, maxAssurance) {
			return Plan{}, ErrInvalidPlan
		}
		plan.MinimumAssurance = *file.MinimumAssurance
	}
	seen := make(map[[32]byte]bool, len(file.Accounts))
	for _, line := range file.Accounts {
		if len(line.Subject) > maxSubjectSize || !validLabel(line.DisplayName, maxNameBytes) ||
			!settings.ValidName(line.WorkspaceName) {
			return Plan{}, ErrInvalidPlan
		}
		digest, err := accountDigest(line, route, key)
		if err != nil || seen[digest.Bytes()] {
			return Plan{}, ErrInvalidPlan
		}
		seen[digest.Bytes()] = true
		plan.Accounts = append(plan.Accounts, Account{
			DisplayName: line.DisplayName, WorkspaceName: line.WorkspaceName, SubjectDigest: digest,
		})
	}
	return plan, nil
}

// accountDigest accepts exactly one of the raw subject and its stored digest.
func accountDigest(line accountLine, route oidcauth.Route, key oidcauth.SubjectKey) (oidcauth.SubjectDigest, error) {
	switch {
	case line.Subject != "" && line.SubjectDigest == "":
		return oidcauth.NewSubjectMigrationDigest(route.DeploymentID(), route.ProviderID(), key,
			route.Issuer(), line.Subject)
	case line.Subject == "" && line.SubjectDigest != "":
		raw, err := hex.DecodeString(line.SubjectDigest)
		if err != nil || len(raw) != sha256.Size || hex.EncodeToString(raw) != line.SubjectDigest {
			return oidcauth.SubjectDigest{}, ErrInvalidPlan
		}
		return oidcauth.NewSubjectDigest(key.ID(), [sha256.Size]byte(raw))
	default:
		return oidcauth.SubjectDigest{}, ErrInvalidPlan
	}
}

func validLabel(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
