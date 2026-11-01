// Package connectionlog holds a Workspace's storage credentials and a
// Network's connection log settings (connection logs design §10, §16b).
// Core never holds an opened credential: the secret arrives sealed to the
// connection log receiver's key.
package connectionlog

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/shared/flowlog"
)

var (
	// ErrInvalid reports input outside the bounds below.
	ErrInvalid = errors.New("connection log: invalid")
	// ErrForbidden reports a caller without the permission.
	ErrForbidden = errors.New("connection log: forbidden")
	// ErrNotFound reports an unknown credential or Network.
	ErrNotFound = errors.New("connection log: not found")
	// ErrConflict reports a stale version.
	ErrConflict = errors.New("connection log: version changed")
	// ErrInUse reports a credential a Network sends with.
	ErrInUse = errors.New("connection log: credential in use")
	// ErrNotAllowed reports a Workspace without the feature, or a
	// credential that does not allow the Network.
	ErrNotAllowed = errors.New("connection log: not allowed")
	// ErrNameTaken reports another credential of the Workspace with the
	// name.
	ErrNameTaken = errors.New("connection log: credential name taken")
	// ErrLimit reports a Workspace at MaxCredentials.
	ErrLimit = errors.New("connection log: credential limit reached")
	// ErrNotConfigured reports a deployment without a receiver key: no
	// secret can be sealed until an operator sets one.
	ErrNotConfigured = errors.New("connection log: receiver not configured")
	// ErrUnavailable reports a failure of Core's own.
	ErrUnavailable = errors.New("connection log: unavailable")
)

// Bounds, as the schema's (schema 266).
const (
	MinimumWindowSeconds = 60
	MaximumWindowSeconds = 300
	DefaultWindowSeconds = 60
	MaximumNetworks      = 1000
	// MaxCredentials bounds a Workspace's credentials, and so its listing.
	MaxCredentials = 50
)

var (
	namePattern   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9 ._-]{0,62}[A-Za-z0-9])?$`)
	bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	regionPattern = regexp.MustCompile(`^(us|eu|ap|sa|ca|me|af|il|mx)-[a-z]{4,10}-[1-9]$`)
	prefixPattern = regexp.MustCompile(`^[a-z0-9_/-]{0,128}$`)
	accountID     = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// ValidName reports a credential name: 1 to 64 letters, digits, spaces,
// dots, underscores and hyphens, starting and ending with a letter or digit.
func ValidName(name string) bool { return namePattern.MatchString(name) }

// ValidBucket reports an S3 or R2 bucket name without dots.
func ValidBucket(bucket string) bool {
	return bucketPattern.MatchString(bucket) && !strings.HasPrefix(bucket, "xn--") &&
		!strings.HasPrefix(bucket, "sthree-") && !strings.HasSuffix(bucket, "-s3alias") &&
		!strings.HasSuffix(bucket, "--ol-s3") && !strings.HasSuffix(bucket, "--x-s3")
}

// ValidRegion reports a region of provider: an AWS region name, "auto" for
// R2. The receiver builds the endpoint from it, so it is a pattern, never a
// host.
func ValidRegion(provider, region string) bool {
	switch provider {
	case flowlog.ProviderR2:
		return region == "auto"
	case flowlog.ProviderS3:
		return regionPattern.MatchString(region)
	default:
		return false
	}
}

// ValidPrefix reports an object key prefix: lower case, digits, "_", "/"
// and "-", at most 128 bytes, no leading slash, "//" or "..".
func ValidPrefix(prefix string) bool {
	return prefixPattern.MatchString(prefix) && !strings.HasPrefix(prefix, "/") &&
		!strings.Contains(prefix, "//") && !strings.Contains(prefix, "..")
}

// ValidAccountID reports a Cloudflare account ID.
func ValidAccountID(account string) bool { return accountID.MatchString(account) }

// CredentialID is a storage credential's public ID.
type CredentialID publicid.ID

// String is the UUID text.
func (id CredentialID) String() string { return publicid.ID(id).String() }

// Credential is a storage credential as the API shows it: never its secret.
type Credential struct {
	ID              CredentialID
	Name            string
	Provider        string
	AccountID       string
	AccessKeySuffix string
	Version         int64
	// SealedVersion is the version the secret was sealed under, which the
	// receiver binds when it opens it; a rename keeps it.
	SealedVersion int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
	// Networks may send with it; UsedBy do.
	Networks []network.ID
	UsedBy   []network.ID
}

// Credentials is a Workspace's credentials and whether it has the feature.
type Credentials struct {
	Feature     bool
	Credentials []Credential
}

// CredentialPut creates (ExpectedVersion 0), rotates (Secret set) or
// re-scopes a credential.
type CredentialPut struct {
	Session         accountsession.Session
	Workspace       workspace.ID
	ID              CredentialID
	ExpectedVersion int64
	Name            string
	Provider        string
	AccountID       string
	// Secret is nil when only the name or Networks change.
	Secret        *flowlog.Credential
	Networks      []network.ID
	CorrelationID publicid.ID
}

// Check holds a put to the bounds Core stores.
func (put CredentialPut) Check() error {
	if put.ExpectedVersion < 0 || !ValidName(put.Name) || len(put.Networks) > MaximumNetworks ||
		(put.ExpectedVersion == 0) && put.Secret == nil {
		return ErrInvalid
	}
	switch put.Provider {
	case flowlog.ProviderS3:
		if put.AccountID != "" {
			return ErrInvalid
		}
	case flowlog.ProviderR2:
		if !ValidAccountID(put.AccountID) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if put.Secret != nil && put.Secret.Check(put.Provider) != nil {
		return ErrInvalid
	}
	seen := map[network.ID]bool{}
	for _, id := range put.Networks {
		if seen[id] {
			return ErrInvalid
		}
		seen[id] = true
	}
	return nil
}

// CredentialDeletion deletes a credential no Network sends with.
type CredentialDeletion struct {
	Session         accountsession.Session
	Workspace       workspace.ID
	ID              CredentialID
	ExpectedVersion int64
	CorrelationID   publicid.ID
}

// Settings are a Network's connection log settings; version 0 is unset
// and off.
type Settings struct {
	Enabled       bool
	Credential    *CredentialID
	Bucket        string
	Region        string
	Prefix        string
	Forwarded     bool
	WindowSeconds int
	Version       int64
	UpdatedAt     time.Time
}

// NetworkSettings is what a Network's reader sees.
type NetworkSettings struct {
	Feature  bool
	Settings Settings
}

// SettingsReplacement replaces a Network's settings when ExpectedVersion is
// current.
type SettingsReplacement struct {
	Session         accountsession.Session
	Scope           network.Scope
	ExpectedVersion int64
	Settings        Settings
	CorrelationID   publicid.ID
}

// Check holds a replacement to the bounds Core stores; the region is
// checked against the credential's provider by the store.
func (replacement SettingsReplacement) Check() error {
	settings := replacement.Settings
	if replacement.ExpectedVersion < 0 || settings.WindowSeconds < MinimumWindowSeconds ||
		settings.WindowSeconds > MaximumWindowSeconds || !ValidPrefix(settings.Prefix) ||
		(settings.Credential == nil) != (settings.Bucket == "") || (settings.Credential == nil) && settings.Region != "" ||
		settings.Enabled && settings.Credential == nil || settings.Bucket != "" && !ValidBucket(settings.Bucket) {
		return ErrInvalid
	}
	return nil
}

// SettingsResult is a replacement's outcome.
type SettingsResult struct {
	Settings Settings
	Changed  bool
	// Feature reports whether the Workspace has connection logs.
	Feature bool
}
