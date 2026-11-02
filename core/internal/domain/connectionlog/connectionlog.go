// Package connectionlog holds a Workspace's storage credentials and a
// Network's connection log settings (connection logs design §10, §16b).
// Core never holds an opened credential: the secret arrives sealed to the
// connection log receiver's key.
package connectionlog

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

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

// Push reports a push destination provider (push destinations design §2).
func Push(provider string) bool {
	return provider == flowlog.ProviderElasticsearch || provider == flowlog.ProviderDatadog ||
		provider == flowlog.ProviderKinesis
}

// Storage reports an object storage provider.
func Storage(provider string) bool {
	return provider == flowlog.ProviderS3 || provider == flowlog.ProviderR2
}

// Destination is a push credential's non-secret fields: where its sealed
// secret may be sent, bound into it (push destinations design §5 S1). It
// is empty for S3 and R2.
type Destination struct {
	// Elasticsearch/OpenSearch: URL is canonical (flowlog.CanonicalURL).
	URL    string
	Flavor string
	// CAPEM is a custom CA, only ever sent in; CASHA256 is all Core shows
	// of it.
	CAPEM    []byte
	CASHA256 string
	// Datadog.
	Site string
	// Kinesis: Region is the StreamARN's.
	Region    string
	StreamARN string
}

// Empty reports no field set.
func (destination Destination) Empty() bool {
	return destination.URL == "" && destination.Flavor == "" && len(destination.CAPEM) == 0 &&
		destination.CASHA256 == "" && destination.Site == "" && destination.Region == "" && destination.StreamARN == ""
}

// Check holds the fields a provider takes to the bounds the receiver
// binds; CASHA256 is Core's to compute, never taken.
func (destination Destination) Check(provider string) error {
	switch provider {
	case flowlog.ProviderS3, flowlog.ProviderR2:
		if !destination.Empty() {
			return ErrInvalid
		}
	case flowlog.ProviderElasticsearch:
		canonical, err := flowlog.CanonicalURL(destination.URL)
		if err != nil || canonical != destination.URL || len(canonical) > 512 || destination.CASHA256 != "" ||
			len(destination.CAPEM) != 0 && !ValidCAPEM(destination.CAPEM) ||
			destination.Flavor != flowlog.FlavorElasticsearch && destination.Flavor != flowlog.FlavorOpenSearch ||
			len(destination.CAPEM) > flowlog.MaxCAPEM || destination.Site != "" || destination.Region != "" ||
			destination.StreamARN != "" {
			return ErrInvalid
		}
	case flowlog.ProviderDatadog:
		if !flowlog.ValidDatadogSite(destination.Site) || destination.URL != "" || destination.Flavor != "" ||
			len(destination.CAPEM) != 0 || destination.CASHA256 != "" || destination.Region != "" ||
			destination.StreamARN != "" {
			return ErrInvalid
		}
	case flowlog.ProviderKinesis:
		region, ok := flowlog.ParseStreamARN(destination.StreamARN)
		if !ok || region != destination.Region || destination.URL != "" || destination.Flavor != "" ||
			len(destination.CAPEM) != 0 || destination.CASHA256 != "" || destination.Site != "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// ValidCAPEM reports a custom CA as Core stores it and the receiver binds
// it, byte for byte: UTF-8 without control characters but line breaks and
// tabs, one or more X.509 certificates in PEM, nothing else
// (review p1b M4).
func ValidCAPEM(pemText []byte) bool {
	if len(pemText) == 0 || len(pemText) > flowlog.MaxCAPEM || !utf8.Valid(pemText) ||
		bytes.ContainsFunc(pemText, func(r rune) bool { return r < 0x20 && r != '\n' && r != '\r' && r != '\t' || r == 0x7f }) {
		return false
	}
	rest, certificates := pemText, 0
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		certificates++
		rest = remaining
	}
	return certificates > 0 && len(bytes.TrimSpace(rest)) == 0
}

// CredentialID is a storage credential's public ID.
type CredentialID publicid.ID

// String is the UUID text.
func (id CredentialID) String() string { return publicid.ID(id).String() }

// Credential is a storage credential as the API shows it: never its secret.
type Credential struct {
	ID        CredentialID
	Name      string
	Provider  string
	AccountID string
	// Destination is a push credential's fields, without its CA.
	Destination     Destination
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
	// Secret (S3, R2) or PushSecret (push providers) is nil when only the
	// name or Networks change. Destination comes with PushSecret only: it is
	// bound into it, so it changes only with it (push destinations §5 S1).
	Secret        *flowlog.Credential
	PushSecret    *flowlog.Secret
	Destination   Destination
	Networks      []network.ID
	CorrelationID publicid.ID
}

// Check holds a put to the bounds Core stores.
func (put CredentialPut) Check() error {
	if put.ExpectedVersion < 0 || !ValidName(put.Name) || len(put.Networks) > MaximumNetworks ||
		put.Secret != nil && put.PushSecret != nil {
		return ErrInvalid
	}
	if put.ExpectedVersion == 0 && put.Secret == nil && put.PushSecret == nil {
		return ErrInvalid
	}
	switch {
	case put.Provider == flowlog.ProviderS3 && put.AccountID != "",
		put.Provider == flowlog.ProviderR2 && !ValidAccountID(put.AccountID),
		Storage(put.Provider) && (put.PushSecret != nil || !put.Destination.Empty()),
		Push(put.Provider) && (put.AccountID != "" || put.Secret != nil),
		!Storage(put.Provider) && !Push(put.Provider):
		return ErrInvalid
	}
	if put.Secret != nil && put.Secret.Check(put.Provider) != nil {
		return ErrInvalid
	}
	if put.PushSecret != nil {
		// OpenSearch takes no Elastic API key (review p1a M3).
		if put.PushSecret.Check(put.Provider) != nil || put.Destination.Check(put.Provider) != nil ||
			put.Destination.Flavor == flowlog.FlavorOpenSearch && put.PushSecret.Kind == flowlog.SecretAPIKey {
			return ErrInvalid
		}
	} else if !put.Destination.Empty() {
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
	// ExpectedBucketOwner is the 12-digit AWS account that owns an S3
	// bucket, or empty: the credential's own account (C52).
	ExpectedBucketOwner string
	// The fields of a push destination's type (push destinations §6):
	// Elasticsearch/OpenSearch a Target and its TargetKind; Datadog a
	// Service and Tags; Kinesis a RecordFormat.
	Target       string
	TargetKind   string
	Service      string
	Tags         []string
	RecordFormat string
	Version      int64
	UpdatedAt    time.Time
}

// Push destination field values.
const (
	TargetKindDataStream    = "data_stream"
	TargetKindIndex         = "index"
	RecordFormatNDJSONBatch = "ndjson_batch"
	RecordFormatJSONLine    = "json_line"
	DefaultDatadogService   = "meshtransit-connections"
	MaximumDatadogTags      = 20
)

var datadogTag = regexp.MustCompile(`^[a-z][a-z0-9_.:/-]*$`)

// ValidDatadogTag reports a Datadog tag (or, within 100 bytes, a service):
// lower case, starting with a letter, no commas, at most limit bytes.
func ValidDatadogTag(tag string, limit int) bool {
	return len(tag) <= limit && datadogTag.MatchString(tag)
}

// checkPush holds the push fields to their shapes; which of them a
// credential's type takes is checked against its provider by the store.
func (settings Settings) checkPush() bool {
	if settings.Credential == nil && (settings.Target != "" || settings.Service != "" || settings.RecordFormat != "") {
		return false
	}
	if (settings.Target == "") != (settings.TargetKind == "") || settings.Target != "" && !flowlog.ValidTarget(settings.Target) ||
		settings.TargetKind != "" && settings.TargetKind != TargetKindDataStream && settings.TargetKind != TargetKindIndex {
		return false
	}
	if settings.Service != "" && !ValidDatadogTag(settings.Service, 100) ||
		settings.Tags != nil && settings.Service == "" || len(settings.Tags) > MaximumDatadogTags {
		return false
	}
	for _, tag := range settings.Tags {
		if !ValidDatadogTag(tag, 200) {
			return false
		}
	}
	return settings.RecordFormat == "" || settings.RecordFormat == RecordFormatNDJSONBatch ||
		settings.RecordFormat == RecordFormatJSONLine
}

// NetworkSettings is what a Network's reader sees.
type NetworkSettings struct {
	Feature  bool
	Settings Settings
	// Status is the rows behind the settings' status (schema 271).
	Status StatusRows
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
		settings.WindowSeconds > MaximumWindowSeconds || !ValidPrefix(settings.Prefix) || !settings.checkPush() ||
		(settings.Credential == nil) && (settings.Bucket != "" || settings.Region != "") ||
		settings.Enabled && settings.Credential == nil || settings.Bucket != "" && !ValidBucket(settings.Bucket) ||
		settings.ExpectedBucketOwner != "" && (settings.Credential == nil || !ValidBucketOwner(settings.ExpectedBucketOwner)) {
		return ErrInvalid
	}
	return nil
}

// ValidBucketOwner reports a 12-digit AWS account ID. Only an S3
// destination may name one; the store checks the provider.
func ValidBucketOwner(owner string) bool {
	if len(owner) != 12 {
		return false
	}
	for _, digit := range owner {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

// SettingsResult is a replacement's outcome.
type SettingsResult struct {
	Settings Settings
	Changed  bool
	// Feature reports whether the Workspace has connection logs.
	Feature bool
}
