// Package signing signs Kubernetes gateway replica certificates for the
// worker (K1a4a a3, the a3 signing design): it claims queued
// requests, checks again the pod token or the renewal signature each one
// carries, signs it with its cluster's active intermediate and issues it
// through the store, which checks the Device, cluster and CA again in the
// same transaction.
package signing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// Capability names what a signing worker does, for control to read (§3).
const Capability = "ca.sign1"

// Proof is how a request proves the pod asks.
type Proof uint8

const (
	// ProofUnknown is never valid.
	ProofUnknown Proof = iota
	// ProofToken is the pod's ServiceAccount token: the first request after
	// the pod starts.
	ProofToken
	// ProofRenewal is a signature by the key of a certificate the gateway
	// still holds.
	ProofRenewal
)

// Reason says why a request was refused; it reaches the gateway.
type Reason string

// Reasons the worker refuses for (a3 §4 step 2).
const (
	ReasonNoCA           Reason = "no_ca"
	ReasonMisnamed       Reason = "misnamed"
	ReasonTrustMissing   Reason = "trust_missing"
	ReasonToken          Reason = "token"
	ReasonProof          Reason = "proof"
	ReasonRenewalExpired Reason = "renewal_expired"
	ReasonCSR            Reason = "csr"
	// ReasonAttempts is the database's: three leases ran out.
	ReasonAttempts Reason = "attempts"
	// ReasonInternal is a claim the worker failed on (a panic while
	// signing it, review §14 R-L4).
	ReasonInternal Reason = "internal"
)

// Reasons the database gives when it refuses to issue (schema 240).
const (
	ReasonRevoked      Reason = "revoked"
	ReasonCluster      Reason = "cluster"
	ReasonTokenExpired Reason = "token_expired"
	ReasonTokenUsed    Reason = "token_used"
	// ReasonSuperseded: the pod started again and asked anew (§14 R-M2).
	ReasonSuperseded Reason = "superseded"
)

// KnownReasons is every reason a refusal is counted under; any other is
// counted as ReasonOther.
var KnownReasons = []Reason{
	ReasonNoCA, ReasonMisnamed, ReasonTrustMissing, ReasonToken, ReasonProof, ReasonRenewalExpired, ReasonCSR,
	ReasonRevoked, ReasonCluster, ReasonTokenExpired, ReasonTokenUsed, ReasonAttempts, ReasonInternal,
	ReasonSuperseded, ReasonOther,
}

// ReasonOther counts a refusal for a reason this build does not know.
const ReasonOther Reason = "other"

// Known reports a reason in KnownReasons.
func (reason Reason) Known() bool {
	for _, known := range KnownReasons {
		if reason == known {
			return true
		}
	}
	return false
}

// Trust is what a token request's pod token must match: the cluster's
// signing trust and the pod the Device's join named.
type Trust struct {
	Version        int64
	Issuer         string
	JWKS           []byte
	Namespace      string
	ServiceAccount string
	PodName        string
}

// Complete reports a trust a token can be checked against.
func (trust Trust) Complete() bool {
	return trust.Version >= 1 && trust.Issuer != "" && len(trust.JWKS) > 0 && trust.Namespace != "" &&
		trust.ServiceAccount != "" && trust.PodName != ""
}

// Intermediate is a cluster's active intermediate as stored, with its root
// and the data key that sealed it.
type Intermediate struct {
	ID              publicid.ID
	Version         int64
	Certificate     []byte
	SealedKey       []byte
	ClusterDNSName  string
	NotAfter        time.Time
	RootID          publicid.ID
	RootCertificate []byte
	DataKey         kubeca.StoredDataKey
}

// ClaimToken is the random UUID that proves a claim still holds a request.
type ClaimToken [16]byte

// IsZero reports no token.
func (token ClaimToken) IsZero() bool { return token == ClaimToken{} }

// String is the token's canonical UUID form.
func (token ClaimToken) String() string {
	encoded := hex.EncodeToString(token[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

// ParseClaimToken parses a canonical lowercase UUID.
func ParseClaimToken(value string) (ClaimToken, error) {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return ClaimToken{}, kubeca.ErrInvalid
	}
	compact := value[0:8] + value[9:13] + value[14:18] + value[19:23] + value[24:]
	decoded, err := hex.DecodeString(compact)
	if err != nil || hex.EncodeToString(decoded) != compact {
		return ClaimToken{}, kubeca.ErrInvalid
	}
	token := ClaimToken(decoded)
	if token.IsZero() {
		return ClaimToken{}, kubeca.ErrInvalid
	}
	return token, nil
}

// Claim is a request the worker holds until its lease ends. Token is a
// bearer credential: Claim never formats it. A token request carries either
// its Token or, once a worker checked it, the claims it checked (Verified):
// the token leaves the database at the first claim (§14 R-M1).
type Claim struct {
	ID               publicid.ID
	ClaimToken       ClaimToken
	RequestID        [16]byte
	Scope            network.Scope
	DeviceID         publicid.ID
	ClusterID        publicid.ID
	ClusterName      string
	WorkspaceCode    string
	NetworkCode      string
	CSR              []byte
	PublicKeySHA256  [sha256.Size]byte
	Proof            Proof
	Token            string `json:"-"`
	Verified         *VerifiedToken
	HandshakeHash    [32]byte
	RenewalProof     []byte
	RenewalPublicKey []byte
	RenewalSerial    [16]byte
	RenewalNotAfter  time.Time
	Trust            *Trust
	Intermediate     *Intermediate
}

// String redacts the claim, which carries a token.
func (Claim) String() string { return "signing.Claim([REDACTED])" }

// GoString redacts detailed formatting.
func (Claim) GoString() string { return "signing.Claim([REDACTED])" }

// LogValue redacts structured formatting.
func (Claim) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Batch is what one claim returned: the database's clock, the DNS suffix
// recorded for the installation, and the claims. Nothing is claimed when a
// restore is suspected (Suspected), or when the restore tripwire was not
// checked within 10 minutes (Unchecked, §14 R-M9).
type Batch struct {
	Now       time.Time
	Suffix    string
	Suspected bool
	Unchecked bool
	// Pending counts the requests still waiting after the claim.
	Pending int64
	// RefusedAttempts counts the requests this claim refused after three
	// leases ran out.
	RefusedAttempts int64
	Claims          []Claim
}

// TokenUse is a verified pod token's evidence: used once for the
// certificate's key.
type TokenUse struct {
	JTI       string
	ExpiresAt time.Time
	PodName   string
}

// VerifiedToken is what a worker checked in a pod token and recorded in
// place of it: the token's evidence and the signing trust it was checked
// against.
type VerifiedToken struct {
	Use          TokenUse
	TrustVersion int64
}

// Valid reports complete claims.
func (verified VerifiedToken) Valid() bool {
	return verified.Use.JTI != "" && !verified.Use.ExpiresAt.IsZero() && verified.Use.PodName != "" &&
		verified.TrustVersion >= 1
}

// Issue is a signed certificate for the request a claim holds.
type Issue struct {
	Request     publicid.ID
	ClaimToken  ClaimToken
	ID          publicid.ID
	CA          publicid.ID
	CAVersion   int64
	Serial      []byte
	Certificate []byte
	PublicKey   []byte
	NotBefore   time.Time
	NotAfter    time.Time
	RenewAt     time.Time
	Token       *TokenUse
	// TrustVersion is the signing trust the token was checked against; the
	// database refuses the token once the trust moved on.
	TrustVersion int64
}

// Outcome is what became of a held request.
type Outcome string

// Outcomes of settling a held request.
const (
	OutcomeIssued    Outcome = "issued"
	OutcomeRefused   Outcome = "refused"
	OutcomeRequeued  Outcome = "requeued"
	OutcomeReleased  Outcome = "released"
	OutcomeSuspected Outcome = "suspected"
	OutcomeLost      Outcome = "lost"
	// OutcomeRecorded: a token's claims replaced it.
	OutcomeRecorded Outcome = "recorded"
)

// FleetRow is one active gateway Device of an active cluster (a4d): its
// place in the scan, when its latest certificate expires (zero: none),
// whether it asked within the last 10 minutes, and whether that latest
// request went unserved (refused, given up, or waiting over a minute).
type FleetRow struct {
	Cluster  int64
	Ordinal  int
	NotAfter time.Time
	Asking   bool
	Unserved bool
}

// Store is the worker's view of the queue and ledger (the postgres
// adapter).
type Store interface {
	// Fleet reads up to limit gateway Devices after (cluster, ordinal).
	Fleet(ctx context.Context, installation deployment.ID, afterCluster int64, afterOrdinal, limit int) ([]FleetRow,
		error)
	Claim(ctx context.Context, installation deployment.ID, limit int, lease time.Duration) (Batch, error)
	Issue(ctx context.Context, installation deployment.ID, issue Issue) (Outcome, Reason, error)
	Refuse(ctx context.Context, installation deployment.ID, request publicid.ID, claimToken ClaimToken,
		reason Reason) (Outcome, error)
	Release(ctx context.Context, installation deployment.ID, request publicid.ID, claimToken ClaimToken) (Outcome,
		error)
	// RecordToken replaces a held request's token with the claims checked
	// in it.
	RecordToken(ctx context.Context, installation deployment.ID, request publicid.ID, claimToken ClaimToken,
		verified VerifiedToken) (Outcome, error)
	Prune(ctx context.Context, installation deployment.ID, limit int) (int, int, error)
	Beat(ctx context.Context, installation deployment.ID, instance publicid.ID, ready bool, version, custody string,
		capabilities []string) (time.Time, error)
}

// TokenVerifier checks a pod token against a trust at now and returns its
// evidence; any error refuses the request.
type TokenVerifier func(raw string, trust Trust, now time.Time) (TokenUse, error)
