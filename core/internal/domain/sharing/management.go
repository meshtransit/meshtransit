package sharing

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/resource"
	"github.com/meshtransit/meshtransit/core/internal/platform/idempotency"
)

const (
	// MaximumManagementPageSize bounds one sharing catalog page.
	MaximumManagementPageSize = 100
	maximumAuditReasonBytes   = 512
	// NoExpiryTimestamp is the canonical representable ceiling for a share that
	// remains valid until revoked. It stays within time.UnixNano's range.
	NoExpiryTimestamp = "2200-01-01T00:00:00Z"
)

// NoExpiryTime returns the canonical ceiling for a share without a scheduled expiry.
func NoExpiryTime() time.Time {
	return time.Date(2200, time.January, 1, 0, 0, 0, 0, time.UTC)
}

// HasNoExpiry reports whether a share uses the canonical no-expiry ceiling.
func HasNoExpiry(value time.Time) bool { return value.Equal(NoExpiryTime()) }

var (
	// ErrInvalidManagementRequest reports malformed management intent.
	ErrInvalidManagementRequest = errors.New("sharing: invalid management request")
	// ErrForbidden conceals a missing sharing authorization prerequisite.
	ErrForbidden = errors.New("sharing: forbidden")
	// ErrNotFound conceals absent and out-of-scope sharing authority.
	ErrNotFound = errors.New("sharing: not found")
	// ErrConflict reports stale version, revision, lifecycle, or authority input.
	ErrConflict = errors.New("sharing: conflict")
	// ErrUnavailable reports an unavailable authoritative dependency.
	ErrUnavailable = errors.New("sharing: unavailable")
)

// Direction selects sharing authority relative to the request Network.
type Direction uint8

const (
	// DirectionUnknown is the unusable zero value.
	DirectionUnknown Direction = iota
	// DirectionOutgoing selects provider-side offers.
	DirectionOutgoing
	// DirectionIncoming selects consumer-side offers.
	DirectionIncoming
)

// IsValid reports whether the direction has exact management semantics.
func (direction Direction) IsValid() bool {
	return direction == DirectionOutgoing || direction == DirectionIncoming
}

// AuditReason is a bounded human explanation retained with a privileged change.
type AuditReason string

// NewAuditReason validates one non-empty, whitespace-canonical explanation.
func NewAuditReason(value string) (AuditReason, error) {
	reason := AuditReason(value)
	if !reason.IsValid() {
		return "", ErrInvalidManagementRequest
	}
	return reason, nil
}

// String returns the validated explanation.
func (reason AuditReason) String() string { return string(reason) }

// IsValid reports whether the explanation is safe to retain in evidence.
func (reason AuditReason) IsValid() bool {
	value := string(reason)
	return value != "" && len(value) <= maximumAuditReasonBytes && strings.TrimSpace(value) == value
}

// OfferToken is the one-time bearer capability delivered outside durable state.
type OfferToken [32]byte

// NewOfferToken validates fixed-size non-zero token material.
func NewOfferToken(value [32]byte) (OfferToken, error) {
	token := OfferToken(value)
	if !token.IsValid() {
		return OfferToken{}, ErrInvalidManagementRequest
	}
	return token, nil
}

// Bytes returns a copy of the secret token material.
func (token OfferToken) Bytes() [32]byte { return [32]byte(token) }

// IsValid reports whether token material is non-zero.
func (token OfferToken) IsValid() bool { return token != OfferToken{} }

// CreateOfferParams contains one provider-side Resource export request.
type CreateOfferParams struct {
	ProviderScope  network.Scope
	ConsumerScope  network.Scope
	ResourceID     resource.ID
	MaximumTraffic TrafficSet
	ExpiresAt      time.Time
	// AccessLabel is the frozen first label of the consumer DNS name. The
	// zero value derives it from the shared Resource name at creation.
	AccessLabel    AccessLabel
	AccountSession accountsession.Session
	Reason         AuditReason
	Idempotency    idempotency.Proof
}

// CreateOffer is immutable provider intent for one exact consumer Network.
type CreateOffer struct{ params CreateOfferParams }

// NewCreateOffer validates one bounded, exact-scope offer request.
func NewCreateOffer(params CreateOfferParams) (CreateOffer, error) {
	// PostgreSQL timestamps retain microseconds. Canonicalize before hashing,
	// persistence and result matching, rounding down so expiry never extends.
	params.ExpiresAt = params.ExpiresAt.UTC().Truncate(time.Microsecond)
	command := CreateOffer{params: params}
	if !command.IsValid() {
		return CreateOffer{}, ErrInvalidManagementRequest
	}
	return command, nil
}

// ProviderScope returns the Resource authority scope.
func (command CreateOffer) ProviderScope() network.Scope { return command.params.ProviderScope }

// ConsumerScope returns the only Network allowed to decide the offer.
func (command CreateOffer) ConsumerScope() network.Scope { return command.params.ConsumerScope }

// ResourceID returns the provider Resource identity.
func (command CreateOffer) ResourceID() resource.ID { return command.params.ResourceID }

// MaximumTraffic returns a caller-owned provider maximum.
func (command CreateOffer) MaximumTraffic() TrafficSet {
	set, _ := NewTrafficSet(command.params.MaximumTraffic.Constraints())
	return set
}

// ExpiresAt returns the exclusive offer deadline.
func (command CreateOffer) ExpiresAt() time.Time { return command.params.ExpiresAt }

// AccessLabel returns the requested label; the zero value requests a default.
func (command CreateOffer) AccessLabel() AccessLabel { return command.params.AccessLabel }

// AccountSession returns the authenticated provider session.
func (command CreateOffer) AccountSession() accountsession.Session {
	return command.params.AccountSession
}

// Reason returns the retained privileged-operation explanation.
func (command CreateOffer) Reason() AuditReason { return command.params.Reason }

// IdempotencyEvidence returns the raw-key-free replay proof.
func (command CreateOffer) IdempotencyEvidence() idempotency.Proof {
	return command.params.Idempotency
}

// IsValid reports whether the provider intent is complete and exact-scoped.
func (command CreateOffer) IsValid() bool {
	params := command.params
	return params.ProviderScope.IsValid() && params.ConsumerScope.IsValid() &&
		params.ProviderScope != params.ConsumerScope && params.ResourceID.IsValid() &&
		params.MaximumTraffic.IsValid() && !params.ExpiresAt.IsZero() &&
		(params.AccessLabel == AccessLabel{} || params.AccessLabel.IsValid()) &&
		params.AccountSession.IsValid() && params.Reason.IsValid() && params.Idempotency.IsValid()
}

// DecisionAction is one terminal Share Offer decision.
type DecisionAction uint8

const (
	// DecisionActionUnknown is the unusable zero value.
	DecisionActionUnknown DecisionAction = iota
	// DecisionActionAccept creates an activating Trust Contract and Imported Resource.
	DecisionActionAccept
	// DecisionActionReject records a terminal consumer rejection.
	DecisionActionReject
	// DecisionActionRevoke withdraws an undecided provider offer.
	DecisionActionRevoke
)

// IsValid reports whether the action has explicit lifecycle semantics.
func (action DecisionAction) IsValid() bool {
	return action == DecisionActionAccept || action == DecisionActionReject ||
		action == DecisionActionRevoke
}

// DecideOfferParams contains one version-bound terminal offer action.
type DecideOfferParams struct {
	ProviderScope        network.Scope
	ConsumerScope        network.Scope
	OfferID              OfferID
	ExpectedOfferVersion int64
	Token                OfferToken
	Action               DecisionAction
	ImportedDisplayName  resource.DisplayName
	AccessName           AccessName
	AccountSession       accountsession.Session
	Reason               AuditReason
	Idempotency          idempotency.Proof
}

// DecideOffer is immutable bilateral offer decision intent.
type DecideOffer struct{ params DecideOfferParams }

// NewDecideOffer validates one exact two-scope terminal action.
func NewDecideOffer(params DecideOfferParams) (DecideOffer, error) {
	command := DecideOffer{params: params}
	if !command.IsValid() {
		return DecideOffer{}, ErrInvalidManagementRequest
	}
	return command, nil
}

// ProviderScope returns the exact provider side.
func (command DecideOffer) ProviderScope() network.Scope { return command.params.ProviderScope }

// ConsumerScope returns the exact consumer side.
func (command DecideOffer) ConsumerScope() network.Scope { return command.params.ConsumerScope }

// OfferID returns the targeted Share Offer.
func (command DecideOffer) OfferID() OfferID { return command.params.OfferID }

// ExpectedOfferVersion returns the ETag compare-and-swap version.
func (command DecideOffer) ExpectedOfferVersion() int64 {
	return command.params.ExpectedOfferVersion
}

// Token returns a copy of the out-of-band acceptance capability.
func (command DecideOffer) Token() OfferToken { return command.params.Token }

// Action returns the requested terminal action.
func (command DecideOffer) Action() DecisionAction { return command.params.Action }

// ImportedDisplayName returns the consumer-local name for acceptance.
func (command DecideOffer) ImportedDisplayName() resource.DisplayName {
	return command.params.ImportedDisplayName
}

// AccessName returns the consumer-supplied DNS name. It is empty when the
// offer's provider label determines the name; a supplied name must match it.
func (command DecideOffer) AccessName() AccessName { return command.params.AccessName }

// AccountSession returns the authenticated decision session.
func (command DecideOffer) AccountSession() accountsession.Session {
	return command.params.AccountSession
}

// Reason returns the retained privileged-operation explanation.
func (command DecideOffer) Reason() AuditReason { return command.params.Reason }

// IdempotencyEvidence returns the raw-key-free replay proof.
func (command DecideOffer) IdempotencyEvidence() idempotency.Proof {
	return command.params.Idempotency
}

// IsValid reports whether action, scope, token, and acceptance shape agree.
func (command DecideOffer) IsValid() bool {
	params := command.params
	if !params.ProviderScope.IsValid() || !params.ConsumerScope.IsValid() ||
		params.ProviderScope == params.ConsumerScope || !params.OfferID.IsValid() ||
		params.ExpectedOfferVersion <= 0 || !params.Token.IsValid() || !params.Action.IsValid() ||
		!params.AccountSession.IsValid() || !params.Reason.IsValid() || !params.Idempotency.IsValid() {
		return false
	}
	accept := params.Action == DecisionActionAccept
	accessNameAbsent := params.AccessName == AccessName{}
	return accept == params.ImportedDisplayName.IsValid() &&
		(accessNameAbsent || accept && params.AccessName.IsValid())
}

// RevokeContractParams contains one version-bound bilateral revocation.
type RevokeContractParams struct {
	ProviderScope           network.Scope
	ConsumerScope           network.Scope
	ContractID              ContractID
	ExpectedContractVersion int64
	LocalScope              network.Scope
	AccountSession          accountsession.Session
	Reason                  AuditReason
	Idempotency             idempotency.Proof
}

// RevokeContract is immutable revocation intent from either contract side.
type RevokeContract struct{ params RevokeContractParams }

// NewRevokeContract validates an exact provider-or-consumer revocation request.
func NewRevokeContract(params RevokeContractParams) (RevokeContract, error) {
	command := RevokeContract{params: params}
	if !command.IsValid() {
		return RevokeContract{}, ErrInvalidManagementRequest
	}
	return command, nil
}

// ProviderScope returns the exact provider side.
func (command RevokeContract) ProviderScope() network.Scope { return command.params.ProviderScope }

// ConsumerScope returns the exact consumer side.
func (command RevokeContract) ConsumerScope() network.Scope { return command.params.ConsumerScope }

// LocalScope returns the side whose share.revoke permission is required.
func (command RevokeContract) LocalScope() network.Scope { return command.params.LocalScope }

// ContractID returns the targeted Trust Contract.
func (command RevokeContract) ContractID() ContractID { return command.params.ContractID }

// ExpectedContractVersion returns the ETag compare-and-swap version.
func (command RevokeContract) ExpectedContractVersion() int64 {
	return command.params.ExpectedContractVersion
}

// AccountSession returns the authenticated revocation session.
func (command RevokeContract) AccountSession() accountsession.Session {
	return command.params.AccountSession
}

// Reason returns the retained privileged-operation explanation.
func (command RevokeContract) Reason() AuditReason { return command.params.Reason }

// IdempotencyEvidence returns the raw-key-free replay proof.
func (command RevokeContract) IdempotencyEvidence() idempotency.Proof {
	return command.params.Idempotency
}

// IsValid reports whether the caller acts from exactly one contract side.
func (command RevokeContract) IsValid() bool {
	params := command.params
	return params.ProviderScope.IsValid() && params.ConsumerScope.IsValid() &&
		params.ProviderScope != params.ConsumerScope && params.ContractID.IsValid() &&
		params.ExpectedContractVersion > 0 &&
		(params.LocalScope == params.ProviderScope || params.LocalScope == params.ConsumerScope) &&
		params.AccountSession.IsValid() && params.Reason.IsValid() && params.Idempotency.IsValid()
}

// ActivateContractParams contains one consumer-authorized activation request.
type ActivateContractParams struct {
	ProviderScope           network.Scope
	ConsumerScope           network.Scope
	ContractID              ContractID
	ExpectedContractVersion int64
	AccountSession          accountsession.Session
	Reason                  AuditReason
	Idempotency             idempotency.Proof
}

// ActivateContract is immutable consumer intent to make an accepted contract
// eligible for policy compilation. Activation alone grants no packet path.
type ActivateContract struct{ params ActivateContractParams }

// NewActivateContract validates one exact, version-bound activation request.
func NewActivateContract(params ActivateContractParams) (ActivateContract, error) {
	command := ActivateContract{params: params}
	if !command.IsValid() {
		return ActivateContract{}, ErrInvalidManagementRequest
	}
	return command, nil
}

// ProviderScope returns the exact provider side.
func (command ActivateContract) ProviderScope() network.Scope { return command.params.ProviderScope }

// ConsumerScope returns the exact consumer side whose share.accept authority is required.
func (command ActivateContract) ConsumerScope() network.Scope { return command.params.ConsumerScope }

// ContractID returns the targeted Trust Contract.
func (command ActivateContract) ContractID() ContractID { return command.params.ContractID }

// ExpectedContractVersion returns the ETag compare-and-swap version.
func (command ActivateContract) ExpectedContractVersion() int64 {
	return command.params.ExpectedContractVersion
}

// AccountSession returns the authenticated consumer session.
func (command ActivateContract) AccountSession() accountsession.Session {
	return command.params.AccountSession
}

// Reason returns the retained privileged-operation explanation.
func (command ActivateContract) Reason() AuditReason { return command.params.Reason }

// IdempotencyEvidence returns the raw-key-free replay proof.
func (command ActivateContract) IdempotencyEvidence() idempotency.Proof {
	return command.params.Idempotency
}

// IsValid reports whether exact bilateral scope and authority evidence are complete.
func (command ActivateContract) IsValid() bool {
	params := command.params
	return params.ProviderScope.IsValid() && params.ConsumerScope.IsValid() &&
		params.ProviderScope != params.ConsumerScope && params.ContractID.IsValid() &&
		params.ExpectedContractVersion > 0 && params.AccountSession.IsValid() &&
		params.Reason.IsValid() && params.Idempotency.IsValid()
}

// OfferSnapshot binds management-visible offer state to exact Resource authority.
type OfferSnapshot struct {
	offer          Offer
	resource       ResourceBinding
	shareExpiresAt time.Time
	createdAt      time.Time
	accessLabel    AccessLabel
	accessName     AccessName
	contract       Contract
	hasContract    bool
	displayCodes   OfferDisplayCodes
}

// WithAccessNaming returns a copy carrying the provider label and the
// Core-derived consumer name. Unlabeled offers carry neither; a labeled
// offer's name always begins with its label.
func (snapshot OfferSnapshot) WithAccessNaming(label AccessLabel, name AccessName) (OfferSnapshot, error) {
	unlabeled := label == AccessLabel{} && name == AccessName{}
	labeled := label.IsValid() && name.IsValid() && strings.HasPrefix(name.String(), label.String()+".")
	if !unlabeled && !labeled {
		return OfferSnapshot{}, ErrInvalidManagementRequest
	}
	snapshot.accessLabel = label
	snapshot.accessName = name
	return snapshot, nil
}

// AccessLabel returns the frozen provider label, or zero for an unlabeled offer.
func (snapshot OfferSnapshot) AccessLabel() AccessLabel { return snapshot.accessLabel }

// AccessName returns the name acceptance will reserve, or zero when the
// consumer must supply one.
func (snapshot OfferSnapshot) AccessName() AccessName { return snapshot.accessName }

// NewOfferSnapshot validates one management-safe offer projection.
func NewOfferSnapshot(offer Offer, binding ResourceBinding, shareExpiresAt, createdAt time.Time) (OfferSnapshot, error) {
	snapshot := OfferSnapshot{offer: offer, resource: binding, shareExpiresAt: shareExpiresAt.UTC(), createdAt: createdAt.UTC()}
	if !snapshot.IsValid() {
		return OfferSnapshot{}, ErrInvalidManagementRequest
	}
	return snapshot, nil
}

// Offer returns immutable lifecycle and traffic authority.
func (snapshot OfferSnapshot) Offer() Offer { return snapshot.offer }

// Resource returns exact provider Resource provenance.
func (snapshot OfferSnapshot) Resource() ResourceBinding { return snapshot.resource }

// ShareExpiresAt is the exclusive grant ceiling after the offer is accepted.
func (snapshot OfferSnapshot) ShareExpiresAt() time.Time { return snapshot.shareExpiresAt }

// CreatedAt returns the offer creation time.
func (snapshot OfferSnapshot) CreatedAt() time.Time { return snapshot.createdAt }

// IsValid reports whether offer and Resource scopes agree.
func (snapshot OfferSnapshot) IsValid() bool {
	return snapshot.offer.IsValid() && snapshot.resource.IsValid() &&
		snapshot.resource.Scope() == snapshot.offer.ProviderScope() &&
		!snapshot.shareExpiresAt.IsZero() && !snapshot.shareExpiresAt.Before(snapshot.offer.ExpiresAt()) &&
		!snapshot.createdAt.IsZero()
}

// MutationResult reports the exact post-commit revisions and optional authority.
type MutationResult struct {
	offer                   OfferSnapshot
	contract                Contract
	token                   OfferToken
	providerNetworkRevision int64
	providerSharingRevision int64
	consumerNetworkRevision int64
	consumerSharingRevision int64
	importedResourceVersion int64
	hasOffer                bool
	hasContract             bool
	hasToken                bool
}

// MutationResultParams contains one validated post-commit sharing result.
type MutationResultParams struct {
	Offer                   OfferSnapshot
	Contract                Contract
	Token                   OfferToken
	ProviderNetworkRevision int64
	ProviderSharingRevision int64
	ConsumerNetworkRevision int64
	ConsumerSharingRevision int64
	ImportedResourceVersion int64
	HasOffer                bool
	HasContract             bool
	HasToken                bool
}

// NewMutationResult validates one cross-Network mutation receipt.
func NewMutationResult(params MutationResultParams) (MutationResult, error) {
	result := MutationResult{
		offer: params.Offer, contract: params.Contract, token: params.Token,
		providerNetworkRevision: params.ProviderNetworkRevision,
		providerSharingRevision: params.ProviderSharingRevision,
		consumerNetworkRevision: params.ConsumerNetworkRevision,
		consumerSharingRevision: params.ConsumerSharingRevision,
		importedResourceVersion: params.ImportedResourceVersion,
		hasOffer:                params.HasOffer, hasContract: params.HasContract, hasToken: params.HasToken,
	}
	if !result.IsValid() {
		return MutationResult{}, ErrInvalidManagementRequest
	}
	return result, nil
}

// Offer returns the post-commit offer when present.
func (result MutationResult) Offer() (OfferSnapshot, bool) { return result.offer, result.hasOffer }

// Contract returns the accepted or revoked contract when present.
func (result MutationResult) Contract() (Contract, bool) { return result.contract, result.hasContract }

// Token returns the one-time offer capability only on initial creation.
func (result MutationResult) Token() (OfferToken, bool) { return result.token, result.hasToken }

// ProviderNetworkRevision returns the provider aggregate revision.
func (result MutationResult) ProviderNetworkRevision() int64 {
	return result.providerNetworkRevision
}

// ProviderSharingRevision returns the provider sharing revision.
func (result MutationResult) ProviderSharingRevision() int64 {
	return result.providerSharingRevision
}

// ConsumerNetworkRevision returns the consumer aggregate revision.
func (result MutationResult) ConsumerNetworkRevision() int64 {
	return result.consumerNetworkRevision
}

// ConsumerSharingRevision returns the consumer sharing revision.
func (result MutationResult) ConsumerSharingRevision() int64 {
	return result.consumerSharingRevision
}

// ImportedResourceVersion returns the accepted or revoked local projection version.
func (result MutationResult) ImportedResourceVersion() int64 {
	return result.importedResourceVersion
}

// IsValid reports whether receipt shape and revision evidence agree.
func (result MutationResult) IsValid() bool {
	if result.providerNetworkRevision <= 0 || result.providerSharingRevision <= 0 ||
		result.consumerNetworkRevision <= 0 || result.consumerSharingRevision <= 0 ||
		result.providerNetworkRevision < result.providerSharingRevision ||
		result.consumerNetworkRevision < result.consumerSharingRevision ||
		!result.hasOffer || !result.offer.IsValid() || result.hasToken != result.token.IsValid() {
		return false
	}
	if result.hasContract != result.contract.IsValid() {
		return false
	}
	if result.hasContract {
		return result.importedResourceVersion > 0 &&
			result.contract.OfferID() == result.offer.Offer().ID()
	}
	return result.importedResourceVersion == 0
}

// PageCursor binds keyset position to one exact sharing revision.
type PageCursor struct {
	revision int64
	after    OfferID
}

// NewPageCursor validates a revision-pinned Share Offer keyset position.
func NewPageCursor(revision int64, after OfferID) (PageCursor, error) {
	cursor := PageCursor{revision: revision, after: after}
	if !cursor.IsValid() {
		return PageCursor{}, ErrInvalidManagementRequest
	}
	return cursor, nil
}

// Revision returns the sharing revision observed by the first page.
func (cursor PageCursor) Revision() int64 { return cursor.revision }

// After returns the last public identity from the previous page.
func (cursor PageCursor) After() OfferID { return cursor.after }

// IsValid reports whether cursor fields are complete.
func (cursor PageCursor) IsValid() bool { return cursor.revision > 0 && cursor.after.IsValid() }

// OfferPage is a deterministic, revision-pinned management page.
type OfferPage struct {
	items    []OfferSnapshot
	revision int64
	next     PageCursor
}

// NewOfferPage validates ordered, unique, scope-relative offer projections.
func NewOfferPage(items []OfferSnapshot, revision int64, next PageCursor) (OfferPage, error) {
	page := OfferPage{items: slices.Clone(items), revision: revision, next: next}
	if !page.IsValid() {
		return OfferPage{}, ErrInvalidManagementRequest
	}
	return page, nil
}

// Items returns caller-owned offer projections.
func (page OfferPage) Items() []OfferSnapshot { return slices.Clone(page.items) }

// Revision returns the exact sharing revision backing the page.
func (page OfferPage) Revision() int64 { return page.revision }

// Next returns the next-page cursor when more items exist.
func (page OfferPage) Next() (PageCursor, bool) { return page.next, page.next.IsValid() }

// IsValid reports whether items are unique and cursor revision agrees.
func (page OfferPage) IsValid() bool {
	if page.items == nil || page.revision <= 0 || page.next.IsValid() && page.next.Revision() != page.revision {
		return false
	}
	seen := make(map[OfferID]struct{}, len(page.items))
	for _, item := range page.items {
		if !item.IsValid() {
			return false
		}
		id := item.Offer().ID()
		if _, duplicate := seen[id]; duplicate {
			return false
		}
		seen[id] = struct{}{}
	}
	return true
}

// EmptyPageCursor returns an explicit invalid cursor for first-page requests.
func EmptyPageCursor() PageCursor { return PageCursor{} }

// PublicOfferID converts an offer identity for generic cursor encoding.
func PublicOfferID(id OfferID) publicid.ID { return publicid.ID(id) }
