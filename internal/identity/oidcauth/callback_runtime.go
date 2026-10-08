package oidcauth

import (
	"reflect"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
)

// CallbackOptions bounds complete application work, fail-fast capacity and
// separate joined cleanup. Cleanup does not extend work or release deadlines.
type CallbackOptions struct {
	RequestTimeout, FailureTimeout, RollbackTimeout time.Duration
	IdleLifetime, AbsoluteLifetime                  time.Duration
	MaxConcurrent                                   int
}

// CallbackDependencies names effect ports and resident keys, not preconstructed
// services or HTTP admission. Each internal service is constructed exactly once
// with the same clock/crypto. IDs must create fresh mutation IDs on every call.
type CallbackDependencies struct {
	Pending          PendingLoader
	Claims           ClaimTransactions
	Failures         FailureTransactions
	Issues           IssueTransactions
	IDs              ClaimIDGenerator
	Material         IssueMaterialGenerator
	Provider         TokenAuthenticator
	Subjects         LoginSubjectResolver
	DigestKey        DigestKey
	VerifierCipher   *VerifierCipher
	SubjectKeys      *SubjectKeyring
	SessionKeys      *accountsession.Keyring
	ProviderSessions ProviderSessionKey
	Clock            StartClock
	Observer         CallbackObserver
	SubjectObserver  SubjectResolutionObserver
	IssueObserver    IssueObserver
	// Invitations accepts Workspace invitations at sign-in; nil refuses any
	// sign-in that presents one.
	Invitations InvitationAcceptor
}

// CallbackService owns bounded synchronous composition, not public admission.
// Its capacity channel is never closed; each admitted caller owns one slot until
// all work/cleanup joins. No goroutines, retries or database units span provider I/O.
type CallbackService struct {
	options      CallbackOptions
	clock        StartClock
	observer     CallbackObserver
	active       chan struct{}
	verification *BrowserVerificationService
	claim        *ClaimService
	exchange     *ExchangeService
	subject      *SubjectResolutionService
	issue        *IssueService
	failure      *FailureService
	invitations  InvitationAcceptor
	subjectKeys  *SubjectKeyring
}

// NewCallbackService validates all dependencies before effects. No service
// starts work during construction; no shared receipt gate or capacity is cloned.
func NewCallbackService(options CallbackOptions, deps CallbackDependencies) (*CallbackService, error) {
	issueOptions := IssueOptions{
		RequestTimeout: options.RequestTimeout, RollbackTimeout: options.RollbackTimeout,
		IdleLifetime: options.IdleLifetime, AbsoluteLifetime: options.AbsoluteLifetime,
		MaxConcurrent: options.MaxConcurrent,
	}
	validCapacity := options.MaxConcurrent >= 1 && options.MaxConcurrent <= 128
	validFailureWindow := options.FailureTimeout > 0 && options.FailureTimeout <= 5*time.Second
	if !validCapacity || !validFailureWindow || !validIssueOptions(issueOptions) {
		return nil, ErrInvalidCallback
	}
	for _, dependency := range []any{
		deps.Pending, deps.Claims, deps.Failures, deps.Issues, deps.IDs, deps.Material,
		deps.Provider, deps.Subjects, deps.Clock, deps.Observer, deps.SubjectObserver, deps.IssueObserver,
	} {
		if nilCallbackDependency(dependency) {
			return nil, ErrInvalidCallback
		}
	}
	verification, err := NewBrowserVerificationService(
		BrowserVerificationOptions{RequestTimeout: options.RequestTimeout},
		BrowserVerificationDependencies{
			Pending: deps.Pending, DigestKey: deps.DigestKey, VerifierCipher: deps.VerifierCipher, Clock: deps.Clock,
		},
	)
	if err != nil {
		return nil, ErrInvalidCallback
	}
	claim, err := NewClaimService(
		ClaimOptions{RequestTimeout: options.RequestTimeout, RollbackTimeout: options.RollbackTimeout},
		ClaimDependencies{Transactions: deps.Claims, IDs: deps.IDs, Clock: deps.Clock},
	)
	if err != nil {
		return nil, ErrInvalidCallback
	}
	exchange, err := NewExchangeService(
		ExchangeOptions{RequestTimeout: options.RequestTimeout, MaxConcurrent: options.MaxConcurrent},
		ExchangeDependencies{
			Provider: deps.Provider, Cipher: deps.VerifierCipher, DigestKey: deps.DigestKey, Clock: deps.Clock,
		},
	)
	if err != nil {
		return nil, ErrInvalidCallback
	}
	subject, err := NewSubjectResolutionService(
		SubjectResolutionOptions{RequestTimeout: options.RequestTimeout, MaxConcurrent: options.MaxConcurrent},
		SubjectResolutionDependencies{
			Subjects: deps.Subjects, Keys: deps.SubjectKeys, Clock: deps.Clock, Observer: deps.SubjectObserver,
		},
	)
	if err != nil {
		return nil, ErrInvalidCallback
	}
	issue, err := NewIssueService(issueOptions, IssueDependencies{
		Transactions: deps.Issues, Material: deps.Material, Subjects: deps.SubjectKeys, Sessions: deps.SessionKeys,
		ProviderSessions: deps.ProviderSessions, Clock: deps.Clock, Observer: deps.IssueObserver,
	})
	if err != nil {
		return nil, ErrInvalidCallback
	}
	failure, err := NewFailureService(
		FailureOptions{RequestTimeout: options.FailureTimeout, RollbackTimeout: options.RollbackTimeout},
		FailureDependencies{Transactions: deps.Failures, IDs: deps.IDs, Clock: deps.Clock},
	)
	if err != nil {
		return nil, ErrInvalidCallback
	}
	return &CallbackService{
		options: options, clock: deps.Clock, observer: deps.Observer, active: make(chan struct{}, options.MaxConcurrent),
		verification: verification, claim: claim, exchange: exchange, subject: subject, issue: issue, failure: failure,
		invitations: deps.Invitations, subjectKeys: deps.SubjectKeys,
	}, nil
}

// This is a nil guard only, not reflection-based dependency discovery/injection.
func nilCallbackDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
