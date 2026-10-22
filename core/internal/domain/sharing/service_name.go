package sharing

import (
	"errors"
	"slices"
)

// MaximumServiceNames bounds the service names a provider suggests on one
// offer (DNS design D3 §3.1).
const MaximumServiceNames = 8

// ErrInvalidServiceName reports a service name that is not a canonical,
// multi-label DNS name.
var ErrInvalidServiceName = errors.New("sharing: invalid service name")

// ServiceName is one name a provider suggests a consumer may give the
// shared Resource, such as app.corp.com: the real name its web app serves.
// It is a suggestion only: it resolves nowhere until the consumer approves
// it, which makes it a DNS name of the consumer Network that answers the
// share's alias. Here it is only syntax; the DNS rules (mesh suffix,
// special-use names, public suffixes, names MeshTransit must reach) are
// checked where DNS names are.
type ServiceName struct {
	value string
}

// ParseServiceName validates a canonical lowercase fully qualified name of
// at least two labels, without a trailing dot, that is not an address.
func ParseServiceName(value string) (ServiceName, error) {
	name, err := ParseAccessName(value)
	if err != nil || name.String() != value {
		return ServiceName{}, ErrInvalidServiceName
	}
	return ServiceName{value: value}, nil
}

// String returns the canonical name.
func (name ServiceName) String() string { return name.value }

// IsValid reports whether the value satisfies the service-name contract.
func (name ServiceName) IsValid() bool {
	parsed, err := ParseServiceName(name.value)
	return err == nil && parsed == name
}

// validServiceNames reports at most MaximumServiceNames valid names, none
// twice.
func validServiceNames(names []ServiceName) bool {
	if len(names) > MaximumServiceNames {
		return false
	}
	for index, name := range names {
		if !name.IsValid() || slices.Contains(names[:index], name) {
			return false
		}
	}
	return true
}

// ServiceNameDecision is the consumer's answer to one suggested service
// name when it accepts an offer: approve makes it a DNS name of the consumer
// Network that answers the share's alias; decline leaves it out.
type ServiceNameDecision struct {
	Name    ServiceName
	Approve bool
}

// validServiceNameDecisions reports decisions on valid names, none twice.
func validServiceNameDecisions(decisions []ServiceNameDecision) bool {
	if len(decisions) > MaximumServiceNames {
		return false
	}
	for index, decision := range decisions {
		if !decision.Name.IsValid() || slices.ContainsFunc(decisions[:index], func(other ServiceNameDecision) bool {
			return other.Name == decision.Name
		}) {
			return false
		}
	}
	return true
}

// ErrServiceNameDecisions reports an accept that does not answer each
// service name the offer suggests exactly once, or answers a name it does
// not suggest.
var ErrServiceNameDecisions = errors.New("sharing: service names answered wrong")

// ServiceNameError reports an approved service name that could not become a
// DNS name of the consumer Network: Index is its place in the decisions,
// Err the DNS reason (the name is taken, the share cannot be a target, the
// session may not manage DNS...). The whole accept rolls back.
type ServiceNameError struct {
	Index int
	Err   error
}

func (failure *ServiceNameError) Error() string {
	return "sharing: service name cannot be approved: " + failure.Err.Error()
}

// Unwrap returns the DNS reason.
func (failure *ServiceNameError) Unwrap() error { return failure.Err }
