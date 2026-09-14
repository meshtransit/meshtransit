package control

import (
	"errors"
	"log/slog"

	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration/intake"
	"github.com/meshtransit/meshtransit/internal/node"
)

// ErrInvalidRegistrationRequest reports malformed, incomplete, or unbound
// registration input without disclosing which authentication field failed.
var ErrInvalidRegistrationRequest = errors.New("control: invalid registration request")

// RegistrationRequestParams is the allowlisted protocol-neutral registration
// payload. Scope authority is deliberately impossible to represent here.
type RegistrationRequestParams struct {
	RegistrationID enrollment.RegistrationID
	CredentialID   enrollment.CredentialID
	Token          enrollment.CredentialToken
	NodeKey        node.Key
	Hostname       node.Hostname
}

// String prevents unbound identity and bearer proof from entering ordinary logs.
func (RegistrationRequestParams) String() string { return "[REDACTED]" }

// GoString prevents unbound identity and bearer proof from entering diagnostic formatting.
func (RegistrationRequestParams) GoString() string {
	return "control.RegistrationRequestParams([REDACTED])"
}

// LogValue prevents unbound identity and bearer proof from entering structured logs.
func (RegistrationRequestParams) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// RegistrationRequest is validated untrusted payload awaiting binding to an
// authenticated transport machine.
type RegistrationRequest struct {
	registrationID enrollment.RegistrationID
	credentialID   enrollment.CredentialID
	token          enrollment.CredentialToken
	nodeKey        node.Key
	hostname       node.Hostname
}

// NewRegistrationRequest validates the protocol-neutral request payload.
func NewRegistrationRequest(params RegistrationRequestParams) (RegistrationRequest, error) {
	request := RegistrationRequest{
		registrationID: params.RegistrationID,
		credentialID:   params.CredentialID,
		token:          params.Token,
		nodeKey:        params.NodeKey,
		hostname:       params.Hostname,
	}
	if !request.IsValid() {
		return RegistrationRequest{}, ErrInvalidRegistrationRequest
	}
	return request, nil
}

// BindRegistration binds untrusted payload to the machine identity proven by
// the transport, without accepting Workspace, Network, profile, or recovery authority.
func (machine AuthenticatedMachine) BindRegistration(
	request RegistrationRequest,
) (intake.Request, error) {
	if !machine.IsValid() || !request.IsValid() {
		return intake.Request{}, ErrInvalidRegistrationRequest
	}
	identity, err := node.NewRegistrationIdentity(machine.key, request.nodeKey)
	if err != nil {
		return intake.Request{}, ErrInvalidRegistrationRequest
	}
	bound := intake.Request{
		RegistrationID: request.registrationID,
		CredentialID:   request.credentialID,
		Token:          request.token,
		Identity:       identity,
		Hostname:       request.hostname,
	}
	if !bound.IsValid() {
		return intake.Request{}, ErrInvalidRegistrationRequest
	}
	return bound, nil
}

// IsValid reports whether every allowlisted untrusted field is structurally valid.
func (request RegistrationRequest) IsValid() bool {
	return request.registrationID.IsValid() && request.credentialID.IsValid() &&
		request.token.IsValid() && request.nodeKey.IsValid() && request.hostname.IsValid()
}

// String prevents registration identity and bearer proof from entering ordinary logs.
func (RegistrationRequest) String() string { return "[REDACTED]" }

// GoString prevents registration identity and bearer proof from entering diagnostic formatting.
func (RegistrationRequest) GoString() string { return "control.RegistrationRequest([REDACTED])" }

// LogValue prevents registration identity and bearer proof from entering structured logs.
func (RegistrationRequest) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
