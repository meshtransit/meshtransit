package control

import (
	"errors"
	"log/slog"

	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment/registration/intake"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/node/keyrotation"
)

// ErrInvalidRegistrationRequest reports malformed, incomplete, or unbound
// registration input without disclosing which authentication field failed.
var ErrInvalidRegistrationRequest = errors.New("control: invalid registration request")

// RegistrationRequestParams is the allowlisted protocol-neutral registration
// payload. Scope authority is deliberately impossible to represent here.
type RegistrationRequestParams struct {
	RegistrationID enrollment.RegistrationID
	Credential     enrollment.CredentialPresentation
	NodeKey        node.Key
	OldNodeKey     node.Key
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
	credential     enrollment.CredentialPresentation
	nodeKey        node.Key
	oldNodeKey     node.Key
	hostname       node.Hostname
}

// NewRegistrationRequest validates the protocol-neutral request payload.
func NewRegistrationRequest(params RegistrationRequestParams) (RegistrationRequest, error) {
	request := RegistrationRequest{
		registrationID: params.RegistrationID,
		credential:     params.Credential,
		nodeKey:        params.NodeKey,
		oldNodeKey:     params.OldNodeKey,
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
	if !machine.IsValid() || !request.IsCredentialRegistration() {
		return intake.Request{}, ErrInvalidRegistrationRequest
	}
	identity, err := node.NewRegistrationIdentity(machine.key, request.nodeKey)
	if err != nil {
		return intake.Request{}, ErrInvalidRegistrationRequest
	}
	bound := intake.Request{
		RegistrationID: request.registrationID,
		CredentialID:   request.credential.CredentialID(),
		Token:          request.credential.Token(),
		Identity:       identity,
		Hostname:       request.hostname,
	}
	if !bound.IsValid() {
		return intake.Request{}, ErrInvalidRegistrationRequest
	}
	return bound, nil
}

// BindNodeKeyRotation binds the exact old/new key transition to the machine
// identity proven by the enclosing Noise session.
func (machine AuthenticatedMachine) BindNodeKeyRotation(
	request RegistrationRequest,
) (keyrotation.Command, error) {
	if !machine.IsValid() || !request.IsNodeKeyRotation() {
		return keyrotation.Command{}, ErrInvalidRegistrationRequest
	}
	command, err := keyrotation.NewCommand(keyrotation.CommandParams{
		OperationID: request.registrationID,
		MachineKey:  machine.key,
		OldNodeKey:  request.oldNodeKey,
		NewNodeKey:  request.nodeKey,
	})
	if err != nil {
		return keyrotation.Command{}, ErrInvalidRegistrationRequest
	}
	return command, nil
}

// IsCredentialRegistration reports whether the request carries exactly one
// enrollment credential and no old Node-key authority.
func (request RegistrationRequest) IsCredentialRegistration() bool {
	return request.registrationID.IsValid() && request.credential.IsValid() &&
		request.nodeKey.IsValid() && !request.oldNodeKey.IsValid() && request.hostname.IsValid()
}

// IsNodeKeyRotation reports whether the request carries an exact old/new key
// transition and no enrollment credential.
func (request RegistrationRequest) IsNodeKeyRotation() bool {
	return request.registrationID.IsValid() && !request.credential.IsValid() &&
		request.nodeKey.IsValid() && request.oldNodeKey.IsValid() &&
		request.nodeKey != request.oldNodeKey && request.hostname.IsValid()
}

// IsValid reports whether every allowlisted untrusted field is structurally valid.
func (request RegistrationRequest) IsValid() bool {
	return request.IsCredentialRegistration() || request.IsNodeKeyRotation()
}

// String prevents registration identity and bearer proof from entering ordinary logs.
func (RegistrationRequest) String() string { return "[REDACTED]" }

// GoString prevents registration identity and bearer proof from entering diagnostic formatting.
func (RegistrationRequest) GoString() string { return "control.RegistrationRequest([REDACTED])" }

// LogValue prevents registration identity and bearer proof from entering structured logs.
func (RegistrationRequest) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
