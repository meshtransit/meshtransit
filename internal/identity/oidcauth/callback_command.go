package oidcauth

import (
	"errors"
	"log/slog"
)

var (
	// ErrInvalidCallback rejects incomplete construction or ambiguous callback syntax.
	ErrInvalidCallback = errors.New("oidc auth: invalid callback")
	// ErrCallbackRejected conceals missing proof, identity and Workspace admission.
	ErrCallbackRejected = errors.New("oidc auth: callback rejected")
	// ErrCallbackLimited reports non-queuing application capacity exhaustion.
	ErrCallbackLimited = errors.New("oidc auth: callback limited")
	// ErrCallbackUnavailable conceals dependency details; it never authorizes retry.
	ErrCallbackUnavailable = errors.New("oidc auth: callback unavailable")
	// ErrCallbackCleanupFailed reports incomplete no-grant terminal/resource cleanup.
	ErrCallbackCleanupFailed = errors.New("oidc auth: callback cleanup failed")
)

// CallbackKind describes untrusted syntax, not authentication or a Session grant.
type CallbackKind uint8

const maxCallbackCodeBytes = 2048

const (
	// CallbackKindUnknown rejects an absent or unsupported callback variant.
	CallbackKindUnknown CallbackKind = iota
	// CallbackCodeReceived supplies one bounded code for a future confirmed claim.
	CallbackCodeReceived
	// CallbackProviderErrorReceived discards diagnostics and must never exchange.
	CallbackProviderErrorReceived
)

// CallbackCommandParams carries syntax only. Route must be Core-configured and
// protected POST/CSRF continuation admission must precede application execution.
type CallbackCommandParams struct {
	Route         Route
	State         State
	PreAuthCookie PreAuthCookie
	Code          Code
	Kind          CallbackKind
}

// String redacts even invalid callback construction input.
func (CallbackCommandParams) String() string { return "[REDACTED]" }

// GoString redacts detailed callback construction input.
func (CallbackCommandParams) GoString() string { return "oidcauth.CallbackCommandParams([REDACTED])" }

// LogValue redacts structured-log callback construction input.
func (CallbackCommandParams) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses construction-input credential serialization.
func (CallbackCommandParams) MarshalJSON() ([]byte, error) { return nil, ErrInvalidCallback }

// CallbackCommand is immutable, redacted syntax. Only fresh durable verification
// followed by confirmed consumption can authorize a back-channel exchange.
type CallbackCommand struct{ params CallbackCommandParams }

// NewCallbackCommand refuses ambiguous success/error variants without effects.
func NewCallbackCommand(params CallbackCommandParams) (CallbackCommand, error) {
	command := CallbackCommand{params: params}
	if !command.IsValid() {
		return CallbackCommand{}, ErrInvalidCallback
	}
	return command, nil
}

// IsValid checks syntax only, never browser intent, possession or current authority.
func (command CallbackCommand) IsValid() bool {
	params := command.params
	hasBinding := params.Route.IsValid() && params.State.IsValid() && params.PreAuthCookie.IsValid()
	if !hasBinding {
		return false
	}
	switch params.Kind {
	case CallbackCodeReceived:
		return params.Code.IsValid() && len(params.Code.value) <= maxCallbackCodeBytes
	case CallbackProviderErrorReceived:
		return params.Code == (Code{})
	default:
		return false
	}
}

// String prevents accidental callback credential disclosure.
func (CallbackCommand) String() string { return "[REDACTED]" }

// GoString prevents detailed callback credential disclosure.
func (CallbackCommand) GoString() string { return "oidcauth.CallbackCommand([REDACTED])" }

// LogValue prevents structured-log callback credential disclosure.
func (CallbackCommand) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses credential-bearing command serialization.
func (CallbackCommand) MarshalJSON() ([]byte, error) { return nil, ErrInvalidCallback }
