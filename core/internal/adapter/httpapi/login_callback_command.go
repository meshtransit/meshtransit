package httpapi

import "meshtransit.net/core/internal/domain/identity/oidcauth"

// Command translates immutable syntax, never authentication. The caller must
// complete continuation POST/CSRF admission and own the whole application and
// response deadline before invoking CallbackService; this method performs no I/O.
func (input LoginCallbackInput) Command() (oidcauth.CallbackCommand, error) {
	if !input.IsValid() {
		return oidcauth.CallbackCommand{}, ErrInvalidLoginCallback
	}
	kind := oidcauth.CallbackKindUnknown
	switch input.kind {
	case LoginCallbackCodeReceived:
		kind = oidcauth.CallbackCodeReceived
	case LoginCallbackProviderErrorReceived:
		kind = oidcauth.CallbackProviderErrorReceived
	}
	command, err := oidcauth.NewCallbackCommand(oidcauth.CallbackCommandParams{
		Route: input.route, State: input.state, PreAuthCookie: input.cookie, Code: input.code, Kind: kind,
	})
	if err != nil {
		return oidcauth.CallbackCommand{}, ErrInvalidLoginCallback
	}
	return command, nil
}
