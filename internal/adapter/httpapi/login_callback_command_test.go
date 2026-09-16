package httpapi

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

func TestLoginCallbackCommandTranslatesSyntaxWithoutAuthority(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"code", "provider error", "zero", "unknown", "ambiguous error"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			input := newContinuationGateFixture(t).input
			kind := oidcauth.CallbackCodeReceived
			valid := name == "code" || name == "provider error"
			switch name {
			case "provider error":
				input.kind, input.code = LoginCallbackProviderErrorReceived, oidcauth.Code{}
				kind = oidcauth.CallbackProviderErrorReceived
			case "zero":
				input = LoginCallbackInput{}
			case "unknown":
				input.kind = LoginCallbackUnknown
			case "ambiguous error":
				input.kind = LoginCallbackProviderErrorReceived
			}
			command, err := input.Command()
			if !valid {
				if !errors.Is(err, ErrInvalidLoginCallback) || command.IsValid() {
					t.Fatal("invalid adapter input became an application command")
				}
				return
			}
			want, wantErr := oidcauth.NewCallbackCommand(oidcauth.CallbackCommandParams{
				Route: input.route, State: input.state, PreAuthCookie: input.cookie, Code: input.code, Kind: kind,
			})
			if err != nil || wantErr != nil || !command.IsValid() || !reflect.DeepEqual(command, want) {
				t.Fatal("adapter changed callback binding or variant")
			}
			if encoded, err := json.Marshal(command); err == nil || len(encoded) != 0 {
				t.Fatal("application command leaked through JSON")
			}
		})
	}
}
