package openapi

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestComposeLoginDocumentRejectsCompiledContractDrift(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, from, to string
	}{
		{name: "version", from: `"openapi": "3.1.0"`, to: `"openapi": "3.0.0"`},
		{name: "profile", from: `"x-meshtransit-auth-profile": "console-cookie-csrf-private-v1"`,
			to: `"x-meshtransit-auth-profile": "account-session-bearer-v1"`},
		{name: "activation", from: `"x-meshtransit-runtime-status": "private-source-only"`,
			to: `"x-meshtransit-runtime-status": "enabled"`},
		{name: "inherited security", from: `"openapi": "3.1.0"`, to: `"security": [], "openapi": "3.1.0"`},
		{name: "unknown path", from: `"/auth/v1/login/start":`, to: `"/auth/private/start":`},
		{name: "unknown method", from: `"post": {`, to: `"put": {`},
		{name: "unknown operation", from: `"operationId": "startBrowserLogin"`, to: `"operationId": "grantSession"`},
		{name: "anonymous start", from: `"security": [{ "loginInitiationCookie": [], "loginIntentProof": [] }]`,
			to: `"security": []`},
		{name: "or instead of and", from: `"security": [{ "loginInitiationCookie": [], "loginIntentProof": [] }]`,
			to: `"security": [{ "loginInitiationCookie": [] }, { "loginIntentProof": [] }]`},
		{name: "null anonymous", from: `"security": []`, to: `"security": null`},
		{name: "null scope", from: `"loginIntentProof": []`, to: `"loginIntentProof": null`},
		{name: "provider scope", from: `"loginIntentProof": []`, to: `"loginIntentProof": ["openid"]`},
		{name: "extra bearer", from: `"loginIntentProof": []`, to: `"loginIntentProof": [], "bearer": []`},
		{name: "completion only syntax", from: `"capturedCallbackCookie": [], "continuationIntentProof": []`,
			to: `"capturedCallbackCookie": []`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if !strings.Contains(loginConsolePrivateContract, test.from) {
				t.Fatal("drift test did not target the actual asset")
			}
			asset := strings.Replace(loginConsolePrivateContract, test.from, test.to, 1)
			body, err := composeLoginDocument(asset, "/auth/callback")
			if body != nil || !errors.Is(err, ErrInvalidLoginProfile) {
				t.Fatal("compiled route/security drift released a document", err)
			}
		})
	}
	for _, asset := range []string{"", "null", "{}", "{", strings.Repeat(" ", 128<<10+1)} {
		body, err := composeLoginDocument(asset, "/auth/callback")
		if body != nil || !errors.Is(err, ErrInvalidLoginProfile) {
			t.Fatal("invalid/unbounded compiled asset released bytes")
		}
	}
}

func TestLoginSecurityRejectsUnknownOperation(t *testing.T) {
	t.Parallel()
	if validLoginOperationSecurity(json.RawMessage(`[]`), "grantSession") {
		t.Fatal("unreviewed operation inherited anonymous security")
	}
}
