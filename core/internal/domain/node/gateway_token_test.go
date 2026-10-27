package node_test

import (
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

func TestGatewayTokenIsValid(t *testing.T) {
	t.Parallel()
	id, err := publicid.Parse("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	valid := node.GatewayToken{DeviceID: node.ID(id), TrustVersion: 1, JTI: "6c1e5b8e-6d7c",
		ExpiresAt: time.Unix(1_800_000_000, 0)}
	if !valid.IsValid() {
		t.Fatal("a complete token is invalid")
	}
	for name, change := range map[string]func(*node.GatewayToken){
		"no Device":        func(token *node.GatewayToken) { token.DeviceID = node.ID{} },
		"no trust version": func(token *node.GatewayToken) { token.TrustVersion = 0 },
		"no jti":           func(token *node.GatewayToken) { token.JTI = "" },
		"long jti":         func(token *node.GatewayToken) { token.JTI = strings.Repeat("j", 129) },
		"jti with a space": func(token *node.GatewayToken) { token.JTI = "a b" },
		"no expiry":        func(token *node.GatewayToken) { token.ExpiresAt = time.Time{} },
	} {
		token := valid
		change(&token)
		if token.IsValid() {
			t.Errorf("%s: IsValid() = true", name)
		}
	}
}
