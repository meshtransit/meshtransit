package accountsession_test

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
)

const canonicalEnvelope = "mtas1.01890f00-0000-7000-8000-000000000001.7.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"

func TestParseToken(t *testing.T) {
	t.Parallel()

	token, err := accountsession.ParseToken(canonicalEnvelope)
	if err != nil {
		t.Fatalf("ParseToken() error = %v", err)
	}
	if !token.IsValid() ||
		token.DeploymentID().String() != "01890f00-0000-7000-8000-000000000001" ||
		token.RecoveryEpoch() != 7 {
		t.Fatal("ParseToken() returned invalid authority qualifiers")
	}
	if fmt.Sprint(token) != "[REDACTED]" ||
		fmt.Sprintf("%#v", token) != "accountsession.Token([REDACTED])" ||
		token.LogValue().Kind() != slog.KindString ||
		token.LogValue().String() != "[REDACTED]" {
		t.Fatal("Token formatting disclosed bearer material")
	}
}

func TestParseTokenRejectsMalformedValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "wrong version", value: "mtas2.01890f00-0000-7000-8000-000000000001.7.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"},
		{name: "uppercase deployment", value: "mtas1.01890F00-0000-7000-8000-000000000001.7.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"},
		{name: "zero epoch", value: "mtas1.01890f00-0000-7000-8000-000000000001.0.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"},
		{name: "noncanonical epoch", value: "mtas1.01890f00-0000-7000-8000-000000000001.07.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"},
		{name: "short secret", value: "mtas1.01890f00-0000-7000-8000-000000000001.7.AQE"},
		{name: "padded secret", value: "mtas1.01890f00-0000-7000-8000-000000000001.7.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="},
		{name: "zero secret", value: "mtas1.01890f00-0000-7000-8000-000000000001.7.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := accountsession.ParseToken(test.value); err == nil {
				t.Fatal("ParseToken() error = nil")
			}
		})
	}
}
