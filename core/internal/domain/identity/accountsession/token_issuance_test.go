package accountsession_test

import (
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
)

func TestTokenIssuancePreservesVerifierEnvelope(t *testing.T) {
	t.Parallel()
	parsed, err := accountsession.ParseToken(canonicalEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	first, err := accountsession.GenerateToken(parsed.DeploymentID(), parsed.RecoveryEpoch())
	if err != nil {
		t.Fatal(err)
	}
	second, err := accountsession.GenerateToken(parsed.DeploymentID(), parsed.RecoveryEpoch())
	if err != nil {
		t.Fatal(err)
	}
	if !first.IsValid() || first.Encoded() == second.Encoded() {
		t.Fatal("fresh entropy missing")
	}
	decoded, err := accountsession.ParseToken(first.Encoded())
	if err != nil || decoded != first {
		t.Fatal("verifier envelope changed")
	}
	if (accountsession.Token{}).Encoded() != "" {
		t.Fatal("zero token encoded")
	}
}
