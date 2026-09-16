package ratelimit

import (
	"fmt"
	"log/slog"
	"testing"
	"time"
)

func TestDigesterSeparatesKindsAndRedactsMaterial(t *testing.T) {
	t.Parallel()

	keyID, err := NewDigestKeyID("management-v1")
	if err != nil {
		t.Fatalf("NewDigestKeyID() error = %v", err)
	}
	material := make([]byte, 32)
	material[31] = 1
	digester, err := NewDigester(keyID, material)
	if err != nil {
		t.Fatalf("NewDigester() error = %v", err)
	}
	source, err := digester.Subject(SubjectSource, "192.0.2.10")
	if err != nil {
		t.Fatalf("Subject(source) error = %v", err)
	}
	session, err := digester.Subject(SubjectAccountSession, "192.0.2.10")
	if err != nil {
		t.Fatalf("Subject(session) error = %v", err)
	}
	if !source.IsValid() || !session.IsValid() || source.DigestString() == session.DigestString() {
		t.Fatalf("subjects = (%+v, %+v), want valid purpose-separated digests", source, session)
	}
	auth, err := digester.Subject(SubjectAuthTransaction, "192.0.2.10")
	if err != nil || !auth.IsValid() || auth.Kind() != SubjectAuthTransaction ||
		auth.DigestString() == source.DigestString() || auth.DigestString() == session.DigestString() {
		t.Fatal("auth transaction budget lost purpose separation")
	}
	if got := fmt.Sprintf("%s|%#v|%s", digester, digester, digester.LogValue().String()); got != "[REDACTED]|ratelimit.Digester([REDACTED])|[REDACTED]" {
		t.Fatalf("redaction = %q", got)
	}
	_ = slog.Any("digester", digester)
}

func TestPolicyAndDecisionValidation(t *testing.T) {
	t.Parallel()

	policy, err := NewPolicy(30, time.Second)
	if err != nil || !policy.IsValid() || policy.Capacity() != 30 || policy.RefillInterval() != time.Second {
		t.Fatalf("NewPolicy() = (%+v, %v)", policy, err)
	}
	for _, invalid := range []struct {
		capacity int
		interval time.Duration
	}{{0, time.Second}, {1, 9 * time.Millisecond}, {1, time.Second + time.Microsecond}} {
		if _, err := NewPolicy(invalid.capacity, invalid.interval); err == nil {
			t.Fatalf("NewPolicy(%d, %s) accepted", invalid.capacity, invalid.interval)
		}
	}
	allowed, err := NewDecision(true, 30, 29, 0)
	if err != nil || !allowed.Allowed() || allowed.Remaining() != 29 {
		t.Fatalf("allowed decision = (%+v, %v)", allowed, err)
	}
	denied, err := NewDecision(false, 30, 0, time.Second)
	if err != nil || denied.Allowed() || denied.RetryAfter() != time.Second {
		t.Fatalf("denied decision = (%+v, %v)", denied, err)
	}
	if _, err := NewDecision(false, 30, 1, time.Second); err == nil {
		t.Fatal("denied decision with remaining tokens accepted")
	}
}
