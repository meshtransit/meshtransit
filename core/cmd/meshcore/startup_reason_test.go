package main

import (
	"context"
	"errors"
	"testing"

	"meshtransit.net/core/internal/adapter/httpapi"
)

func TestStartupFailureReason(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{name: "certificate names another host",
			err:  errors.Join(errInvalidPrivateIdentityComposition, httpapi.ErrInvalidLoginServer, httpapi.ErrServerCertificateName),
			want: "tls_certificate_name"},
		{name: "certificate without server auth",
			err:  errors.Join(errInvalidIdentityBrokerComposition, httpapi.ErrInvalidIdentityServer, httpapi.ErrServerCertificateUsage),
			want: "tls_certificate_usage"},
		{name: "weak certificate", err: httpapi.ErrServerCertificateStrength, want: "tls_certificate_strength"},
		{name: "certificate and key do not pair", err: httpapi.ErrServerCertificateUnreadable,
			want: "tls_certificate_unreadable"},
		{name: "file missing", err: errors.Join(errInvalidIdentityBrokerComposition, errStartupFilesUnreadable),
			want: "files_unreadable"},
		{name: "identity database", err: errors.Join(errInvalidIdentityBrokerComposition, errStartupIdentityDatabase),
			want: "identity_database_unavailable"},
		{name: "profile files refused", err: errors.Join(errInvalidPrivateIdentityComposition, errStartupProfileRejected),
			want: "profile_files_rejected"},
		{name: "renewed while read", err: errors.Join(errInvalidPrivateIdentityComposition, errStartupFilesChanged),
			want: "files_changed_while_read"},
		{name: "identity database settings", err: errors.Join(errStartupIdentityDatabaseSettings, errStartupIdentityDatabase),
			want: "identity_database_settings"},
		{name: "deadline", err: errors.Join(errInvalidPrivateIdentityComposition, context.DeadlineExceeded), want: "timeout"},
		{name: "anything else", err: errInvalidPrivateIdentityComposition, want: "unclassified"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := startupFailureReason(test.err); got != test.want {
				t.Fatalf("reason = %s, want %s", got, test.want)
			}
		})
	}
}

// A composition error says only its own closed message, whatever the cause
// carries (an address, a host), and still answers errors.Is for both.
func TestWithCauseKeepsTheClosedMessage(t *testing.T) {
	t.Parallel()
	cause := errors.New("listen 10.0.0.7:9443: refused")
	err := withCause(errInvalidPrivateIdentityComposition, cause)
	if err.Error() != errInvalidPrivateIdentityComposition.Error() {
		t.Fatalf("message = %q", err.Error())
	}
	if !errors.Is(err, errInvalidPrivateIdentityComposition) || !errors.Is(err, cause) {
		t.Fatal("the failure or its cause is lost")
	}
}
