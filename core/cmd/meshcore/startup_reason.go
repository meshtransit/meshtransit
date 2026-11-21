package main

import (
	"context"
	"errors"

	"meshtransit.net/core/internal/adapter/httpapi"
)

var (
	// errStartupFilesUnreadable: a file the role was given (TLS
	// certificate or key, a profile's secret or key) could not be read.
	errStartupFilesUnreadable = errors.New("startup: a configured file cannot be read")
	// errStartupIdentityDatabase: the identity broker's database could not
	// be opened.
	errStartupIdentityDatabase = errors.New("startup: the identity database cannot be opened")
	// errStartupIdentityDatabaseSettings: the identity database settings or
	// their files (password, CA) are invalid.
	errStartupIdentityDatabaseSettings = errors.New("startup: the identity database settings are invalid")
	// errStartupProfileRejected: the private login profile's files (TLS,
	// client secret, keys) are refused: unreadable, invalid, a key used for
	// two purposes, or read past the deadline.
	errStartupProfileRejected = errors.New("startup: the login profile's files are refused")
	// errStartupFilesChanged: a file changed while it was read (a
	// certificate renewed at start); a restart reads it again.
	errStartupFilesChanged = errors.New("startup: a file changed while it was read")
)

// compositionError reports a composition failure with its own closed
// message only (no address or other topology from the cause) while still
// carrying the cause for errors.Is, which startupFailureReason reads.
type compositionError struct {
	failure error
	causes  []error
}

func withCause(failure error, causes ...error) error {
	return &compositionError{failure: failure, causes: causes}
}

func (composition *compositionError) Error() string { return composition.failure.Error() }

func (composition *compositionError) Unwrap() []error {
	return append([]error{composition.failure}, composition.causes...)
}

// startupFailureReason names, from a closed set, why a role's composition
// failed, so an operator can act although the error text is redacted:
// "unclassified" when no known cause is among the errors.
func startupFailureReason(err error) string {
	for _, known := range []struct {
		err    error
		reason string
	}{
		{httpapi.ErrServerCertificateName, "tls_certificate_name"},
		{httpapi.ErrServerCertificateUsage, "tls_certificate_usage"},
		{httpapi.ErrServerCertificateStrength, "tls_certificate_strength"},
		{httpapi.ErrServerCertificateUnreadable, "tls_certificate_unreadable"},
		{errStartupFilesUnreadable, "files_unreadable"},
		{errStartupProfileRejected, "profile_files_rejected"},
		{errStartupFilesChanged, "files_changed_while_read"},
		{errStartupIdentityDatabaseSettings, "identity_database_settings"},
		{errStartupIdentityDatabase, "identity_database_unavailable"},
		{context.DeadlineExceeded, "timeout"},
	} {
		if errors.Is(err, known.err) {
			return known.reason
		}
	}
	return "unclassified"
}
