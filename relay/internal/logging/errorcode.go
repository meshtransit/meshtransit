package logging

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/acme"
)

// Coded is an error that names its own closed code.
type Coded interface{ ErrorCode() string }

// StatusCoded is an error carrying an HTTP status.
type StatusCoded interface{ StatusCode() int }

type codedError struct {
	code string
	err  error
}

func (coded codedError) Error() string     { return coded.err.Error() }
func (coded codedError) Unwrap() error     { return coded.err }
func (coded codedError) ErrorCode() string { return coded.code }

// Code wraps err with a closed code for the log.
func Code(code string, err error) error {
	if err == nil {
		return nil
	}
	return codedError{code: code, err: err}
}

// ErrorAttrs are the attributes a warning logs for err: the error itself
// (redacted by the handler), a closed error_code an operator can act on,
// and the HTTP status when there is one (TD-SEC-28).
func ErrorAttrs(err error) []any {
	attrs := []any{"error", err, "error_code", ErrorCode(err)}
	var status StatusCoded
	if errors.As(err, &status) {
		attrs = append(attrs, "status_code", status.StatusCode())
	}
	return attrs
}

// ErrorCode classifies err into a closed, non-sensitive code.
func ErrorCode(err error) string {
	var coded Coded
	var acmeError *acme.Error
	var dns *net.DNSError
	var errno syscall.Errno
	var netError net.Error
	var unknownAuthority x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var verification *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	switch {
	case err == nil:
		return "none"
	case errors.As(err, &coded):
		return coded.ErrorCode()
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &acmeError):
		return "acme_" + problem(acmeError.ProblemType)
	case errors.As(err, &dns):
		return "dns"
	case errors.As(err, &unknownAuthority), errors.As(err, &invalid), errors.As(err, &hostname),
		errors.As(err, &verification), errors.As(err, &record):
		return "tls"
	case errors.As(err, &errno):
		return errnoCode(errno)
	case errors.As(err, &netError) && netError.Timeout():
		return "timeout"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	}
	return "other"
}

func errnoCode(errno syscall.Errno) string {
	switch errno {
	case syscall.ECONNREFUSED:
		return "connection_refused"
	case syscall.ECONNRESET:
		return "connection_reset"
	case syscall.ECONNABORTED:
		return "connection_aborted"
	case syscall.EMFILE, syscall.ENFILE:
		return "too_many_files"
	case syscall.ENETUNREACH, syscall.EHOSTUNREACH:
		return "unreachable"
	}
	return "errno_" + strconv.Itoa(int(errno))
}

// problem keeps the last segment of an ACME problem URN, letters only.
func problem(urn string) string {
	last := urn[strings.LastIndex(urn, ":")+1:]
	var builder strings.Builder
	for _, r := range last {
		if builder.Len() >= 32 {
			break
		}
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			builder.WriteRune(r)
		}
	}
	if builder.Len() == 0 {
		return "unknown"
	}
	return builder.String()
}
