package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
)

const maximumBrowserSessionProofBytes = 256

type browserSessionProof struct {
	issued, expires time.Time
	encoded         string
}

func (browser *BrowserManagement) sealProof(
	token accountsession.Token,
	session accountsession.Session,
	now time.Time,
	nonce [32]byte,
) (browserSessionProof, error) {
	if !browser.activeSession(token, session, now) || nonce == ([32]byte{}) {
		return browserSessionProof{}, ErrInvalidBrowserManagement
	}
	issued := now.UTC().Truncate(time.Second)
	expires := issued.Add(browser.lifetime)
	if session.IdleExpiresAt().Before(expires) {
		expires = session.IdleExpiresAt().UTC().Truncate(time.Second)
	}
	if session.AbsoluteExpiresAt().Before(expires) {
		expires = session.AbsoluteExpiresAt().UTC().Truncate(time.Second)
	}
	if expires.Sub(now) < time.Second {
		return browserSessionProof{}, ErrBrowserManagementUnavailable
	}
	payload := strings.Join([]string{"mtscsrf1", browser.keyID,
		strconv.FormatInt(issued.Unix(), 10), strconv.FormatInt(expires.Unix(), 10),
		base64.RawURLEncoding.EncodeToString(nonce[:])}, ".")
	mac, err := browser.proofMAC(token, payload)
	if err != nil {
		return browserSessionProof{}, err
	}
	encoded := payload + "." + base64.RawURLEncoding.EncodeToString(mac)
	return browserSessionProof{issued: issued, expires: expires, encoded: encoded}, nil
}

func (browser *BrowserManagement) readProof(
	token accountsession.Token,
	encoded string,
	now time.Time,
) (browserSessionProof, error) {
	if !token.IsValid() || len(encoded) == 0 || len(encoded) > maximumBrowserSessionProofBytes {
		return browserSessionProof{}, ErrInvalidBrowserManagement
	}
	parts := strings.Split(encoded, ".")
	if len(parts) != 6 || parts[0] != "mtscsrf1" || parts[1] != browser.keyID {
		return browserSessionProof{}, ErrInvalidBrowserManagement
	}
	issued, issueErr := canonicalProofTime(parts[2])
	expires, expiryErr := canonicalProofTime(parts[3])
	validWindow := issueErr == nil && expiryErr == nil && expires.After(issued) &&
		expires.Sub(issued) <= browser.lifetime
	if !validWindow || !validCapsuleTime(now) || now.Before(issued) || !now.Before(expires) {
		return browserSessionProof{}, ErrInvalidBrowserManagement
	}
	nonce, nonceErr := canonicalProofBytes(parts[4])
	actual, macErr := canonicalProofBytes(parts[5])
	if nonceErr != nil || macErr != nil || nonce == ([32]byte{}) {
		return browserSessionProof{}, ErrInvalidBrowserManagement
	}
	expected, err := browser.proofMAC(token, strings.Join(parts[:5], "."))
	if err != nil || !hmac.Equal(actual[:], expected) {
		return browserSessionProof{}, ErrInvalidBrowserManagement
	}
	return browserSessionProof{issued: issued, expires: expires, encoded: encoded}, nil
}

func (browser *BrowserManagement) proofMAC(token accountsession.Token, payload string) ([]byte, error) {
	// All fields have validated NUL-free grammars. The full bearer stays resident,
	// not in the proof envelope, public-ID budgets, telemetry or diagnostics.
	input := strings.Join([]string{"meshtransit/browser-management-csrf/v1", browser.deploymentID.String(),
		browser.origin, token.Encoded(), payload}, "\x00")
	mac := hmac.New(sha256.New, browser.key[:])
	if _, err := mac.Write([]byte(input)); err != nil {
		return nil, ErrBrowserManagementUnavailable
	}
	return mac.Sum(nil), nil
}

func canonicalProofTime(encoded string) (time.Time, error) {
	if len(encoded) == 0 || len(encoded) > 12 {
		return time.Time{}, ErrInvalidBrowserManagement
	}
	seconds, err := strconv.ParseInt(encoded, 10, 64)
	if err != nil || seconds <= 0 || strconv.FormatInt(seconds, 10) != encoded {
		return time.Time{}, ErrInvalidBrowserManagement
	}
	at := time.Unix(seconds, 0).UTC()
	if !validCapsuleTime(at) {
		return time.Time{}, ErrInvalidBrowserManagement
	}
	return at, nil
}

func canonicalProofBytes(encoded string) ([32]byte, error) {
	if len(encoded) != 43 {
		return [32]byte{}, ErrInvalidBrowserManagement
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return [32]byte{}, ErrInvalidBrowserManagement
	}
	var value [32]byte
	copy(value[:], decoded)
	return value, nil
}

func (browser *BrowserManagement) activeSession(
	token accountsession.Token,
	session accountsession.Session,
	now time.Time,
) bool {
	return validCapsuleTime(now) && session.IsActiveAt(now) && token.IsValid() &&
		token.DeploymentID() == browser.deploymentID && session.DeploymentID() == browser.deploymentID &&
		token.RecoveryEpoch() == session.DeploymentRecoveryEpoch()
}

func (browserSessionProof) String() string               { return "[REDACTED]" }
func (browserSessionProof) GoString() string             { return "httpapi.browserSessionProof([REDACTED])" }
func (browserSessionProof) LogValue() slog.Value         { return slog.StringValue("[REDACTED]") }
func (browserSessionProof) MarshalJSON() ([]byte, error) { return nil, ErrInvalidBrowserManagement }
