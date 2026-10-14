package mtcpclient

import (
	"crypto/tls"
	"net/http"
	"testing"

	"meshtransit.net/client/internal/underlay/underlaytest"
)

// Not parallel: the underlay protector is process-wide.
func TestControlSocketsAreProtected(t *testing.T) {
	underlaytest.Refuse(t)
	_, err := dialTLS(t.Context(), "127.0.0.1:9", &tls.Config{MinVersion: tls.VersionTLS12})
	underlaytest.RequireProtected(t, "dialTLS", err)
	transport, ok := New().httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("the control transport is not an *http.Transport")
	}
	_, err = transport.DialContext(t.Context(), "tcp", "127.0.0.1:9")
	underlaytest.RequireProtected(t, "control HTTP transport", err)
}
