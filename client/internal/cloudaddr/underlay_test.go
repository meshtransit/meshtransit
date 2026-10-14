package cloudaddr

import (
	"net/http"
	"testing"

	"meshtransit.net/client/internal/underlay/underlaytest"
)

// Not parallel: the underlay protector is process-wide.
func TestMetadataSocketsAreProtected(t *testing.T) {
	underlaytest.Refuse(t)
	transport, ok := NewClient().http.Transport.(*http.Transport)
	if !ok {
		t.Fatal("the metadata transport is not an *http.Transport")
	}
	_, err := transport.DialContext(t.Context(), "tcp", "127.0.0.1:9")
	underlaytest.RequireProtected(t, "metadata HTTP transport", err)
}
