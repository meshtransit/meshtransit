package probe

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerEchoesTheNonceAndAnswersNothingElse(t *testing.T) {
	t.Parallel()
	var results []string
	handler := Handler(func(result string) { results = append(results, result) })
	for _, test := range []struct {
		method, target string
		code           int
		nonce          string
	}{
		{http.MethodGet, "/generate_204?n=0123456789abcdef", http.StatusNoContent, "0123456789abcdef"},
		{http.MethodHead, "/generate_204?n=0123456789abcdef0123", http.StatusNoContent, "0123456789abcdef0123"},
		// A nonce that is not one is not echoed: the answer still says 204.
		{http.MethodGet, "/generate_204?n=<script>", http.StatusNoContent, ""},
		{http.MethodGet, "/generate_204", http.StatusNoContent, ""},
		{http.MethodPost, "/generate_204", http.StatusMethodNotAllowed, ""},
		{http.MethodGet, "/", http.StatusNotFound, ""},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), test.method, test.target, nil))
		if recorder.Code != test.code || recorder.Header().Get(NonceHeader) != test.nonce {
			t.Errorf("%s %s = %d %q, want %d %q", test.method, test.target, recorder.Code,
				recorder.Header().Get(NonceHeader), test.code, test.nonce)
		}
		if test.code == http.StatusNoContent && recorder.Body.Len() != 0 {
			t.Errorf("%s %s has a body", test.method, test.target)
		}
	}
	if len(results) != 6 || results[0] != "ok" || results[4] != "method" || results[5] != "not_found" {
		t.Fatalf("results %v", results)
	}
}

func TestHandlerLimitsABurst(t *testing.T) {
	t.Parallel()
	handler := Handler(nil)
	limited := 0
	for range probeBurst + 50 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, Path, nil))
		if recorder.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("a burst beyond the limit was answered")
	}
}
