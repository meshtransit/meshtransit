package httpapi

import (
	"net/http"
	"strings"
)

// withNoTransform makes every response of the browser auth and management
// servers carry Cache-Control no-transform, so a proxy in front (Cloudflare)
// never compresses a response that may hold secrets or tokens (BREACH). A
// response without its own Cache-Control also gets no-store. It wraps the
// whole server, so a handler that forgets the header is still covered.
func withNoTransform(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		writer := &noTransformWriter{ResponseWriter: response}
		next.ServeHTTP(writer, request)
		// A handler that wrote nothing still gets an implicit header.
		writer.addDirective()
	})
}

// noTransformWriter adds the directive just before the header is sent.
// Unwrap keeps http.ResponseController deadlines reaching the transport.
type noTransformWriter struct {
	http.ResponseWriter
	sent bool
}

func (writer *noTransformWriter) WriteHeader(status int) {
	writer.addDirective()
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *noTransformWriter) Write(body []byte) (int, error) {
	writer.addDirective()
	return writer.ResponseWriter.Write(body)
}

func (writer *noTransformWriter) Unwrap() http.ResponseWriter { return writer.ResponseWriter }

func (writer *noTransformWriter) addDirective() {
	if writer.sent {
		return
	}
	writer.sent = true
	header := writer.Header()
	current := header.Values("Cache-Control")
	if len(current) == 0 {
		header.Set("Cache-Control", "no-store, no-transform")
		return
	}
	joined := strings.Join(current, ", ")
	for directive := range strings.SplitSeq(joined, ",") {
		if strings.EqualFold(strings.TrimSpace(directive), "no-transform") {
			return
		}
	}
	header.Set("Cache-Control", joined+", no-transform")
}
