package mtcp

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/platform/clientip"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// syncBuffer is a log sink safe for the server's goroutines.
type syncBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (sink *syncBuffer) Write(p []byte) (int, error) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.buffer.Write(p)
}

func (sink *syncBuffer) count(substring string) int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return strings.Count(sink.buffer.String(), substring)
}

func TestUntrustedForwardingIsCountedAndWarnedAtABoundedRate(t *testing.T) {
	var logs syncBuffer
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	trusted, err := clientip.NewResolver([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, func(options *Options) {
		options.ClientIPs = trusted
		options.Logger = slog.New(slog.NewTextHandler(&logs, nil))
		options.Now = clock
	})
	upgrade := func(remote string, header string) {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, sharedmtcp.WebSocketPath, nil)
		request.RemoteAddr = remote
		request.Header.Set("Sec-WebSocket-Protocol", sharedmtcp.WebSocketProtocol)
		if header != "" {
			request.Header.Set(header, "198.51.100.9")
		}
		// No MTCP key: refused after the forwarding check, before any work.
		f.server.ServeHTTP(httptest.NewRecorder(), request)
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(f.server.options.Metrics.Collectors()...)
	counted := func() float64 {
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, family := range families {
			if family.GetName() == "meshtransit_mtcp_untrusted_forwarding_total" {
				return family.GetMetric()[0].GetCounter().GetValue()
			}
		}
		t.Fatal("untrusted forwarding counter not exported")
		return 0
	}

	upgrade("10.20.3.4:443", "X-Forwarded-For")
	upgrade("203.0.113.7:443", "")
	if counted() != 0 || logs.count("mtcp_untrusted_forwarding") != 0 {
		t.Fatal("a trusted proxy or a plain direct client was reported as untrusted forwarding")
	}

	upgrade("203.0.113.7:443", "X-Forwarded-For")
	upgrade("203.0.113.8:443", "CF-Connecting-IP")
	if counted() != 2 {
		t.Fatalf("counted %v untrusted forwarding requests, want 2", counted())
	}
	if got := logs.count("mtcp_untrusted_forwarding"); got != 1 {
		t.Fatalf("warned %d times within one interval, want 1", got)
	}

	mu.Lock()
	now = now.Add(untrustedForwardingWarnEvery)
	mu.Unlock()
	upgrade("203.0.113.7:443", "Forwarded")
	if got := logs.count("mtcp_untrusted_forwarding"); got != 2 {
		t.Fatalf("warned %d times after the interval, want 2", got)
	}
}
