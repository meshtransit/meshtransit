package legacyts2021

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestControlServerPublishesPinnedControlKey(t *testing.T) {
	t.Parallel()

	server := newControlServerFixture(t, respondingSessionFactory())
	request := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"http://control.example/key?v=142",
		nil,
	)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("control key status = %d, want 200", response.Code)
	}
	if response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("control key headers = %v", response.Header())
	}
	var decoded controlKeyResponseWire
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("Decode(trailing) error = %v, want EOF", err)
	}
	if decoded.PublicKey != server.publicKey || !strings.HasPrefix(decoded.PublicKey, "mkey:") {
		t.Fatalf("published control key = %q, want configured public key", decoded.PublicKey)
	}
}

func TestNewControlServerRejectsUnsafeOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*ControlServerOptions)
	}{
		{name: "missing private key", mutate: func(options *ControlServerOptions) {
			options.PrivateKey = ControlPrivateKey{}
		}},
		{name: "missing sessions", mutate: func(options *ControlServerOptions) {
			options.Sessions = nil
		}},
		{name: "missing logger", mutate: func(options *ControlServerOptions) {
			options.Logger = nil
		}},
		{name: "zero sessions", mutate: func(options *ControlServerOptions) {
			options.MaxSessions = 0
		}},
		{name: "excess sessions", mutate: func(options *ControlServerOptions) {
			options.MaxSessions = maxControlSessions + 1
		}},
		{name: "zero streams", mutate: func(options *ControlServerOptions) {
			options.MaxConcurrentStreams = 0
		}},
		{name: "excess streams", mutate: func(options *ControlServerOptions) {
			options.MaxConcurrentStreams = maxControlSessionStreams + 1
		}},
		{name: "short handshake", mutate: func(options *ControlServerOptions) {
			options.HandshakeTimeout = minControlTimeout - time.Nanosecond
		}},
		{name: "long handshake", mutate: func(options *ControlServerOptions) {
			options.HandshakeTimeout = maxControlHandshake + time.Nanosecond
		}},
		{name: "short read idle", mutate: func(options *ControlServerOptions) {
			options.ReadIdleTimeout = minControlTimeout - time.Nanosecond
		}},
		{name: "ping exceeds read idle", mutate: func(options *ControlServerOptions) {
			options.PingTimeout = options.ReadIdleTimeout + time.Nanosecond
		}},
		{name: "short write timeout", mutate: func(options *ControlServerOptions) {
			options.WriteTimeout = minControlTimeout - time.Nanosecond
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			options := controlServerOptionsFixture(t, respondingSessionFactory())
			test.mutate(&options)
			if _, err := NewControlServer(options); !errors.Is(err, ErrInvalidControlServer) {
				t.Fatalf("NewControlServer() error = %v, want invalid server", err)
			}
		})
	}
}

func TestControlServerRejectsInvalidPublicBoundary(t *testing.T) {
	t.Parallel()

	validUpgrade := newNoiseUpgradeRequest(t)
	tests := []struct {
		name       string
		request    *http.Request
		wantStatus int
	}{
		{
			name: "unknown path",
			request: httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"http://control.example/machine/register",
				nil,
			),
			wantStatus: http.StatusNotFound,
		},
		{
			name: "wrong key method",
			request: httptest.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"http://control.example/key?v=142",
				nil,
			),
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name: "wrong key capability",
			request: httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"http://control.example/key?v=141",
				nil,
			),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "wrong upgrade method",
			request: cloneRequestWith(t, validUpgrade, func(request *http.Request) {
				request.Method = http.MethodGet
			}),
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name: "upgrade query",
			request: cloneRequestWith(t, validUpgrade, func(request *http.Request) {
				request.URL.RawQuery = "scope=untrusted"
			}),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "missing connection upgrade",
			request: cloneRequestWith(t, validUpgrade, func(request *http.Request) {
				request.Header.Del("Connection")
			}),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "wrong upgrade protocol",
			request: cloneRequestWith(t, validUpgrade, func(request *http.Request) {
				request.Header.Set("Upgrade", "unsupported")
			}),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "duplicate upgrade protocol",
			request: cloneRequestWith(t, validUpgrade, func(request *http.Request) {
				request.Header["Upgrade"] = []string{noiseUpgradeProtocol, noiseUpgradeProtocol}
			}),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "missing handshake",
			request: cloneRequestWith(t, validUpgrade, func(request *http.Request) {
				request.Header.Del(noiseHandshakeHeader)
			}),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "duplicate handshake",
			request: cloneRequestWith(t, validUpgrade, func(request *http.Request) {
				request.Header[noiseHandshakeHeader] = []string{"AQ==", "AQ=="}
			}),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "malformed handshake",
			request: cloneRequestWith(t, validUpgrade, func(request *http.Request) {
				request.Header.Set(noiseHandshakeHeader, "not-base64")
			}),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "oversized handshake",
			request: cloneRequestWith(t, validUpgrade, func(request *http.Request) {
				request.Header.Set(
					noiseHandshakeHeader,
					strings.Repeat("A", base64.StdEncoding.EncodedLen(maxNoiseInitiationBytes)+1),
				)
			}),
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newControlServerFixture(t, respondingSessionFactory())
			response := httptest.NewRecorder()
			server.ServeHTTP(response, test.request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
		})
	}
}

func TestControlServerFailsClosedWithoutHijackOrCapacity(t *testing.T) {
	t.Parallel()

	server := newControlServerFixture(t, respondingSessionFactory())
	response := httptest.NewRecorder()
	server.ServeHTTP(response, newNoiseUpgradeRequest(t))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("non-hijack response status = %d, want 500", response.Code)
	}

	server.slots <- struct{}{}
	server.slots <- struct{}{}
	response = httptest.NewRecorder()
	server.ServeHTTP(response, newNoiseUpgradeRequest(t))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("saturated response status = %d, want 503", response.Code)
	}
	<-server.slots
	<-server.slots
}

func cloneRequestWith(
	t testing.TB,
	source *http.Request,
	mutate func(*http.Request),
) *http.Request {
	t.Helper()

	request := source.Clone(source.Context())
	request.Header = source.Header.Clone()
	urlCopy := *source.URL
	request.URL = &urlCopy
	mutate(request)
	return request
}
