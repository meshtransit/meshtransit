package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWithNoTransformAddsTheDirective(t *testing.T) {
	tests := []struct {
		name  string
		serve func(http.ResponseWriter)
		want  string
	}{
		{"no header", func(w http.ResponseWriter) { _, _ = w.Write([]byte("{}")) }, "no-store, no-transform"},
		{"no-store", func(w http.ResponseWriter) {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
		}, "no-store, no-transform"},
		{"already there", func(w http.ResponseWriter) {
			w.Header().Set("Cache-Control", "no-store, No-Transform")
			w.WriteHeader(http.StatusNoContent)
		}, "no-store, No-Transform"},
		{"public", func(w http.ResponseWriter) {
			w.Header().Set("Cache-Control", "public, max-age=60")
			_, _ = w.Write([]byte("x"))
		}, "public, max-age=60, no-transform"},
		{"two fields", func(w http.ResponseWriter) {
			w.Header().Add("Cache-Control", "private")
			w.Header().Add("Cache-Control", "max-age=0")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("x"))
		}, "private, max-age=0, no-transform"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler := withNoTransform(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { test.serve(w) }))
			handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/x", nil))
			if got := recorder.Header().Values("Cache-Control"); len(got) != 1 || got[0] != test.want {
				t.Fatalf("Cache-Control = %q, want %q", got, test.want)
			}
		})
	}
}

func TestWithNoTransformKeepsResponseController(t *testing.T) {
	server := httptest.NewServer(withNoTransform(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	defer server.Close()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent || response.Header.Get("Cache-Control") != "no-store, no-transform" {
		t.Fatalf("response = %d %q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
}

func TestServersSendNoTransform(t *testing.T) {
	plain := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	management, err := NewManagementServer(ManagementServerOptions{
		Address: "127.0.0.1:0", Certificate: managementTLSCertificate(t), Handler: plain, MaxConnections: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	management.server.Handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/workspaces", nil))
	if got := recorder.Header().Get("Cache-Control"); got != "no-store, no-transform" {
		t.Fatalf("management Cache-Control = %q", got)
	}

	options, _, _ := loginServerTestOptions(t)
	login, err := NewLoginServer(options)
	if err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	login.server.Handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/v1/unknown", nil))
	if got := recorder.Header().Get("Cache-Control"); got != "no-store, no-transform" {
		t.Fatalf("login Cache-Control = %q (status %d)", got, recorder.Code)
	}
}

// servedNoStore is Cache-Control as a client of the owned servers sees it.
const servedNoStore = "no-store, no-transform"
