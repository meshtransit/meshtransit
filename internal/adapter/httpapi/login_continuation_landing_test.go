package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/goleak"
)

func landingTestOptions(t *testing.T) (LoginContinuationLandingOptions, *completionTestPort) {
	t.Helper()
	options, _, port := completionTestOptions(t)
	completion, err := NewLoginCompletion(options)
	if err != nil {
		t.Fatal(err)
	}
	return LoginContinuationLandingOptions{Completion: completion, Observer: NewLoginLandingTelemetry(),
		RequestTimeout: 2 * time.Second, MaxConcurrent: 1}, port
}

func TestLoginContinuationLandingRejectsConstruction(t *testing.T) {
	t.Parallel()
	var absent *LoginLandingTelemetry
	for _, test := range []struct {
		name   string
		change func(*LoginContinuationLandingOptions)
	}{
		{name: "missing completion", change: func(o *LoginContinuationLandingOptions) { o.Completion = nil }},
		{name: "zero completion", change: func(o *LoginContinuationLandingOptions) { o.Completion = &LoginCompletion{} }},
		{name: "missing gate", change: func(o *LoginContinuationLandingOptions) { o.Completion.options.Admission = nil }},
		{name: "missing observer", change: func(o *LoginContinuationLandingOptions) { o.Observer = nil }},
		{name: "typed nil observer", change: func(o *LoginContinuationLandingOptions) { o.Observer = absent }},
		{name: "zero timeout", change: func(o *LoginContinuationLandingOptions) { o.RequestTimeout = 0 }},
		{name: "long timeout", change: func(o *LoginContinuationLandingOptions) { o.RequestTimeout = 31 * time.Second }},
		{name: "zero capacity", change: func(o *LoginContinuationLandingOptions) { o.MaxConcurrent = 0 }},
		{name: "large capacity", change: func(o *LoginContinuationLandingOptions) { o.MaxConcurrent = 129 }},
		{name: "foreign mapping", change: func(o *LoginContinuationLandingOptions) {
			o.Completion.options.ReturnRouteID = "other"
		}},
		{name: "unsafe path", change: func(o *LoginContinuationLandingOptions) {
			o.Completion.options.ReturnPath = "//other.example.test"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options, _ := landingTestOptions(t)
			test.change(&options)
			if landing, err := NewLoginContinuationLanding(options); landing != nil || !errors.Is(err, ErrInvalidLoginLanding) {
				t.Fatal("invalid landing constructed")
			}
		})
	}
}

func landingTestRequest() *http.Request {
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		LoginCallbackContinuePath,
		nil,
	)
	request.Host = "console.example.test"
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	return request
}

func TestLoginContinuationLandingPresentsOnlyStaticCleanContent(t *testing.T) {
	t.Parallel()
	options, port := landingTestOptions(t)
	landing, err := NewLoginContinuationLanding(options)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(strings.ToLower(method), func(t *testing.T) {
			request := landingTestRequest()
			request.Method = method
			request.Header.Set("Cookie", "synthetic-private-cookie")
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			if err := landing.Present(response, request); err != nil {
				t.Fatal(err)
			}
			if port.calls != 0 || response.Code != http.StatusOK || response.statusWrites != 1 {
				t.Fatal("landing invoked authority or failed presentation")
			}
			if response.Header().Get("Set-Cookie") != "" || response.Header().Get("Location") != "" ||
				strings.Contains(response.Body.String(), "synthetic-private-cookie") {
				t.Fatal("landing reflected credential or redirected")
			}
			if method == http.MethodHead && response.Body.Len() != 0 {
				t.Fatal("HEAD released active content")
			}
			if method == http.MethodGet && !strings.Contains(response.Body.String(), `data-return-path="/console"`) {
				t.Fatal("missing fixed Core-owned return mapping")
			}
			if response.Header().Get("Content-Type") != "text/html; charset=utf-8" ||
				response.Header().Get("Content-Length") != strconv.Itoa(len(landing.body)) {
				t.Fatal("unsafe static response encoding")
			}
		})
	}
}

func TestLoginContinuationLandingRejectsUncleanHTTPBeforeDelivery(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*http.Request)
	}{
		{name: "cleartext proxy", change: func(r *http.Request) { r.TLS = nil; r.Header.Set("X-Forwarded-Proto", "https") }},
		{name: "unfinished tls", change: func(r *http.Request) { r.TLS.HandshakeComplete = false }},
		{name: "old tls", change: func(r *http.Request) { r.TLS.Version = tls.VersionTLS11 }},
		{name: "wrong host", change: func(r *http.Request) { r.Host = "other.example.test" }},
		{name: "post", change: func(r *http.Request) { r.Method = http.MethodPost }},
		{name: "preflight", change: func(r *http.Request) { r.Method = http.MethodOptions }},
		{name: "missing url", change: func(r *http.Request) { r.URL = nil }},
		{name: "query", change: func(r *http.Request) {
			r.URL.RawQuery = "code=synthetic-secret"
			r.RequestURI = r.URL.RequestURI()
		}},
		{name: "empty query", change: func(r *http.Request) { r.URL.ForceQuery = true; r.RequestURI = r.URL.RequestURI() }},
		{name: "fragment", change: func(r *http.Request) { r.URL.Fragment = "synthetic-secret" }},
		{name: "raw fragment", change: func(r *http.Request) { r.URL.RawFragment = "synthetic-secret" }},
		{name: "encoded path", change: func(r *http.Request) { r.URL.RawPath = "/auth/v1/login/%63ontinue" }},
		{name: "wrong target", change: func(r *http.Request) { r.RequestURI = "/other" }},
		{name: "foreign url", change: func(r *http.Request) { r.URL.Scheme = "https"; r.URL.Host = "console.example.test" }},
		{name: "userinfo", change: func(r *http.Request) { r.URL.User = url.User("synthetic-secret") }},
		{name: "opaque url", change: func(r *http.Request) { r.URL.Opaque = "synthetic-secret" }},
		{name: "body", change: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("{}")) }},
		{name: "length", change: func(r *http.Request) { r.ContentLength = 1 }},
		{name: "unknown length", change: func(r *http.Request) { r.ContentLength = -1 }},
		{name: "transfer", change: func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }},
		{name: "trailer", change: func(r *http.Request) { r.Trailer = http.Header{"X-Synthetic": {"secret"}} }},
		{name: "alternate host", change: func(r *http.Request) { r.Header.Set("Host", r.Host) }},
		{name: "credential header", change: func(r *http.Request) { r.Header.Set("Authorization", "synthetic-secret") }},
		{name: "length alias", change: func(r *http.Request) { r.Header.Set("Content-Length", "00") }},
		{name: "duplicate length", change: func(r *http.Request) { r.Header["Content-Length"] = []string{"0", "0"} }},
		{name: "sibling origin", change: func(r *http.Request) { r.Header.Set("Origin", "https://sibling.example.test") }},
		{name: "duplicate origin", change: func(r *http.Request) {
			r.Header["Origin"] = []string{"https://console.example.test", "https://console.example.test"}
		}},
		{name: "header alias", change: func(r *http.Request) {
			r.Header["origin"] = []string{"https://console.example.test"}
		}},
		{name: "oversized header", change: func(r *http.Request) { r.Header.Set("X-Synthetic", strings.Repeat("x", 16385)) }},
		{name: "header injection", change: func(r *http.Request) { r.Header.Set("X-Synthetic", "bad\r\nvalue") }},
		{name: "ajax", change: func(r *http.Request) { r.Header.Set("Sec-Fetch-Mode", "cors") }},
		{name: "iframe", change: func(r *http.Request) { r.Header.Set("Sec-Fetch-Dest", "iframe") }},
		{name: "orphan user", change: func(r *http.Request) { r.Header.Set("Sec-Fetch-User", "?1") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options, port := landingTestOptions(t)
			landing, err := NewLoginContinuationLanding(options)
			if err != nil {
				t.Fatal(err)
			}
			request := landingTestRequest()
			test.change(request)
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			if err := landing.Present(response, request); !errors.Is(err, ErrInvalidLoginLanding) {
				t.Fatal("unclean request accepted")
			}
			if port.calls != 0 || response.statusWrites != 0 || response.Body.Len() != 0 || len(response.Header()) != 0 {
				t.Fatal("rejected request caused effects/reflection")
			}
		})
	}
}

func TestLoginContinuationLandingRequiresPristineBoundedHeaders(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"Set-Cookie", "Location", "Content-Length", "Transfer-Encoding", "Authorization",
		"set-cookie", "Refresh", "Link", "Content-Encoding", "Report-To", "Reporting-Endpoints", "Nel", "Www-Authenticate",
		"combined budget"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options, _ := landingTestOptions(t)
			landing, err := NewLoginContinuationLanding(options)
			if err != nil {
				t.Fatal(err)
			}
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			if name == "combined budget" {
				response.Header().Set("X-Synthetic", strings.Repeat("x", 16000))
			} else {
				response.Header()[name] = []string{"synthetic-private-value"}
			}
			if err := landing.Present(response, landingTestRequest()); !errors.Is(err, ErrInvalidLoginLanding) {
				t.Fatal("unsafe response headers accepted")
			}
			if response.statusWrites != 0 || response.Body.Len() != 0 {
				t.Fatal("invalid headers released active content")
			}
		})
	}
}

func TestLoginContinuationLandingExactCSPAndNoDynamicSecrets(t *testing.T) {
	t.Parallel()
	options, port := landingTestOptions(t)
	landing, err := NewLoginContinuationLanding(options)
	if err != nil {
		t.Fatal(err)
	}
	request := landingTestRequest()
	request.Header.Set("Origin", "https://console.example.test")
	request.Header.Set("Content-Length", "0")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	request.Header.Set("Sec-Fetch-Mode", "navigate")
	request.Header.Set("Sec-Fetch-Dest", "document")
	request.Header.Set("Sec-Fetch-User", "?1")
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := landing.Present(response, request); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"script", "style"} {
		openingTag, closingTag := "<"+name+">", "</"+name+">"
		body := response.Body.String()
		start, end := strings.Index(body, openingTag)+len(openingTag), strings.Index(body, closingTag)
		digest := sha256.Sum256([]byte(body[start:end]))
		expected := name + "-src 'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
		if !strings.Contains(response.Header().Get("Content-Security-Policy"), expected) {
			t.Fatal("CSP does not match exact delivered inline bytes")
		}
	}
	for _, forbidden := range []string{"unsafe-inline", "unsafe-eval", "report-uri", "report-to"} {
		if strings.Contains(response.Header().Get("Content-Security-Policy"), forbidden) {
			t.Fatal("CSP broadened")
		}
	}
	if !strings.Contains(response.Header().Get("Content-Security-Policy"), "connect-src 'self'") || port.calls != 0 {
		t.Fatal("static page changed trust scope")
	}
	for _, forbidden := range []string{"document.cookie", "localStorage", "sessionStorage", "innerHTML",
		"location.search", "location.hash", "https://", "<form"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatal("unsafe browser surface", forbidden)
		}
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" ||
		response.Header().Get("X-Frame-Options") != "DENY" ||
		!strings.Contains(response.Body.String(), `aria-live="polite"`) {
		t.Fatal("unsafe presentation/accessibility policy")
	}
	if fmt.Sprint(landing) != "[REDACTED]" {
		t.Fatal("configured topology entered formatting")
	}
}

type landingDeliveryRecorder struct {
	*continuationStatusRecorder
	read, write time.Time
	failRead    bool
	failWrite   bool
	onDeadline  func()
	onWrite     func([]byte) (int, error)
}

func (recorder *landingDeliveryRecorder) SetReadDeadline(at time.Time) error {
	recorder.read = at
	if recorder.onDeadline != nil {
		recorder.onDeadline()
	}
	if recorder.failRead {
		return errors.New("synthetic-private-transport")
	}
	return nil
}

func (recorder *landingDeliveryRecorder) SetWriteDeadline(at time.Time) error {
	recorder.write = at
	if recorder.failWrite {
		return errors.New("synthetic-private-transport")
	}
	return nil
}

func (recorder *landingDeliveryRecorder) Write(body []byte) (int, error) {
	if recorder.onWrite != nil {
		return recorder.onWrite(body)
	}
	return recorder.continuationStatusRecorder.Write(body)
}

func TestLoginContinuationLandingDeadlinesCancellationAndDelivery(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"parent deadline", "read unavailable", "write unavailable",
		"cancel before response", "partial failure", "short write"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			options, _ := landingTestOptions(t)
			landing, err := NewLoginContinuationLanding(options)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 750*time.Millisecond)
			defer cancel()
			request := landingTestRequest().WithContext(ctx)
			response := &landingDeliveryRecorder{
				continuationStatusRecorder: &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()},
			}
			var expected error
			switch mode {
			case "read unavailable":
				response.failRead, expected = true, ErrLoginLandingUnavailable
			case "write unavailable":
				response.failWrite, expected = true, ErrLoginLandingUnavailable
			case "cancel before response":
				response.onDeadline, expected = cancel, context.Canceled
			case "partial failure":
				response.onWrite = func([]byte) (int, error) { return 1, errors.New("synthetic-private-transport") }
				expected = ErrLoginLandingDelivery
			case "short write":
				response.onWrite = func(body []byte) (int, error) { return len(body) - 1, nil }
				expected = ErrLoginLandingDelivery
			}
			err = landing.Present(response, request)
			if !errors.Is(err, expected) {
				t.Fatal("wrong closed result", err)
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-private-transport") {
				t.Fatal("dependency details released")
			}
			if mode == "parent deadline" {
				deadline, _ := ctx.Deadline()
				if response.read != deadline || response.write != deadline {
					t.Fatal("caller deadline extended/replaced")
				}
			}
			if expected != nil && !errors.Is(expected, ErrLoginLandingDelivery) && response.statusWrites != 0 {
				t.Fatal("prerelease failure wrote response")
			}
			if errors.Is(expected, ErrLoginLandingDelivery) && response.statusWrites != 1 {
				t.Fatal("partial delivery rewritten")
			}
		})
	}
}

func TestLoginContinuationLandingRejectsAbsentOwnerAndDeadlineSupport(t *testing.T) {
	t.Parallel()
	options, _ := landingTestOptions(t)
	landing, err := NewLoginContinuationLanding(options)
	if err != nil {
		t.Fatal(err)
	}
	var absentOwner *LoginContinuationLanding
	var absentWriter *landingDeliveryRecorder
	for _, owner := range []*LoginContinuationLanding{absentOwner, {}} {
		if err := owner.Present(newLoginHTTPRecorder(), landingTestRequest()); !errors.Is(err, ErrLoginLandingUnavailable) {
			t.Fatal("absent owner accepted")
		}
	}
	if err := landing.Present(absentWriter, landingTestRequest()); !errors.Is(err, ErrLoginLandingUnavailable) {
		t.Fatal("typed nil writer accepted")
	}
	if err := landing.Present(newLoginHTTPRecorder(), nil); !errors.Is(err, ErrLoginLandingUnavailable) {
		t.Fatal("nil request accepted")
	}
	response := httptest.NewRecorder()
	presentErr := landing.Present(response, landingTestRequest())
	if !errors.Is(presentErr, ErrLoginLandingUnavailable) || response.Body.Len() != 0 {
		t.Fatal("missing transport deadlines allowed delivery")
	}
}

func TestLoginContinuationLandingCapacityOwnedThroughDelivery(t *testing.T) {
	// Process-wide goleak must run serially and outside the deterministic bubble.
	defer goleak.VerifyNone(t)
	synctest.Test(t, func(t *testing.T) {
		options, port := landingTestOptions(t)
		landing, err := NewLoginContinuationLanding(options)
		if err != nil {
			t.Fatal(err)
		}
		entered := make(chan struct{})
		joined := make(chan error, 1)
		response := &landingDeliveryRecorder{
			continuationStatusRecorder: &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()},
		}
		response.onWrite = func([]byte) (int, error) {
			close(entered)
			time.Sleep(time.Until(response.write))
			return 0, errors.New("synthetic-write-deadline")
		}
		go func() { joined <- landing.Present(response, landingTestRequest()) }()
		<-entered
		second := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
		saturatedErr := landing.Present(second, landingTestRequest())
		if !errors.Is(saturatedErr, ErrLoginLandingSaturated) || second.statusWrites != 0 {
			t.Fatal("delivery capacity queued/released early")
		}
		if err := <-joined; !errors.Is(err, ErrLoginLandingDelivery) {
			t.Fatal("owned deadline did not join delivery")
		}
		if port.calls != 0 {
			t.Fatal("presentation reached authority")
		}
		if err := landing.Present(second, landingTestRequest()); err != nil {
			t.Fatal("joined capacity not released")
		}
	})
}

func TestLoginContinuationLandingRealVerifiedHTTPS(t *testing.T) {
	t.Parallel()
	options, port := landingTestOptions(t)
	landing, err := NewLoginContinuationLanding(options)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := landing.Present(w, r); err != nil {
			t.Error("real TLS static presentation failed", err)
		}
	}))
	server.Config.ReadTimeout = 2 * time.Second
	server.Config.WriteTimeout = 2 * time.Second
	server.Config.IdleTimeout = 2 * time.Second
	server.StartTLS()
	defer server.Close()
	client := server.Client() // Synthetic CA trust, never insecure certificate fallback.
	client.Timeout = 2 * time.Second
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		request, err := http.NewRequestWithContext(
			t.Context(),
			method,
			server.URL+LoginCallbackContinuePath,
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "console.example.test"
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumLoginLandingBytes+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || port.calls != 0 {
			t.Fatal("real TLS presentation failed")
		}
		if method == http.MethodHead && len(body) != 0 || method == http.MethodGet && string(body) != landing.body {
			t.Fatal("real TLS static bytes changed")
		}
	}
}

func FuzzLoginContinuationLandingHTTP(f *testing.F) {
	f.Add("", "", "", "", http.MethodGet)
	f.Add("code=synthetic", "", "", "", http.MethodHead)
	f.Fuzz(func(t *testing.T, query, rawPath, fragment, header, method string) {
		options, port := landingTestOptions(t)
		landing, err := NewLoginContinuationLanding(options)
		if err != nil {
			t.Fatal(err)
		}
		request := landingTestRequest()
		request.URL.RawQuery, request.URL.RawPath, request.URL.Fragment = query, rawPath, fragment
		request.RequestURI, request.Method = request.URL.RequestURI(), method
		request.Header.Set("X-Synthetic", header)
		response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
		err = landing.Present(response, request)
		unclean := query != "" || rawPath != "" || fragment != ""
		wrongMethod := method != http.MethodGet && method != http.MethodHead
		if (unclean || wrongMethod) && err == nil {
			t.Fatal("unclean target released active content")
		}
		if err != nil && (response.statusWrites != 0 || response.Body.Len() != 0) {
			t.Fatal("rejection released response")
		}
		if port.calls != 0 || response.Header().Get("Set-Cookie") != "" || response.Header().Get("Location") != "" {
			t.Fatal("presentation created authority/redirect")
		}
	})
}
