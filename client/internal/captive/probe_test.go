package captive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"
)

// relayAt serves handler as a relay's probe and returns a prober aimed at it.
func relayAt(t *testing.T, handler http.HandlerFunc) (*Prober, netip.Addr) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	address := netip.MustParseAddrPort(server.Listener.Addr().String())
	prober := NewProber(nil)
	prober.port = address.Port()
	return prober, address.Addr()
}

func TestProbeTellsTheRelayFromAPortal(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
		want    Result
	}{
		{"the relay", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(nonceHeader, r.URL.Query().Get("n"))
			w.WriteHeader(http.StatusNoContent)
		}, Result{Verdict: VerdictNone}},
		{"a fake 204", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, Result{Verdict: VerdictPortal}},
		{"a redirect to a sign-in page", func(w http.ResponseWriter, _ *http.Request) {
			http.Redirect(w, &http.Request{}, "http://10.0.0.1:8880/guest/s/default/", http.StatusFound)
		}, Result{Verdict: VerdictPortal, URL: "http://10.0.0.1:8880/guest/s/default/"}},
		{"a page in place", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("<html>Welcome to the hotel</html>"))
		}, Result{Verdict: VerdictPortal}},
		{"network authentication required", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNetworkAuthenticationRequired)
		}, Result{Verdict: VerdictPortal}},
		{"a refusal", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}, Result{Verdict: VerdictSuspected}},
		{"the relay's rate limit", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}, Result{Verdict: VerdictUnknown}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			prober, address := relayAt(t, test.handler)
			if got := prober.Probe(t.Context(), address); got != test.want {
				t.Fatalf("Probe() = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestProbeOfNothingIsUnknown(t *testing.T) {
	t.Parallel()
	prober := NewProber(nil)
	prober.port = 9 // discard: nothing listens
	if got := prober.Probe(t.Context(), netip.MustParseAddr("127.0.0.1")); got.Verdict != VerdictUnknown {
		t.Fatalf("Probe() = %+v", got)
	}
}

func TestSignInURLAndPortalEndpoint(t *testing.T) {
	t.Parallel()
	target := url.URL{Scheme: "http", Host: "198.51.100.1:80", Path: probePath}
	for location, want := range map[string]string{
		"/login":                      "http://198.51.100.1:80/login",
		"https://user@wifi.example/x": "https://wifi.example/x", // user info is dropped
		"javascript:alert(1)":         "",
		"":                            "",
	} {
		if got := signInURL(location, target); got != want {
			t.Errorf("signInURL(%q) = %q, want %q", location, got, want)
		}
	}
	if host, port, ok := PortalEndpoint("http://10.0.0.1:8880/guest"); !ok || host != "10.0.0.1" || port != 8880 {
		t.Fatalf("PortalEndpoint() = %q %d %t", host, port, ok)
	}
	for _, plain := range []string{"http://10.0.0.1/guest", "https://wifi.example:443/", "not a url"} {
		if _, _, ok := PortalEndpoint(plain); ok {
			t.Errorf("PortalEndpoint(%q) wanted its own port", plain)
		}
	}
}

func TestFetchAPIReadsTheNetworksVerdict(t *testing.T) {
	t.Parallel()
	captive := true
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", apiMediaType)
		_, _ = w.Write([]byte(`{"captive":` + strconv.FormatBool(captive) +
			`,"user-portal-url":"https://portal.example/login","seconds-remaining":300}`))
	}))
	t.Cleanup(server.Close)
	prober := NewProber(nil)
	prober.client.Transport = server.Client().Transport
	got, err := prober.FetchAPI(t.Context(), server.URL+"/api")
	if err != nil || got != (Result{Verdict: VerdictPortal, URL: "https://portal.example/login"}) {
		t.Fatalf("FetchAPI() = %+v, %v", got, err)
	}
	captive = false
	if got, err := prober.FetchAPI(t.Context(), server.URL+"/api"); err != nil || got.Verdict != VerdictNone {
		t.Fatalf("FetchAPI() after signing in = %+v, %v", got, err)
	}
	if _, err := prober.FetchAPI(t.Context(), "http://portal.example/api"); err == nil {
		t.Fatal("a plain HTTP API was asked")
	}
}

// fakeChecker answers probes from a map and the API from a result.
type fakeChecker struct {
	mu     sync.Mutex
	probes map[netip.Addr]Result
	api    *Result
	asked  []netip.Addr
}

func (f *fakeChecker) Probe(_ context.Context, address netip.Addr) Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, address)
	if result, ok := f.probes[address]; ok {
		return result
	}
	return Result{Verdict: VerdictUnknown}
}

func (f *fakeChecker) FetchAPI(context.Context, string) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.api == nil {
		return Result{}, context.DeadlineExceeded
	}
	return *f.api, nil
}

type detectorHarness struct {
	now     time.Time
	inputs  Inputs
	checker *fakeChecker
	changes []State
	resolve []netip.Addr
	uris    []string
	*Detector
}

func newDetectorHarness() *detectorHarness {
	relay := netip.MustParseAddr("198.51.100.1")
	h := &detectorHarness{
		now:     time.Date(2026, time.October, 21, 22, 0, 0, 0, time.UTC),
		inputs:  Inputs{ExitWanted: true, Relays: []netip.Addr{relay}, RelayName: "relay.example"},
		checker: &fakeChecker{probes: map[netip.Addr]Result{}},
		resolve: []netip.Addr{relay},
	}
	h.Detector = NewDetector(Config{
		Inputs: func() Inputs { return h.inputs }, Checker: h.checker,
		APIURIs: func() []string { return h.uris },
		Resolve: func(context.Context, string) ([]netip.Addr, error) { return h.resolve, nil },
		Clock:   func() time.Time { return h.now }, OnChange: func(state State) { h.changes = append(h.changes, state) },
	})
	return h
}

func (h *detectorHarness) advance(by time.Duration) {
	for elapsed := time.Duration(0); elapsed < by; elapsed += time.Second {
		h.now = h.now.Add(time.Second)
		h.Step(context.Background())
	}
}

// Nothing is checked while the tunnel works, or before the control session
// was down for 10 s; a portal is then found and followed every 15 s, and
// the verdict goes once the session is back.
func TestDetectorFindsAPortalOnlyWhenTheTunnelIsDown(t *testing.T) {
	t.Parallel()
	h := newDetectorHarness()
	relay := h.inputs.Relays[0]
	h.checker.probes[relay] = Result{Verdict: VerdictPortal, URL: "http://10.0.0.1/login"}
	h.inputs.ControlUp = true
	h.advance(30 * time.Second)
	if len(h.checker.asked) != 0 {
		t.Fatal("probed while the control session was up")
	}
	h.inputs.ControlUp = false
	h.advance(9 * time.Second)
	if len(h.checker.asked) != 0 {
		t.Fatal("probed before the session was down for 10 s")
	}
	h.advance(2 * time.Second)
	if state := h.State(); state.Verdict != VerdictPortal || state.URL != "http://10.0.0.1/login" || len(h.changes) != 1 {
		t.Fatalf("state = %+v, changes %v", state, h.changes)
	}
	asked := len(h.checker.asked)
	h.advance(16 * time.Second)
	if len(h.checker.asked) != asked+1 {
		t.Fatalf("%d probes in 16 s while held, want 1", len(h.checker.asked)-asked)
	}
	h.inputs.ControlUp = true
	h.advance(time.Second)
	if state := h.State(); state.Verdict != VerdictNone || len(h.changes) != 2 {
		t.Fatalf("after the session came back: %+v", state)
	}
}

// A network that answers nothing is not called a portal, and is checked less
// and less often; a network change checks again at once.
func TestDetectorBacksOffOnSilenceAndChecksAfterANetworkChange(t *testing.T) {
	t.Parallel()
	h := newDetectorHarness()
	h.advance(3 * time.Minute)
	if state := h.State(); state.Verdict != VerdictNone {
		t.Fatalf("silence became %+v", state)
	}
	if asked := len(h.checker.asked); asked < 3 || asked > 6 {
		t.Fatalf("%d probes in 3 minutes of silence", asked)
	}
	asked := len(h.checker.asked)
	h.NetworkChanged()
	h.advance(time.Second)
	if len(h.checker.asked) != asked+1 {
		t.Fatal("a network change did not check at once")
	}
}

// The network's API is trusted first; a network that only takes over DNS
// is suspected.
func TestDetectorTrustsTheAPIAndSuspectsAForeignDNSAnswer(t *testing.T) {
	t.Parallel()
	h := newDetectorHarness()
	h.uris = []string{"https://portal.example/api"}
	h.checker.api = &Result{Verdict: VerdictPortal, URL: "https://portal.example/login"}
	h.advance(11 * time.Second)
	if state := h.State(); state.Verdict != VerdictPortal || state.URL != "https://portal.example/login" ||
		len(h.checker.asked) != 0 {
		t.Fatalf("API verdict %+v, probes %v", state, h.checker.asked)
	}

	h = newDetectorHarness()
	h.resolve = []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	h.advance(11 * time.Second)
	if state := h.State(); state.Verdict != VerdictSuspected {
		t.Fatalf("a foreign DNS answer gave %+v", state)
	}
}

// With no relay known (a cold start behind the portal), the network's
// answer for the relay's name is probed.
func TestDetectorProbesTheResolvedRelayOnAColdStart(t *testing.T) {
	t.Parallel()
	h := newDetectorHarness()
	portal := netip.MustParseAddr("10.0.0.1")
	h.inputs.Relays, h.resolve = nil, []netip.Addr{portal}
	h.checker.probes[portal] = Result{Verdict: VerdictPortal}
	h.advance(11 * time.Second)
	if state := h.State(); state.Verdict != VerdictPortal || len(h.checker.asked) != 1 || h.checker.asked[0] != portal {
		t.Fatalf("cold start: %+v, asked %v", state, h.checker.asked)
	}
}
