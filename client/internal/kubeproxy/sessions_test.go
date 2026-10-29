package kubeproxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/rbaccheck"
)

// openStream starts a watch the fake API server streams, and returns its
// body once the first bytes came.
func (f *fixture) openStream(path string) io.ReadCloser {
	f.t.Helper()
	request, err := http.NewRequestWithContext(f.t.Context(), http.MethodGet, "https://"+clusterName+path, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	response, err := f.client.Do(request)
	if err != nil {
		f.t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		f.t.Fatalf("stream: %d", response.StatusCode)
	}
	if _, err := response.Body.Read(make([]byte, 512)); err != nil {
		f.t.Fatal(err)
	}
	f.forwarded()
	return response.Body
}

// ends waits for a stream to end, within limit.
func ends(t *testing.T, body io.Reader, limit time.Duration) time.Duration {
	t.Helper()
	started := time.Now()
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		_, _ = io.Copy(io.Discard, body)
	}()
	select {
	case <-ended:
		return time.Since(started)
	case <-time.After(limit):
		t.Fatalf("still open after %s", limit)
		return 0
	}
}

func (f *fixture) waitStats(what string, ok func(SessionStats) bool) SessionStats {
	f.t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		stats := f.server.Sessions()
		if ok(stats) {
			return stats
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("%s: %+v", what, stats)
		}
	}
}

// A watch whose group the Device no longer holds is cut by the sweep
// within its interval (K1b design §8, K1-I4).
func TestSessionsCutAWatchWhenTheGrantEnds(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	body := f.openStream("/api/v1/namespaces/a/pods?watch=true")
	defer body.Close()
	f.waitStats("no open watch", func(stats SessionStats) bool { return stats.Open[kindWatch] == 1 })

	peer := *f.peer.Load()
	peer.Access = &networkmap.KubernetesAccess{OwnerRef: peer.Access.OwnerRef,
		OwnerChangedAt: peer.Access.OwnerChangedAt,
		Grants:         []networkmap.KubernetesGrant{{Group: "edit", ValidUntil: time.Now().Add(time.Hour)}}}
	f.peer.Store(&peer)
	if took := ends(t, body, 3*time.Second); took > 2*sweepInterval {
		t.Fatalf("cut after %s", took)
	}
	stats := f.waitStats("not counted", func(stats SessionStats) bool {
		return stats.Open[kindWatch] == 0 && stats.Cut[cutRevoked] == 1
	})
	if stats.CutSeconds.Cumulative[len(stats.CutSeconds.Cumulative)-1] != 1 {
		t.Fatalf("cut histogram %+v", stats.CutSeconds)
	}
	// The request is reported answered, not lost.
	f.records.mu.Lock()
	defer f.records.mu.Unlock()
	if len(f.records.intents) != 0 {
		t.Fatalf("a watch on pods was recorded: %+v", f.records.intents)
	}
}

// Wake sweeps at once: a group turned off cuts its sessions without
// waiting for the tick.
func TestSessionsWakeCutsAGroupTurnedOff(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	body := f.openStream("/api/v1/namespaces/a/pods?watch=true")
	defer body.Close()
	f.verdicts.Store("view", rbaccheck.Verdict{Reason: "may list secrets in the cluster"})
	f.wake <- struct{}{}
	ends(t, body, 3*time.Second)
	f.waitStats("not cut as group off", func(stats SessionStats) bool { return stats.Cut[cutGroupOff] == 1 })
}

// An upgraded connection (exec) is closed when the Device's address moves
// to another key.
func TestSessionsCloseAnUpgrade(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	conn, err := tls.Dial("tcp", f.address, &tls.Config{RootCAs: f.client.Transport.(*http.Transport).TLSClientConfig.RootCAs,
		ServerName: clusterName, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "POST /mt/g/edit/api/v1/namespaces/default/pods/web-0/exec?command=sh HTTP/1.1\r\nHost: "+
		clusterName+"\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\nContent-Length: 0\r\n\r\n")
	reader := bufio.NewReader(conn)
	if status, _ := reader.ReadString('\n'); !strings.Contains(status, "101") {
		t.Fatalf("status line %q", status)
	}
	f.forwarded()
	f.waitStats("no open upgrade", func(stats SessionStats) bool { return stats.Open[kindUpgrade] == 1 })
	peer := *f.peer.Load()
	peer.Key = [32]byte{9}
	f.peer.Store(&peer)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatalf("the upgrade was not closed: %v", err)
	}
	f.waitStats("not cut for identity", func(stats SessionStats) bool { return stats.Cut[cutIdentity] == 1 })
}

// A privileged group's use makes an Event in the cluster first; when it
// cannot, the request is refused and reported not forwarded (K1b §4).
func TestProxyPrivilegedSessionEvent(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.do(http.MethodGet, "/mt/g/sre/api/v1/pods", nil)
	f.forwarded()
	f.events.mu.Lock()
	uses := f.events.uses
	f.events.mu.Unlock()
	if len(uses) != 1 || uses[0].Group != "sre" || uses[0].Owner != "person-1" || uses[0].Device != "device-a" ||
		uses[0].AuditID == "" || uses[0].Source != "127.0.0.1" {
		t.Fatalf("uses %+v", uses)
	}
	f.events.fail.Store(true)
	response, body := f.do(http.MethodGet, "/mt/g/sre/api/v1/pods", nil)
	if response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "privileged session") {
		t.Fatalf("%d %s", response.StatusCode, body)
	}
	f.nothingForwarded()
	f.records.mu.Lock()
	defer f.records.mu.Unlock()
	if last := f.records.finished[len(f.records.finished)-1]; last != 0 {
		t.Fatalf("an unannounced privileged request reported %d", last)
	}
}

// A proxy with a privileged group needs the cluster's Events.
func TestNewNeedsEventsForAPrivilegedGroup(t *testing.T) {
	t.Parallel()
	options := Options{
		Cluster: "c", Namespace: "n", Backend: "https://api:6443", StaleAfter: 5 * time.Minute,
		Groups:      []Group{{Name: "view", Default: true}, {Name: "sre", Privileged: true, AllowedPrincipals: []string{"p"}}},
		Peer:        func(netip.Addr) (Peer, bool) { return Peer{}, false },
		Certificate: func() (*tls.Certificate, bool) { return nil, false },
		MapFreshAt:  time.Now, CoreNow: time.Now,
		Verdict: func(string) rbaccheck.Verdict { return rbaccheck.Verdict{} },
		Records: &fakeRecords{}, Tokens: &fakeTokens{}, Logger: slog.New(slog.DiscardHandler),
	}
	if err := options.validate(); err == nil || !strings.Contains(err.Error(), "Events") {
		t.Fatalf("without Events: %v", err)
	}
	options.Events = &fakeEvents{}
	if err := options.validate(); err != nil {
		t.Fatal(err)
	}
}

// A request cut before the API server answered gets the reason, never an
// empty 200 (review b6a H1).
func TestSessionsAnswerARequestCutBeforeItsAnswer(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	answered := make(chan *http.Response, 1)
	go func() {
		response, err := f.client.Get("https://" + clusterName + "/api/v1/namespaces/a/configmaps/slow")
		if err != nil {
			answered <- nil
			return
		}
		answered <- response
	}()
	f.forwarded()
	peer := *f.peer.Load()
	peer.Access = &networkmap.KubernetesAccess{OwnerRef: peer.Access.OwnerRef}
	f.peer.Store(&peer)
	select {
	case response := <-answered:
		if response == nil {
			t.Fatal("no answer")
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "ended") {
			t.Fatalf("%d %s", response.StatusCode, body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the cut request was never answered")
	}
}

// A session kept Impersonate-* headers is cut once its group may no longer
// impersonate (review b6a M1).
func TestSessionsCutImpersonationWithdrawn(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"https://"+clusterName+"/mt/g/sre/api/v1/namespaces/a/pods?watch=true", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Impersonate-User", "alice@example.com")
	response, err := f.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("watch %d", response.StatusCode)
	}
	if got := f.forwarded(); got.Header.Get("Impersonate-User") != "alice@example.com" {
		t.Fatalf("impersonation dropped: %+v", got.Header)
	}
	f.verdicts.Store("sre", rbaccheck.Verdict{Enabled: true})
	f.wake <- struct{}{}
	ends(t, response.Body, 3*time.Second)
	f.waitStats("not cut", func(stats SessionStats) bool { return stats.Cut[cutImpersonation] == 1 })
}
