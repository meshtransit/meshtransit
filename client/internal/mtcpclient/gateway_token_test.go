package mtcpclient

import (
	"errors"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// countingConn counts the records a session writes; err fails them.
type countingConn struct {
	writes int
	err    error
}

func (conn *countingConn) write(sharedmtcp.RecordType, []byte) error {
	if conn.err != nil {
		return conn.err
	}
	conn.writes++
	return nil
}

func (*countingConn) read(time.Time) (sharedmtcp.RecordType, []byte, error) {
	return 0, nil, errors.New("not read")
}
func (*countingConn) close() error { return nil }

// tokenSession is a session past its handshake that presented "first".
func tokenSession(t *testing.T, conn recordConn, sent time.Time) *session {
	t.Helper()
	control, err := key.NewControlPrivate(nil)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := key.NewMachinePrivate(nil)
	if err != nil {
		t.Fatal(err)
	}
	client, init, err := sharedmtcp.StartClient(sharedmtcp.ClientConfig{Machine: machine, Control: control.Public(),
		Hello: &mtcpv1.ClientHello{ProtocolVersion: 1, TimestampMs: sent.UnixMilli()}})
	if err != nil {
		t.Fatal(err)
	}
	server, err := sharedmtcp.ReadInit(control, init, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, response, err := server.Respond(&mtcpv1.ServerHello{ProtocolVersion: 1, SessionId: make([]byte, 16)})
	if err != nil {
		t.Fatal(err)
	}
	noise, _, err := client.Finish(response)
	if err != nil {
		t.Fatal(err)
	}
	return &session{conn: conn, noise: noise, tokens: true, podToken: "first", podTokenSent: sent}
}

// The refresh cadence Core's limit (2 at once, then 1 per 15 s) relies on:
// a changed token goes at once, an unchanged one every 2 minutes, none
// never (K1c-T H1, review v2 N2).
func TestRefreshPodTokenCadence(t *testing.T) {
	t.Parallel()
	start := time.Unix(1_800_000_000, 0)
	for _, test := range []struct {
		name   string
		token  controlplane.PodToken
		after  time.Duration
		tokens bool
		sends  int
	}{
		{name: "unchanged within 2 minutes", token: "first", after: time.Minute, tokens: true},
		{name: "unchanged at 2 minutes", token: "first", after: podTokenResend, tokens: true, sends: 1},
		{name: "changed", token: "second", after: podTokenReread, tokens: true, sends: 1},
		{name: "none to send", token: "", after: time.Hour, tokens: true},
		{name: "no gateway.token1", token: "second", after: time.Hour},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			conn := &countingConn{}
			s := tokenSession(t, conn, start)
			s.tokens = test.tokens
			token := test.token
			run := &sessionRun{s: s, stream: &netmapStream{client: &Client{
				podToken: func() controlplane.PodToken { return token },
			}}}
			if err := run.refreshPodToken(start.Add(test.after)); err != nil {
				t.Fatal(err)
			}
			if conn.writes != test.sends {
				t.Fatalf("%d records sent, want %d", conn.writes, test.sends)
			}
			if test.sends == 1 && (s.podToken != test.token || !s.podTokenSent.Equal(start.Add(test.after))) {
				t.Fatalf("after a send the session holds %v at %v", s.podToken, s.podTokenSent)
			}
			// Sent: the same token is not sent again on the next tick.
			if test.sends == 1 {
				if err := run.refreshPodToken(start.Add(test.after + podTokenReread)); err != nil ||
					conn.writes != 1 {
					t.Fatalf("the next tick sent again: %d, %v", conn.writes, err)
				}
			}
		})
	}
	// A send that fails ends the session.
	conn := &countingConn{err: errors.New("broken pipe")}
	run := &sessionRun{s: tokenSession(t, conn, start), stream: &netmapStream{client: &Client{
		podToken: func() controlplane.PodToken { return "second" },
	}}}
	if err := run.refreshPodToken(start.Add(podTokenReread)); err == nil {
		t.Fatal("a failed send was not reported")
	}
}
