//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/config"
)

// Fixture TLS termination is deliberately outside the production pool/factory.
// Only owned PostgreSQL backend frames are inspected; no SQL or proof is retained.
type privateFactoryACKRelay struct {
	listener *net.TCPListener
	server   *tls.Config
	upstream *tls.Config
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	stopOnce sync.Once
	owners   sync.WaitGroup
	failed   atomic.Bool

	mu      sync.Mutex
	closing bool
	conns   map[net.Conn]struct{}
	skip    int
	armed   bool
	dropped int
}

var privateFactorySSLRequest = [8]byte{0, 0, 0, 8, 4, 210, 22, 47}

func newPrivateFactoryACKRelay(t *testing.T) *privateFactoryACKRelay {
	t.Helper()
	profile, err := config.Load(privateFactoryConfigLookup("api"))
	if err != nil || profile.Storage == nil ||
		profile.Storage.PostgreSQL.Address != "meshtransit-postgres:5432" ||
		profile.Storage.PostgreSQL.Database != "meshtransit_private_factory_ack" {
		t.Fatal("refuse unowned wire acknowledgement relay")
	}
	certificate, err := tls.LoadX509KeyPair(
		os.Getenv("MESHTRANSIT_TEST_OIDC_TLS_CERTIFICATE_FILE"),
		os.Getenv("MESHTRANSIT_TEST_OIDC_TLS_PRIVATE_KEY_FILE"),
	)
	if err != nil {
		t.Fatal("load owned relay fixture certificate")
	}
	ca, err := profile.Storage.PostgreSQL.CAFile.Read()
	if err != nil {
		t.Fatal("read owned relay fixture trust")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("parse owned relay fixture trust")
	}
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal("listen owned loopback relay")
	}
	if listener.SetDeadline(time.Now().Add(2*time.Minute)) != nil {
		_ = listener.Close()
		t.Fatal("bound relay accept lifetime")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	relay := &privateFactoryACKRelay{
		listener: listener, ctx: ctx, cancel: cancel, done: make(chan struct{}),
		conns:  make(map[net.Conn]struct{}),
		server: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}},
		upstream: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "meshtransit-postgres",
		},
	}
	t.Cleanup(func() { relay.close(t) })
	go relay.accept()
	return relay
}

func (relay *privateFactoryACKRelay) accept() {
	// The accept owner stops Add before Wait. Closing sockets joins both copies.
	defer close(relay.done)
	defer relay.owners.Wait()
	defer relay.stop()
	slots := make(chan struct{}, 2)
	for {
		client, err := relay.listener.AcceptTCP()
		if err != nil {
			relay.mu.Lock()
			closing := relay.closing
			relay.mu.Unlock()
			if !closing {
				relay.failed.Store(true)
			}
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = client.Close()
			relay.failed.Store(true)
			continue
		}
		if !relay.track(client) {
			_ = client.Close()
			<-slots
			return
		}
		relay.owners.Add(1)
		go func() {
			defer relay.owners.Done()
			defer func() { <-slots }()
			defer relay.release(client)
			relay.serve(client)
		}()
	}
}

func (relay *privateFactoryACKRelay) track(connection net.Conn) bool {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.closing {
		return false
	}
	relay.conns[connection] = struct{}{}
	return true
}

func (relay *privateFactoryACKRelay) release(connection net.Conn) {
	_ = connection.Close()
	relay.mu.Lock()
	delete(relay.conns, connection)
	relay.mu.Unlock()
}

func (relay *privateFactoryACKRelay) serve(raw net.Conn) {
	if raw.SetDeadline(time.Now().Add(5*time.Second)) != nil {
		relay.failed.Store(true)
		return
	}
	var request [8]byte
	if _, err := io.ReadFull(raw, request[:]); err != nil {
		return
	}
	if request != privateFactorySSLRequest {
		relay.failed.Store(true)
		return
	}
	if _, err := raw.Write([]byte{'S'}); err != nil {
		return
	}
	client := tls.Server(raw, relay.server)
	ctx, cancel := context.WithTimeout(relay.ctx, 5*time.Second)
	defer cancel()
	if client.HandshakeContext(ctx) != nil {
		relay.failed.Store(true)
		return
	}
	if raw.SetDeadline(time.Now().Add(2*time.Minute)) != nil {
		relay.failed.Store(true)
		return
	}
	upstreamRaw, err := (&net.Dialer{}).DialContext(ctx, "tcp", "meshtransit-postgres:5432")
	if err != nil {
		relay.failed.Store(true)
		return
	}
	if !relay.track(upstreamRaw) {
		_ = upstreamRaw.Close()
		return
	}
	defer relay.release(upstreamRaw)
	if upstreamRaw.SetDeadline(time.Now().Add(5*time.Second)) != nil {
		relay.failed.Store(true)
		return
	}
	var answer [1]byte
	if _, err := upstreamRaw.Write(privateFactorySSLRequest[:]); err != nil {
		relay.failed.Store(true)
		return
	}
	if _, err := io.ReadFull(upstreamRaw, answer[:]); err != nil || answer[0] != 'S' {
		relay.failed.Store(true)
		return
	}
	upstream := tls.Client(upstreamRaw, relay.upstream)
	if upstream.HandshakeContext(ctx) != nil {
		relay.failed.Store(true)
		return
	}
	if upstreamRaw.SetDeadline(time.Now().Add(2*time.Minute)) != nil {
		relay.failed.Store(true)
		return
	}
	frontendDone := make(chan struct{})
	go func() {
		defer close(frontendDone)
		buffer := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(upstream, struct{ io.Reader }{client}, buffer)
		clear(buffer)
		// Client termination must wake a blocked backend frame read.
		_ = upstreamRaw.Close()
	}()
	err = relay.forwardBackend(upstream, client)
	_ = raw.Close()
	_ = upstreamRaw.Close()
	<-frontendDone
	if errors.Is(err, errPrivateFactoryACKFrame) {
		relay.failed.Store(true)
	}
}

var errPrivateFactoryACKFrame = errors.New("invalid owned acknowledgement frame")

func (relay *privateFactoryACKRelay) forwardBackend(source io.Reader, target io.Writer) error {
	var header [5]byte
	for {
		if _, err := io.ReadFull(source, header[:]); err != nil {
			return err
		}
		length := binary.BigEndian.Uint32(header[1:])
		if length < 4 || length > 1024*1024 {
			return errPrivateFactoryACKFrame
		}
		body := make([]byte, int(length)-4)
		if _, err := io.ReadFull(source, body); err != nil {
			clear(body)
			return err
		}
		commit := header[0] == 'C' && bytes.Equal(body, []byte("COMMIT\x00"))
		if commit && relay.dropCommit() {
			clear(body)
			return nil
		}
		headerBytes, headerErr := target.Write(header[:])
		if headerErr != nil || headerBytes != len(header) {
			clear(body)
			return errors.Join(io.ErrShortWrite, headerErr)
		}
		bodyBytes, bodyErr := target.Write(body)
		clear(body)
		if bodyErr != nil || bodyBytes != len(body) {
			return errors.Join(io.ErrShortWrite, bodyErr)
		}
	}
}

func (relay *privateFactoryACKRelay) dropCommit() bool {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if !relay.armed {
		return false
	}
	if relay.skip > 0 {
		relay.skip--
		return false
	}
	relay.armed = false
	relay.dropped++
	return true
}

func (relay *privateFactoryACKRelay) arm(t *testing.T, skip int) {
	t.Helper()
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.armed || relay.closing || skip < 0 || skip > 3 {
		t.Fatal("invalid single wire acknowledgement fault")
	}
	relay.skip, relay.armed = skip, true
}

func (relay *privateFactoryACKRelay) assertDrops(t *testing.T, want int) {
	t.Helper()
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.dropped != want || relay.armed || relay.failed.Load() {
		t.Fatal("wire relay did not drop exactly the selected committed acknowledgement")
	}
}

func (relay *privateFactoryACKRelay) stop() {
	relay.stopOnce.Do(func() {
		relay.cancel()
		relay.mu.Lock()
		relay.closing = true
		connections := make([]net.Conn, 0, len(relay.conns))
		for connection := range relay.conns {
			connections = append(connections, connection)
		}
		relay.mu.Unlock()
		_ = relay.listener.Close()
		for _, connection := range connections {
			_ = connection.Close()
		}
	})
}

func (relay *privateFactoryACKRelay) close(t *testing.T) {
	t.Helper()
	relay.stop()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
	defer cancel()
	select {
	case <-relay.done:
	case <-ctx.Done():
		t.Error("join owned wire relay")
	}
}

func (relay *privateFactoryACKRelay) openRuntime(t *testing.T) *postgresadapter.Pool {
	t.Helper()
	profile, err := config.Load(privateFactoryConfigLookup("api"))
	if err != nil || profile.Storage == nil || profile.Storage.PostgreSQL.Runtime == nil {
		t.Fatal("load owned wire runtime credentials")
	}
	pg := profile.Storage.PostgreSQL
	if pg.Address != "meshtransit-postgres:5432" || pg.Database != "meshtransit_private_factory_ack" ||
		pg.Runtime.User != "mesh_runtime" {
		t.Fatal("refuse unowned wire runtime scope")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	pool, err := postgresadapter.Open(ctx, postgresadapter.Options{
		Role: postgresadapter.PoolRoleRuntime, Address: relay.listener.Addr().String(),
		Database: pg.Database, User: pg.Runtime.User, PasswordFile: pg.Runtime.PasswordFile,
		CAFile: pg.CAFile, MaxConnections: 1, ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal("open real TLS relay runtime pool")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer stop()
		if pool.Shutdown(cleanup) != nil {
			t.Error("join real relay runtime pool")
		}
	})
	if pool.Check(ctx) != nil {
		t.Fatal("verify real TLS relay role and schema")
	}
	return pool
}

func TestPrivateFactoryACKBackendFrames(t *testing.T) {
	frame := func(kind byte, body string) []byte {
		length := len(body)
		if length < 0 || length > 1024*1024-4 {
			t.Fatal("invalid fixture frame length")
			return nil
		}
		result := []byte{kind, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(result[1:], uint32(length)+4)
		return append(result, body...)
	}
	commit := frame('C', "COMMIT\x00")
	for _, skip := range []int{0, 1} {
		relay := &privateFactoryACKRelay{armed: true, skip: skip}
		prefix := append(frame('D', "COMMIT\x00"), frame('C', "ROLLBACK\x00")...)
		input := append(bytes.Clone(prefix), commit...)
		input = append(input, commit...)
		var output bytes.Buffer
		if relay.forwardBackend(bytes.NewReader(input), &output) != nil {
			t.Fatal("selected completion frame was not suppressed")
		}
		want := bytes.Clone(prefix)
		if skip == 1 {
			want = append(want, commit...)
		}
		if !bytes.Equal(output.Bytes(), want) {
			t.Fatal("relay changed preceding frames or disclosed suppressed frame")
		}
		relay.assertDrops(t, 1)
	}
	for _, malformed := range [][]byte{
		{'C', 0, 0, 0, 3}, {'C', 0, 16, 0, 1}, {'C', 0, 0, 0, 8, 'x'},
	} {
		var output bytes.Buffer
		if (&privateFactoryACKRelay{}).forwardBackend(bytes.NewReader(malformed), &output) == nil ||
			output.Len() != 0 {
			t.Fatal("malformed bounded frame was forwarded")
		}
	}
}
