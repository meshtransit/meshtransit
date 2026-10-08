package smtpmail

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"mime"
	"net"
	"net/mail"
	"strings"
	"sync"
	"testing"
	"time"
)

// testCertificate is a self-signed certificate for 127.0.0.1.
func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// fakeServer speaks just enough SMTP to accept one message.
type fakeServer struct {
	listener  net.Listener
	tlsConfig *tls.Config
	mode      string
	offerTLS  bool
	rejectTo  bool
	mu        sync.Mutex
	auth      string
	from      string
	to        string
	data      string
	secured   bool
}

func (server *fakeServer) serve(t *testing.T) {
	t.Helper()
	connection, err := server.listener.Accept()
	if err != nil {
		return
	}
	defer func() { _ = connection.Close() }()
	if server.mode == TLSImplicit {
		connection = tls.Server(connection, server.tlsConfig)
		server.secured = true
	}
	reader, writer := bufio.NewReader(connection), connection
	reply := func(line string) { _, _ = writer.Write([]byte(line + "\r\n")) }
	reply("220 fake ESMTP")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(command)
		switch {
		case strings.HasPrefix(upper, "EHLO"):
			if server.offerTLS && !server.secured {
				reply("250-fake")
				reply("250-STARTTLS")
				reply("250 AUTH PLAIN")
			} else {
				reply("250-fake")
				reply("250 AUTH PLAIN")
			}
		case upper == "STARTTLS":
			reply("220 go ahead")
			secured := tls.Server(connection, server.tlsConfig)
			connection, server.secured = secured, true
			reader, writer = bufio.NewReader(secured), secured
		case strings.HasPrefix(upper, "AUTH PLAIN"):
			server.mu.Lock()
			server.auth = strings.TrimPrefix(command, "AUTH PLAIN ")
			server.mu.Unlock()
			reply("235 ok")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			server.mu.Lock()
			server.from = command
			server.mu.Unlock()
			reply("250 ok")
		case strings.HasPrefix(upper, "RCPT TO:"):
			if server.rejectTo {
				reply("550 5.1.1 mailbox member@example.com unavailable")
				continue
			}
			server.mu.Lock()
			server.to = command
			server.mu.Unlock()
			reply("250 ok")
		case upper == "DATA":
			reply("354 send")
			var body strings.Builder
			for {
				dataLine, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if dataLine == ".\r\n" {
					break
				}
				body.WriteString(dataLine)
			}
			server.mu.Lock()
			server.data = body.String()
			server.mu.Unlock()
			reply("250 queued")
		case upper == "QUIT":
			reply("221 bye")
			return
		default:
			reply("502 unknown")
		}
	}
}

func startServer(t *testing.T, mode string, offerTLS, rejectTo bool) (*fakeServer, *x509.CertPool) {
	t.Helper()
	certificate, pool := testCertificate(t)
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server := &fakeServer{
		listener: listener, mode: mode, offerTLS: offerTLS, rejectTo: rejectTo,
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
	}
	go server.serve(t)
	return server, pool
}

func testSender(t *testing.T, server *fakeServer, pool *x509.CertPool, mode string) *Sender {
	t.Helper()
	port := server.listener.Addr().(*net.TCPAddr).Port
	sender, err := New(Options{
		Host: "127.0.0.1", Port: port, TLSMode: mode, Username: "smtp-user", Password: []byte("smtp-pass"),
		From: "MeshTransit <no-reply@example.com>", Timeout: 5 * time.Second,
		tlsConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	})
	if err != nil {
		t.Fatal(err)
	}
	return sender
}

var testMessage = Message{
	To: "member@example.com", Subject: "Lan invited you to Test ABC — MeshTransit",
	Text: "Accept: https://console.example.com/join#invite=x", HTML: "<p>Accept</p>",
}

func TestSendOverStartTLSAndImplicitTLS(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{TLSStartTLS, TLSImplicit} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			server, pool := startServer(t, mode, mode == TLSStartTLS, false)
			if err := testSender(t, server, pool, mode).Send(context.Background(), testMessage); err != nil {
				t.Fatalf("Send() error = %v", err)
			}
			server.mu.Lock()
			defer server.mu.Unlock()
			if !server.secured || server.auth == "" || !strings.Contains(server.from, "no-reply@example.com") ||
				!strings.Contains(server.to, "member@example.com") {
				t.Fatalf("server saw secured=%t auth=%q from=%q to=%q", server.secured, server.auth, server.from, server.to)
			}
			message, err := mail.ReadMessage(strings.NewReader(server.data))
			if err != nil {
				t.Fatalf("parse delivered message: %v", err)
			}
			subject, err := new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
			if err != nil || subject != testMessage.Subject {
				t.Fatalf("subject = %q, %v", subject, err)
			}
			if !strings.HasPrefix(message.Header.Get("Content-Type"), "multipart/alternative;") ||
				message.Header.Get("Message-Id") == "" || !strings.Contains(server.data, "text/html") {
				t.Fatalf("headers = %v", message.Header)
			}
		})
	}
}

func TestSendRefusesAServerWithoutStartTLS(t *testing.T) {
	t.Parallel()
	server, pool := startServer(t, TLSStartTLS, false, false)
	err := testSender(t, server, pool, TLSStartTLS).Send(context.Background(), testMessage)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Send() error = %v, want unavailable", err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.auth != "" || server.data != "" {
		t.Fatal("credentials or content crossed an unencrypted link")
	}
}

func TestSendClassifiesARejectedRecipient(t *testing.T) {
	t.Parallel()
	server, pool := startServer(t, TLSImplicit, false, true)
	err := testSender(t, server, pool, TLSImplicit).Send(context.Background(), testMessage)
	if !errors.Is(err, ErrRejected) || strings.Contains(err.Error(), "member@example.com") {
		t.Fatalf("Send() error = %v, want rejected without the address", err)
	}
}

func TestNewAndSendRejectInvalidInput(t *testing.T) {
	t.Parallel()
	valid := Options{Host: "smtp.example.com", Port: 587, TLSMode: TLSStartTLS, From: "no-reply@example.com",
		Timeout: time.Second}
	for name, mutate := range map[string]func(*Options){
		"plaintext":  func(options *Options) { options.TLSMode = "none" },
		"no host":    func(options *Options) { options.Host = "" },
		"bad port":   func(options *Options) { options.Port = 0 },
		"user only":  func(options *Options) { options.Username = "u" },
		"bad sender": func(options *Options) { options.From = "nobody" },
		"no timeout": func(options *Options) { options.Timeout = 0 },
	} {
		options := valid
		mutate(&options)
		if _, err := New(options); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: New() error = %v", name, err)
		}
	}
	sender, err := New(valid)
	if err != nil {
		t.Fatal(err)
	}
	for name, message := range map[string]Message{
		"header break": {To: "member@example.com", Subject: "s\r\nBcc: x@example.com", Text: "t"},
		"named":        {To: "Member <member@example.com>", Subject: "s", Text: "t"},
		"no text":      {To: "member@example.com", Subject: "s"},
	} {
		if err := sender.Send(context.Background(), message); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Send() error = %v", name, err)
		}
	}
}
