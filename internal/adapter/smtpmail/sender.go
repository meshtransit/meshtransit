// Package smtpmail delivers product email to an SMTP submission server. Every
// connection is encrypted before credentials or content are sent: implicit
// TLS (port 465) or a required STARTTLS upgrade (port 587). It renders no
// product content; callers pass a finished message.
package smtpmail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	// ErrInvalid reports incomplete options or a malformed message.
	ErrInvalid = errors.New("smtpmail: invalid input")
	// ErrRejected reports a permanent (5xx) refusal; resending the same
	// message fails again.
	ErrRejected = errors.New("smtpmail: message rejected")
	// ErrUnavailable reports a failure that may pass on a later attempt.
	ErrUnavailable = errors.New("smtpmail: delivery unavailable")
)

// TLS modes.
const (
	TLSImplicit = "tls"
	TLSStartTLS = "starttls"
)

const (
	maximumSubjectBytes = 256
	maximumBodyBytes    = 64 << 10
)

// Options configure one sender.
type Options struct {
	Host string
	Port int
	// TLSMode is TLSImplicit or TLSStartTLS; there is no plaintext mode.
	TLSMode string
	// Username and Password authenticate with AUTH PLAIN over TLS; both empty
	// means no authentication.
	Username string
	Password []byte
	// From is the sender, such as "MeshTransit <no-reply@example.com>".
	From string
	// HeloName is the name announced in EHLO.
	HeloName string
	// Timeout bounds one whole delivery.
	Timeout time.Duration
	// tlsConfig replaces the system trust in tests only.
	tlsConfig *tls.Config
}

// Message is one plain-text email with an optional HTML part.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Sender delivers messages to one submission server.
type Sender struct {
	address  string
	host     string
	mode     string
	username string
	password string
	from     *mail.Address
	helo     string
	timeout  time.Duration
	tls      *tls.Config
}

// New validates the options without network I/O.
func New(options Options) (*Sender, error) {
	from, err := mail.ParseAddress(options.From)
	if err != nil || options.Host == "" || strings.ContainsAny(options.Host, " /\r\n") ||
		options.Port < 1 || options.Port > 65535 ||
		(options.TLSMode != TLSImplicit && options.TLSMode != TLSStartTLS) ||
		(options.Username == "") != (len(options.Password) == 0) ||
		options.Timeout <= 0 || options.Timeout > time.Minute {
		return nil, ErrInvalid
	}
	helo := options.HeloName
	if helo == "" {
		helo = "meshtransit"
	}
	config := &tls.Config{ServerName: options.Host, MinVersion: tls.VersionTLS12}
	if options.tlsConfig != nil {
		config = options.tlsConfig.Clone()
		config.ServerName, config.MinVersion = options.Host, tls.VersionTLS12
	}
	return &Sender{
		address: net.JoinHostPort(options.Host, strconv.Itoa(options.Port)), host: options.Host,
		mode: options.TLSMode, username: options.Username, password: string(options.Password), from: from,
		helo: helo, timeout: options.Timeout, tls: config,
	}, nil
}

func validMessage(message Message) bool {
	address, err := mail.ParseAddress(message.To)
	return err == nil && address.Name == "" && address.Address == message.To &&
		message.Subject != "" && len(message.Subject) <= maximumSubjectBytes &&
		!strings.ContainsAny(message.Subject, "\r\n") && utf8.ValidString(message.Subject) &&
		message.Text != "" && len(message.Text) <= maximumBodyBytes && utf8.ValidString(message.Text) &&
		len(message.HTML) <= maximumBodyBytes && utf8.ValidString(message.HTML)
}

// Send delivers one message.
func (sender *Sender) Send(ctx context.Context, message Message) error {
	if ctx == nil || sender == nil || !validMessage(message) {
		return ErrInvalid
	}
	body, err := sender.compose(message, time.Now())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, sender.timeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	dialer := &net.Dialer{}
	raw, err := dialer.DialContext(ctx, "tcp", sender.address)
	if err != nil {
		return ErrUnavailable
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	if err := raw.SetDeadline(deadline); err != nil {
		_ = raw.Close()
		return ErrUnavailable
	}
	connection := raw
	if sender.mode == TLSImplicit {
		secured := tls.Client(raw, sender.tls)
		if err := secured.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return ErrUnavailable
		}
		connection = secured
	}
	client, err := smtp.NewClient(connection, sender.host)
	if err != nil {
		_ = connection.Close()
		return classify(err)
	}
	// After QUIT the server closes the link; a close error carries nothing.
	defer func() { _ = client.Close() }()
	if err := client.Hello(sender.helo); err != nil {
		return classify(err)
	}
	if sender.mode == TLSStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("%w: server does not offer STARTTLS", ErrUnavailable)
		}
		if err := client.StartTLS(sender.tls); err != nil {
			return ErrUnavailable
		}
	}
	if sender.username != "" {
		// PlainAuth refuses to send credentials over an unencrypted link.
		if err := client.Auth(smtp.PlainAuth("", sender.username, sender.password, sender.host)); err != nil {
			return classify(err)
		}
	}
	if err := client.Mail(sender.from.Address); err != nil {
		return classify(err)
	}
	if err := client.Rcpt(message.To); err != nil {
		return classify(err)
	}
	writer, err := client.Data()
	if err != nil {
		return classify(err)
	}
	if _, err := writer.Write(body); err != nil {
		return ErrUnavailable
	}
	if err := writer.Close(); err != nil {
		return classify(err)
	}
	if err := client.Quit(); err != nil {
		return classify(err)
	}
	return nil
}

// compose builds an RFC 5322 message with text and HTML alternatives.
func (sender *Sender) compose(message Message, now time.Time) ([]byte, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, ErrUnavailable
	}
	domain := sender.from.Address[strings.LastIndexByte(sender.from.Address, '@')+1:]
	var buffer bytes.Buffer
	parts := multipart.NewWriter(&buffer)
	headers := []string{
		"From: " + sender.from.String(),
		"To: " + message.To,
		"Subject: " + mime.QEncoding.Encode("utf-8", message.Subject),
		"Date: " + now.UTC().Format(time.RFC1123Z),
		"Message-ID: <" + hex.EncodeToString(random) + "@" + domain + ">",
		"MIME-Version: 1.0",
		"Content-Type: multipart/alternative; boundary=" + parts.Boundary(),
	}
	var out bytes.Buffer
	out.WriteString(strings.Join(headers, "\r\n") + "\r\n\r\n")
	if err := writePart(parts, "text/plain; charset=utf-8", message.Text); err != nil {
		return nil, err
	}
	if message.HTML != "" {
		if err := writePart(parts, "text/html; charset=utf-8", message.HTML); err != nil {
			return nil, err
		}
	}
	if err := parts.Close(); err != nil {
		return nil, err
	}
	out.Write(buffer.Bytes())
	return out.Bytes(), nil
}

func writePart(parts *multipart.Writer, contentType, content string) error {
	header := textproto.MIMEHeader{}
	header.Set("Content-Type", contentType)
	header.Set("Content-Transfer-Encoding", "quoted-printable")
	part, err := parts.CreatePart(header)
	if err != nil {
		return err
	}
	encoder := quotedprintable.NewWriter(part)
	if _, err := encoder.Write([]byte(strings.ReplaceAll(content, "\n", "\r\n"))); err != nil {
		return err
	}
	return encoder.Close()
}

// classify keeps only the reply class: server text can name addresses.
func classify(err error) error {
	var reply *textproto.Error
	if errors.As(err, &reply) {
		if reply.Code >= 500 && reply.Code < 600 {
			return fmt.Errorf("%w: reply %d", ErrRejected, reply.Code)
		}
		return fmt.Errorf("%w: reply %d", ErrUnavailable, reply.Code)
	}
	return ErrUnavailable
}
