// Package sesmail delivers product email through the Amazon SES v2 API over
// HTTPS. It owns no product decision: callers render the message and decide
// whether a failure is retried. Credentials are static keys read from files
// by the configuration layer; nothing here reads the environment.
package sesmail

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/aws/smithy-go"
)

var (
	// ErrInvalid reports incomplete options or a malformed message.
	ErrInvalid = errors.New("sesmail: invalid input")
	// ErrRejected reports a message SES will not send as it is, such as an
	// unverified recipient in the sandbox; retrying the same message fails.
	ErrRejected = errors.New("sesmail: message rejected")
	// ErrUnavailable reports a failure that may pass on a later attempt.
	ErrUnavailable = errors.New("sesmail: delivery unavailable")
)

// Bounds on what one message may carry.
const (
	maximumSubjectBytes = 256
	maximumBodyBytes    = 64 << 10
)

// Options configure one sender.
type Options struct {
	// Region is the SES region, such as ap-southeast-1.
	Region string
	// AccessKeyID and SecretAccessKey are the IAM user's keys; the secret is
	// copied and never logged or formatted.
	AccessKeyID     string
	SecretAccessKey []byte
	// From is the verified sender, such as "MeshTransit <no-reply@example.com>".
	From string
	// ConfigurationSet optionally names an SES configuration set.
	ConfigurationSet string
	// Timeout bounds each HTTPS request, retries included.
	Timeout time.Duration
}

// Message is one plain-text email with an optional HTML part.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Sender sends messages through one SES client.
type Sender struct {
	client           *sesv2.Client
	from             string
	configurationSet string
	timeout          time.Duration
}

// New validates the options and builds the client without network I/O.
func New(options Options) (*Sender, error) {
	from, err := mail.ParseAddress(options.From)
	if err != nil || options.Region == "" || options.AccessKeyID == "" || len(options.SecretAccessKey) == 0 ||
		options.Timeout <= 0 || options.Timeout > time.Minute {
		return nil, ErrInvalid
	}
	secret := string(options.SecretAccessKey)
	client := sesv2.New(sesv2.Options{
		Region:           options.Region,
		Credentials:      credentials.NewStaticCredentialsProvider(options.AccessKeyID, secret, ""),
		HTTPClient:       &http.Client{Timeout: options.Timeout, CheckRedirect: refuseRedirect},
		RetryMaxAttempts: 3,
	})
	return &Sender{
		client: client, from: from.String(), configurationSet: options.ConfigurationSet, timeout: options.Timeout,
	}, nil
}

func refuseRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func validMessage(message Message) bool {
	address, err := mail.ParseAddress(message.To)
	return err == nil && address.Name == "" && address.Address == message.To &&
		message.Subject != "" && len(message.Subject) <= maximumSubjectBytes &&
		!strings.ContainsAny(message.Subject, "\r\n") && utf8.ValidString(message.Subject) &&
		message.Text != "" && len(message.Text) <= maximumBodyBytes && utf8.ValidString(message.Text) &&
		len(message.HTML) <= maximumBodyBytes && utf8.ValidString(message.HTML)
}

// Send delivers one message and returns the SES message identifier.
func (sender *Sender) Send(ctx context.Context, message Message) (string, error) {
	if ctx == nil || sender == nil || sender.client == nil || !validMessage(message) {
		return "", ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, sender.timeout)
	defer cancel()
	body := &types.Body{Text: &types.Content{Data: aws.String(message.Text), Charset: aws.String("UTF-8")}}
	if message.HTML != "" {
		body.Html = &types.Content{Data: aws.String(message.HTML), Charset: aws.String("UTF-8")}
	}
	input := &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(sender.from),
		Destination:      &types.Destination{ToAddresses: []string{message.To}},
		Content: &types.EmailContent{Simple: &types.Message{
			Subject: &types.Content{Data: aws.String(message.Subject), Charset: aws.String("UTF-8")},
			Body:    body,
		}},
	}
	if sender.configurationSet != "" {
		input.ConfigurationSetName = aws.String(sender.configurationSet)
	}
	output, err := sender.client.SendEmail(ctx, input)
	if err != nil {
		return "", classify(err)
	}
	if output == nil || output.MessageId == nil || *output.MessageId == "" {
		return "", ErrUnavailable
	}
	return *output.MessageId, nil
}

// Failure is a delivery failure that keeps only a stable reason: an SES
// error code or a transport kind, never SES message text.
type Failure struct {
	kind   error
	reason string
}

// Error returns the failure kind and reason.
func (failure *Failure) Error() string { return failure.kind.Error() + ": " + failure.reason }

// Unwrap returns ErrRejected or ErrUnavailable.
func (failure *Failure) Unwrap() error { return failure.kind }

// Reason returns the SES error code or transport kind.
func (failure *Failure) Reason() string { return failure.reason }

// classify keeps only a stable error code or transport kind: SES messages
// can name addresses.
func classify(err error) error {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		switch apiError.ErrorCode() {
		case "MessageRejected", "MailFromDomainNotVerifiedException", "AccountSuspendedException",
			"SendingPausedException", "BadRequestException", "NotFoundException":
			return &Failure{kind: ErrRejected, reason: apiError.ErrorCode()}
		default:
			return &Failure{kind: ErrUnavailable, reason: apiError.ErrorCode()}
		}
	}
	var dnsError *net.DNSError
	var certificateError *tls.CertificateVerificationError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return &Failure{kind: ErrUnavailable, reason: "timeout"}
	case errors.As(err, &dnsError):
		return &Failure{kind: ErrUnavailable, reason: "dns"}
	case errors.As(err, &certificateError):
		return &Failure{kind: ErrUnavailable, reason: "tls"}
	default:
		return &Failure{kind: ErrUnavailable, reason: "transport"}
	}
}
