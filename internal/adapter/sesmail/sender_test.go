package sesmail

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

type roundTripper func(*http.Request) (*http.Response, error)

func (fn roundTripper) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func testSender(t *testing.T, transport roundTripper) *Sender {
	t.Helper()
	sender, err := New(Options{
		Region: "ap-southeast-1", AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: []byte("example-secret"),
		From: "MeshTransit <no-reply@example.com>", Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	sender.client = sesv2.New(sesv2.Options{
		Region:           "ap-southeast-1",
		Credentials:      credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "example-secret", ""),
		HTTPClient:       &http.Client{Transport: transport},
		RetryMaxAttempts: 1,
	})
	return sender
}

func respond(status int, body string, headers map[string]string) *http.Response {
	response := &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
	response.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		response.Header.Set(key, value)
	}
	return response
}

func TestNewRejectsIncompleteOptions(t *testing.T) {
	t.Parallel()
	valid := Options{Region: "ap-southeast-1", AccessKeyID: "AKID", SecretAccessKey: []byte("s"),
		From: "no-reply@example.com", Timeout: time.Second}
	for name, mutate := range map[string]func(*Options){
		"no region":  func(options *Options) { options.Region = "" },
		"no key":     func(options *Options) { options.AccessKeyID = "" },
		"no secret":  func(options *Options) { options.SecretAccessKey = nil },
		"bad sender": func(options *Options) { options.From = "not an address" },
		"no timeout": func(options *Options) { options.Timeout = 0 },
		"long wait":  func(options *Options) { options.Timeout = time.Hour },
	} {
		options := valid
		mutate(&options)
		if _, err := New(options); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: New() error = %v", name, err)
		}
	}
	if _, err := New(valid); err != nil {
		t.Fatalf("New(valid) error = %v", err)
	}
}

func TestSendSignsOneRequestAndReturnsTheMessageID(t *testing.T) {
	t.Parallel()
	var seen *http.Request
	var body string
	sender := testSender(t, func(request *http.Request) (*http.Response, error) {
		seen = request
		raw, _ := io.ReadAll(request.Body)
		body = string(raw)
		return respond(http.StatusOK, `{"MessageId":"0100-example"}`, nil), nil
	})
	id, err := sender.Send(context.Background(), Message{
		To: "member@example.com", Subject: "Join Test", Text: "Open the link.", HTML: "<p>Open the link.</p>",
	})
	if err != nil || id != "0100-example" {
		t.Fatalf("Send() = %q, %v", id, err)
	}
	if seen.URL.Host != "email.ap-southeast-1.amazonaws.com" || seen.URL.Scheme != "https" ||
		!strings.HasPrefix(seen.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
		t.Fatalf("request = %s %s", seen.URL, seen.Header.Get("Authorization"))
	}
	for _, want := range []string{`"member@example.com"`, `"Join Test"`, `no-reply@example.com`} {
		if !strings.Contains(body, want) {
			t.Errorf("request body lacks %s", want)
		}
	}
}

func TestSendClassifiesFailuresWithoutDetails(t *testing.T) {
	t.Parallel()
	for code, want := range map[string]error{
		"MessageRejected":          ErrRejected,
		"TooManyRequestsException": ErrUnavailable,
		"InternalFailureException": ErrUnavailable,
	} {
		sender := testSender(t, func(*http.Request) (*http.Response, error) {
			return respond(http.StatusBadRequest,
				`{"message":"Email address is not verified: member@example.com"}`,
				map[string]string{"X-Amzn-Errortype": code}), nil
		})
		_, err := sender.Send(context.Background(), Message{To: "member@example.com", Subject: "s", Text: "t"})
		var failure *Failure
		if !errors.Is(err, want) || strings.Contains(err.Error(), "member@example.com") ||
			!errors.As(err, &failure) || failure.Reason() != code {
			t.Errorf("%s: Send() error = %v, want %v without the address", code, err, want)
		}
	}
}

func TestSendRejectsMalformedMessages(t *testing.T) {
	t.Parallel()
	sender := testSender(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("a malformed message must not reach SES")
		return nil, nil
	})
	for name, message := range map[string]Message{
		"named recipient": {To: "Member <member@example.com>", Subject: "s", Text: "t"},
		"header break":    {To: "member@example.com", Subject: "s\r\nBcc: x@example.com", Text: "t"},
		"no text":         {To: "member@example.com", Subject: "s"},
		"huge body":       {To: "member@example.com", Subject: "s", Text: strings.Repeat("x", maximumBodyBytes+1)},
	} {
		if _, err := sender.Send(context.Background(), message); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Send() error = %v", name, err)
		}
	}
}
