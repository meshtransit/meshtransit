package k8sstate

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	// maxResponseBytes bounds what the client reads from the API server.
	maxResponseBytes = 4 << 20
	// defaultRetryAfter is the wait after a 429 without a usable Retry-After.
	defaultRetryAfter = time.Second
)

// secret is a Secret as the API server sent it. The whole object is kept so
// a PUT sends back the fields and metadata the mirror does not know, such as
// labels, owners or immutable.
type secret struct {
	object   map[string]json.RawMessage
	metadata map[string]json.RawMessage
	data     map[string][]byte
	version  string
}

func decodeSecret(payload []byte) (secret, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		return secret{}, fmt.Errorf("decoding the Secret: %w", err)
	}
	var kind string
	if err := json.Unmarshal(object["kind"], &kind); err != nil || kind != "Secret" {
		return secret{}, fmt.Errorf("the API server sent a %q, not a Secret", kind)
	}
	decoded := secret{object: object}
	if err := json.Unmarshal(object["metadata"], &decoded.metadata); err != nil {
		return secret{}, fmt.Errorf("decoding the Secret's metadata: %w", err)
	}
	if err := json.Unmarshal(decoded.metadata["resourceVersion"], &decoded.version); err != nil || decoded.version == "" {
		return secret{}, errors.New("the Secret carries no resourceVersion")
	}
	if raw, ok := object["data"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &decoded.data); err != nil {
			return secret{}, fmt.Errorf("decoding the Secret's data: %w", err)
		}
	}
	if decoded.data == nil {
		decoded.data = map[string][]byte{}
	}
	return decoded, nil
}

// replacement is the PUT body that gives s the data, over s's version.
func (s secret) replacement(data map[string][]byte) ([]byte, error) {
	object := make(map[string]json.RawMessage, len(s.object)+1)
	for key, value := range s.object {
		object[key] = value
	}
	metadata := make(map[string]json.RawMessage, len(s.metadata))
	for key, value := range s.metadata {
		metadata[key] = value
	}
	// The API server keeps managed fields itself; sending them back is noise.
	delete(metadata, "managedFields")
	var err error
	if metadata["resourceVersion"], err = json.Marshal(s.version); err != nil {
		return nil, err
	}
	if object["metadata"], err = json.Marshal(metadata); err != nil {
		return nil, err
	}
	if object["data"], err = json.Marshal(data); err != nil {
		return nil, err
	}
	if _, ok := object["type"]; !ok {
		object["type"] = json.RawMessage(`"Opaque"`)
	}
	return json.Marshal(object)
}

// statusError is an answer other than 200 from the API server.
type statusError struct {
	code       int
	message    string
	retryAfter time.Duration
}

func (e *statusError) Error() string {
	return fmt.Sprintf("API server answered %d: %s", e.code, e.message)
}

// localError is a failure before the request left the process, so the API
// server never saw it.
type localError struct{ err error }

func (e *localError) Error() string { return e.err.Error() }
func (e *localError) Unwrap() error { return e.err }

// notRun reports whether a request that ended with err certainly did not
// change the Secret: it never left the process, or the API server refused
// it. A 409 did not run either but needs a read back, so it is not here.
func notRun(err error) bool {
	var local *localError
	if errors.As(err, &local) {
		return true
	}
	var status *statusError
	return errors.As(err, &status) && status.code < 500 && status.code != http.StatusConflict
}

// tooMany returns the wait a 429 asked for.
func tooMany(err error) (time.Duration, bool) {
	var status *statusError
	if errors.As(err, &status) && status.code == http.StatusTooManyRequests {
		return status.retryAfter, true
	}
	return 0, false
}

type apiClient struct {
	cfg       Config
	http      *http.Client
	transport *http.Transport
	url       string
}

func newAPIClient(cfg Config) (*apiClient, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("k8sstate: reading the cluster CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("k8sstate: the cluster CA file holds no certificate")
	}
	// No proxy from the environment: the token goes to the API server only.
	// Pings find a dead HTTP/2 connection after an API server failover
	// instead of letting every request time out on it.
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
		IdleConnTimeout:   90 * time.Second,
		HTTP2:             &http.HTTP2Config{SendPingTimeout: 30 * time.Second, PingTimeout: 15 * time.Second},
	}
	return &apiClient{
		cfg: cfg,
		http: &http.Client{
			Transport: transport,
			// The token must not follow a redirect anywhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		transport: transport,
		url: strings.TrimSuffix(cfg.Server, "/") + "/api/v1/namespaces/" +
			url.PathEscape(cfg.Namespace) + "/secrets/" + url.PathEscape(cfg.SecretName),
	}, nil
}

func (c *apiClient) close() { c.transport.CloseIdleConnections() }

func (c *apiClient) get(ctx context.Context) (secret, error) {
	return c.do(ctx, http.MethodGet, nil)
}

func (c *apiClient) put(ctx context.Context, current secret, data map[string][]byte) (secret, error) {
	body, err := current.replacement(data)
	if err != nil {
		return secret{}, &localError{fmt.Errorf("encoding the Secret: %w", err)}
	}
	return c.do(ctx, http.MethodPut, body)
}

func (c *apiClient) do(ctx context.Context, method string, body []byte) (secret, error) {
	token, err := os.ReadFile(c.cfg.TokenFile)
	if err != nil {
		return secret{}, &localError{fmt.Errorf("reading the service account token: %w", err)}
	}
	request, err := http.NewRequestWithContext(ctx, method, c.url, bytes.NewReader(body))
	if err != nil {
		return secret{}, &localError{fmt.Errorf("building the request: %w", err)}
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		// The connection may be dead; the next request dials a new one.
		c.transport.CloseIdleConnections()
		return secret{}, fmt.Errorf("%s Secret: %w", method, err)
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		c.transport.CloseIdleConnections()
		return secret{}, fmt.Errorf("reading the %s answer: %w", method, err)
	}
	if response.StatusCode != http.StatusOK {
		return secret{}, &statusError{
			code:       response.StatusCode,
			message:    statusMessage(payload),
			retryAfter: retryAfter(response.Header.Get("Retry-After")),
		}
	}
	return decodeSecret(payload)
}

// statusMessage is the reason and message of a Kubernetes Status, or the
// start of any other body, cleaned so it is safe to log.
func statusMessage(payload []byte) string {
	var status struct {
		Reason  string `json:"reason"`
		Message string `json:"message"`
	}
	text := string(payload)
	if json.Unmarshal(payload, &status) == nil && (status.Reason != "" || status.Message != "") {
		text = strings.TrimSpace(status.Reason + ": " + status.Message)
	}
	const limit = 200
	cleaned := []rune{}
	for _, r := range text {
		if len(cleaned) == limit {
			cleaned = append(cleaned, '…')
			break
		}
		if unicode.IsControl(r) {
			r = ' '
		}
		cleaned = append(cleaned, r)
	}
	return strings.TrimSpace(string(cleaned))
}

// retryAfter reads a Retry-After of whole seconds, as the API server sends.
func retryAfter(header string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil || seconds <= 0 {
		return defaultRetryAfter
	}
	return time.Duration(seconds) * time.Second
}
