package kubecheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// API is what the check reads from the API server, and the Event it writes.
type API interface {
	// Get decodes the JSON at path, under the API server, into into.
	Get(ctx context.Context, path string, into any) error
	// Post sends body as JSON to path.
	Post(ctx context.Context, path string, body any) error
}

// StatusError is the API server's refusal, with its code.
type StatusError struct {
	Code    int
	Message string
}

func (err *StatusError) Error() string {
	return fmt.Sprintf("kubecheck: the API server answered %d: %s", err.Code, err.Message)
}

// NotFound reports err as the API server's 404.
func NotFound(err error) bool {
	var status *StatusError
	return errors.As(err, &status) && status.Code == http.StatusNotFound
}

const (
	// maximumResponse bounds one answer: lists are read in pages of
	// listPage items (review c2b H2).
	maximumResponse = 32 << 20
	listPage        = 500
	requestTimeout  = 30 * time.Second
)

// InCluster is the API server the pod runs under, reached with the pod's
// own ServiceAccount token, read again for every request.
type InCluster struct {
	server    string
	tokenFile string
	http      *http.Client
}

// NewInCluster reads the pod's API server, CA and token paths.
func NewInCluster(getenv func(string) string, caFile, tokenFile string) (*InCluster, error) {
	host, port := getenv("KUBERNETES_SERVICE_HOST"), getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("kubecheck: not in a pod: KUBERNETES_SERVICE_HOST or KUBERNETES_SERVICE_PORT is unset")
	}
	pem, err := os.ReadFile(caFile) //nolint:gosec // G304: the mounted cluster CA
	if err != nil {
		return nil, fmt.Errorf("kubecheck: reading the cluster CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("kubecheck: the cluster CA file holds no certificate")
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return &InCluster{
		server:    "https://" + host + ":" + port,
		tokenFile: tokenFile,
		http: &http.Client{
			// No proxy from the environment: the token goes to the API
			// server only, never following a redirect.
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Timeout:       requestTimeout,
		},
	}, nil
}

// Get implements API.
func (client *InCluster) Get(ctx context.Context, path string, into any) error {
	payload, err := client.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payload, into); err != nil {
		return fmt.Errorf("kubecheck: decoding %s: %w", path, err)
	}
	return nil
}

// Post implements API.
func (client *InCluster) Post(ctx context.Context, path string, body any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	_, err = client.do(ctx, http.MethodPost, path, encoded)
	return err
}

func (client *InCluster) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	token, err := os.ReadFile(client.tokenFile)
	if err != nil {
		return nil, fmt.Errorf("kubecheck: reading the ServiceAccount token: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, method, client.server+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("kubecheck: %s %s: %w", method, path, err)
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maximumResponse+1))
	if err != nil {
		return nil, fmt.Errorf("kubecheck: reading %s: %w", path, err)
	}
	if len(payload) > maximumResponse {
		return nil, fmt.Errorf("kubecheck: %s answered more than %d MiB", path, maximumResponse>>20)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		var status struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(payload, &status)
		return nil, &StatusError{Code: response.StatusCode, Message: printable(status.Message)}
	}
	return payload, nil
}

// printable keeps a message safe to log: printable ASCII, at most 512 bytes.
func printable(message string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, message)
	if len(cleaned) > 512 {
		cleaned = cleaned[:512]
	}
	return cleaned
}

// maximumStatus bounds a replica's /status answer.
const maximumStatus = 1 << 20

// statusClient reads the replicas' /status, one connection each, no proxy.
var statusClient = &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

// listAll reads every item of the list at path in pages, handing each to
// each; an expired continue token restarts the list once (review c2b H2).
func listAll(ctx context.Context, api API, path string, each func(json.RawMessage) error) error {
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	for restarted := false; ; {
		next, err := "", error(nil)
		for {
			page := path + separator + "limit=" + strconv.Itoa(listPage)
			if next != "" {
				page += "&continue=" + url.QueryEscape(next)
			}
			var answer struct {
				Metadata struct {
					Continue string `json:"continue"`
				} `json:"metadata"`
				Items []json.RawMessage `json:"items"`
			}
			if err = api.Get(ctx, page, &answer); err != nil {
				break
			}
			for _, item := range answer.Items {
				if err := each(item); err != nil {
					return err
				}
			}
			if next = answer.Metadata.Continue; next == "" {
				return nil
			}
		}
		var status *StatusError
		if restarted || !errors.As(err, &status) || status.Code != http.StatusGone {
			return err
		}
		restarted = true
	}
}

// FetchStatus reads a replica's /status over the pod network: the probes'
// port, which the chart's NetworkPolicy opens to the check pod only.
func FetchStatus(ctx context.Context, host string, port int) (ReplicaStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	address := "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/status"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return ReplicaStatus{}, err
	}
	response, err := statusClient.Do(request)
	if err != nil {
		return ReplicaStatus{}, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return ReplicaStatus{}, fmt.Errorf("kubecheck: /status answered %d", response.StatusCode)
	}
	var status ReplicaStatus
	if err := json.NewDecoder(io.LimitReader(response.Body, maximumStatus)).Decode(&status); err != nil {
		return ReplicaStatus{}, fmt.Errorf("kubecheck: decoding /status: %w", err)
	}
	return status, nil
}
