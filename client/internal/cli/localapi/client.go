// Package localapi calls meshd through its versioned Unix-socket API.
package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"time"
)

const (
	baseURL              = "http://meshd.local"
	maxResponseBodyBytes = 1 << 20
)

// APIError is a sanitized error returned by meshd.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

// Error returns a stable message suitable for CLI stderr.
func (e *APIError) Error() string {
	return fmt.Sprintf("daemon returned %s: %s", e.Code, e.Message)
}

// Client calls the local daemon without exposing its HTTP transport.
type Client struct {
	httpClient *http.Client
}

// New creates a client that dials socketPath for every local API connection.
func New(socketPath string, timeout time.Duration) (*Client, error) {
	if !filepath.IsAbs(socketPath) {
		return nil, errors.New("localapi: socket path must be absolute")
	}
	if timeout <= 0 {
		return nil, errors.New("localapi: timeout must be positive")
	}

	transport := &http.Transport{
		DisableCompression: true,
		DialContext:        dialer(socketPath, timeout),
	}

	return &Client{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
	}, nil
}

func newWithHTTPClient(httpClient *http.Client) *Client {
	return &Client{httpClient: httpClient}
}

// Status returns the current daemon and data-plane status.
func (c *Client) Status(ctx context.Context) (Status, error) {
	response := Status{}
	if err := c.do(ctx, http.MethodGet, "/v1/status", nil, http.StatusOK, &response); err != nil {
		return Status{}, err
	}
	if response.APIVersion != apiVersion {
		return Status{}, fmt.Errorf("localapi: unsupported api version %q", response.APIVersion)
	}

	return response, nil
}

// ListProfiles returns every profile and its active marker.
func (c *Client) ListProfiles(ctx context.Context) (Profiles, error) {
	response := Profiles{}
	if err := c.do(ctx, http.MethodGet, "/v1/profiles", nil, http.StatusOK, &response); err != nil {
		return Profiles{}, err
	}
	if response.APIVersion != apiVersion {
		return Profiles{}, fmt.Errorf("localapi: unsupported api version %q", response.APIVersion)
	}
	if response.Profiles == nil {
		response.Profiles = []Profile{}
	}

	return response, nil
}

// CreateProfile creates a profile without accepting a client-selected network id.
func (c *Client) CreateProfile(ctx context.Context, input CreateProfile) (Profile, error) {
	response := Profile{}
	if err := c.do(ctx, http.MethodPost, "/v1/profiles", input, http.StatusCreated, &response); err != nil {
		return Profile{}, err
	}

	return response, nil
}

// ActivateProfile selects one profile without merging its network view with another.
func (c *Client) ActivateProfile(ctx context.Context, id string) (Profile, error) {
	if !isProfileID(id) {
		return Profile{}, errors.New("localapi: invalid profile id")
	}

	response := Profile{}
	path := "/v1/profiles/" + id + "/activate"
	if err := c.do(ctx, http.MethodPost, path, nil, http.StatusOK, &response); err != nil {
		return Profile{}, err
	}

	return response, nil
}

// ProbeControl verifies the active profile's HTTPS control-key endpoint.
func (c *Client) ProbeControl(ctx context.Context) (ControlProbe, error) {
	response := ControlProbe{}
	if err := c.do(
		ctx,
		http.MethodPost,
		"/v1/doctor/control",
		nil,
		http.StatusOK,
		&response,
	); err != nil {
		return ControlProbe{}, err
	}
	if response.APIVersion != apiVersion {
		return ControlProbe{}, fmt.Errorf("localapi: unsupported api version %q", response.APIVersion)
	}

	return response, nil
}

// TrustControl verifies and pins the active profile's control key.
func (c *Client) TrustControl(ctx context.Context, fingerprint string) (ControlTrust, error) {
	response := ControlTrust{}
	if err := c.do(
		ctx,
		http.MethodPost,
		"/v1/control/trust",
		trustControlRequest{Fingerprint: fingerprint},
		http.StatusOK,
		&response,
	); err != nil {
		return ControlTrust{}, err
	}
	if response.APIVersion != apiVersion {
		return ControlTrust{}, fmt.Errorf("localapi: unsupported api version %q", response.APIVersion)
	}

	return response, nil
}

// StartLogin starts registration. The optional auth key is sent in memory and
// is not retained by meshctl.
func (c *Client) StartLogin(ctx context.Context, authKey string) (Login, error) {
	response := Login{}
	if err := c.do(
		ctx,
		http.MethodPost,
		"/v1/login",
		loginRequest{AuthKey: authKey},
		http.StatusOK,
		&response,
	); err != nil {
		return Login{}, err
	}
	if response.APIVersion != apiVersion {
		return Login{}, fmt.Errorf("localapi: unsupported api version %q", response.APIVersion)
	}

	return response, nil
}

// CompleteLogin polls a previously started browser authorization flow.
func (c *Client) CompleteLogin(ctx context.Context) (Login, error) {
	response := Login{}
	if err := c.do(
		ctx,
		http.MethodPost,
		"/v1/login/complete",
		nil,
		http.StatusOK,
		&response,
	); err != nil {
		return Login{}, err
	}
	if response.APIVersion != apiVersion {
		return Login{}, fmt.Errorf("localapi: unsupported api version %q", response.APIVersion)
	}

	return response, nil
}

// Down takes meshd off the network until Up.
func (c *Client) Down(ctx context.Context) (Connection, error) {
	return c.postConnection(ctx, "/v1/down")
}

// Up clears a Down.
func (c *Client) Up(ctx context.Context) (Connection, error) {
	return c.postConnection(ctx, "/v1/up")
}

// ApproveExitNodes lets the pool in use carry traffic through the exit
// nodes Core added to it.
func (c *Client) ApproveExitNodes(ctx context.Context, ids []string) (ExitApproval, error) {
	response := ExitApproval{}
	if err := c.do(ctx, http.MethodPost, "/v1/exit/approve", exitApprovalRequest{IDs: ids}, http.StatusOK,
		&response); err != nil {
		return ExitApproval{}, err
	}
	if response.APIVersion != apiVersion {
		return ExitApproval{}, fmt.Errorf("localapi: unsupported api version %q", response.APIVersion)
	}
	return response, nil
}

func (c *Client) postConnection(ctx context.Context, path string) (Connection, error) {
	response := Connection{}
	if err := c.do(ctx, http.MethodPost, path, nil, http.StatusOK, &response); err != nil {
		return Connection{}, err
	}
	if response.APIVersion != apiVersion {
		return Connection{}, fmt.Errorf("localapi: unsupported api version %q", response.APIVersion)
	}

	return response, nil
}

// Logout ends the active profile's Device.
func (c *Client) Logout(ctx context.Context) (Logout, error) {
	response := Logout{}
	if err := c.do(ctx, http.MethodPost, "/v1/logout", nil, http.StatusOK, &response); err != nil {
		return Logout{}, err
	}
	if response.APIVersion != apiVersion {
		return Logout{}, fmt.Errorf("localapi: unsupported api version %q", response.APIVersion)
	}

	return response, nil
}

// RotateNodeKey requests one crash-safe Node-key transition for the active
// registered profile. Private key material remains owned by meshd.
func (c *Client) RotateNodeKey(ctx context.Context) (NodeKeyRotation, error) {
	response := NodeKeyRotation{}
	if err := c.do(
		ctx,
		http.MethodPost,
		"/v1/identity/node-key/rotate",
		nil,
		http.StatusOK,
		&response,
	); err != nil {
		return NodeKeyRotation{}, err
	}
	if response.APIVersion != apiVersion {
		return NodeKeyRotation{}, fmt.Errorf(
			"localapi: unsupported api version %q",
			response.APIVersion,
		)
	}

	return response, nil
}

// RefreshNAT asks the daemon to classify its NAT now.
func (c *Client) RefreshNAT(ctx context.Context) (Netcheck, error) {
	response := Netcheck{}
	if err := c.do(ctx, http.MethodPost, "/v1/netcheck", nil, http.StatusOK, &response); err != nil {
		return Netcheck{}, err
	}
	if response.APIVersion != apiVersion {
		return Netcheck{}, fmt.Errorf("localapi: unsupported api version %q", response.APIVersion)
	}

	return response, nil
}

func (c *Client) do(
	ctx context.Context,
	method string,
	path string,
	requestBody any,
	expectedStatus int,
	responseBody any,
) error {
	if c == nil || c.httpClient == nil {
		return errors.New("localapi: client is not initialized")
	}

	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("localapi: encoding request: %w", err)
		}
		defer clear(encoded)
		body = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, baseURL+path, body)
	if err != nil {
		return fmt.Errorf("localapi: creating request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("localapi: calling daemon: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if err := validateContentType(response.Header.Get("Content-Type")); err != nil {
		return err
	}
	limited := io.LimitReader(response.Body, maxResponseBodyBytes+1)
	encoded, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("localapi: reading response: %w", err)
	}
	if len(encoded) > maxResponseBodyBytes {
		return fmt.Errorf("localapi: response exceeds %d bytes", maxResponseBodyBytes)
	}

	if response.StatusCode != expectedStatus {
		return decodeAPIError(response.StatusCode, encoded)
	}
	if err := json.Unmarshal(encoded, responseBody); err != nil {
		return fmt.Errorf("localapi: decoding response: %w", err)
	}

	return nil
}

func validateContentType(contentType string) error {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("localapi: unexpected content type %q", contentType)
	}

	return nil
}

func decodeAPIError(statusCode int, body []byte) error {
	response := errorResponse{}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("localapi: daemon returned http %d with an invalid error body", statusCode)
	}
	if response.Code == "" || response.Message == "" {
		return fmt.Errorf("localapi: daemon returned http %d without an error code", statusCode)
	}
	if response.APIVersion != apiVersion {
		return fmt.Errorf("localapi: daemon error uses unsupported api version %q", response.APIVersion)
	}

	return &APIError{
		StatusCode: statusCode,
		Code:       response.Code,
		Message:    response.Message,
	}
}

func isProfileID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		isDigit := r >= '0' && r <= '9'
		isLowerHex := r >= 'a' && r <= 'f'
		if !isDigit && !isLowerHex {
			return false
		}
	}

	return true
}

// CheckCaptiveWindow has meshd ask the helper about a captive portal window
// root just opened or closed.
func (c *Client) CheckCaptiveWindow(ctx context.Context) error {
	response := captiveCheckResponse{}
	if err := c.do(ctx, http.MethodPost, "/v1/exit/captive/check", nil, http.StatusOK, &response); err != nil {
		return err
	}
	if response.APIVersion != apiVersion {
		return fmt.Errorf("localapi: unsupported api version %q", response.APIVersion)
	}
	return nil
}
