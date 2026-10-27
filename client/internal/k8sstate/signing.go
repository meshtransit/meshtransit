package k8sstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"meshtransit.net/shared/kubejoin"
)

// maxSigningBytes bounds the discovery document and the JWKS: Core accepts
// a JWKS of 16 KiB at most (kubejoin.MaxJWKSSize).
const maxSigningBytes = kubejoin.MaxJWKSSize

// ReadSigningKeys reads the cluster's ServiceAccount token issuer and its
// public keys (JWKS), as the API server serves them, with the pod's token:
// any ServiceAccount may read them through the issuer discovery binding. A
// K1 gateway sends both with its join (K1.1); Core verifies its pod token
// against them, and the administrator's code anchors them.
func ReadSigningKeys(ctx context.Context, cfg Config) (issuer string, jwks []byte, err error) {
	client, err := newAPIClient(cfg)
	if err != nil {
		return "", nil, err
	}
	defer client.close()
	discovery, err := client.getRaw(ctx, "/.well-known/openid-configuration", "application/json")
	if err != nil {
		return "", nil, err
	}
	var document struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(discovery, &document); err != nil || document.Issuer == "" {
		return "", nil, errors.New("k8sstate: the API server's discovery document names no issuer")
	}
	jwks, err = client.getRaw(ctx, "/openid/v1/jwks", "application/jwk-set+json, application/json")
	if err != nil {
		return "", nil, err
	}
	return document.Issuer, jwks, nil
}

// getRaw GETs path from the API server, bounded, with the pod's token.
// accept names the media types to ask for: the API server answers 406 to a
// JWKS request that does not accept application/jwk-set+json.
func (c *apiClient) getRaw(ctx context.Context, path, accept string) ([]byte, error) {
	if c.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.cfg.Timeout)
		defer cancel()
	}
	token, err := os.ReadFile(c.cfg.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("k8sstate: reading the service account token: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(c.cfg.Server, "/")+path, nil)
	if err != nil {
		return nil, fmt.Errorf("k8sstate: building the request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	request.Header.Set("Accept", accept)
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("k8sstate: GET %s: %w", path, err)
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxSigningBytes+1))
	if err != nil {
		return nil, fmt.Errorf("k8sstate: reading %s: %w", path, err)
	}
	switch {
	case response.StatusCode == http.StatusUnauthorized:
		return nil, fmt.Errorf("k8sstate: the API server refused the pod's default token for %s (%s)", path,
			statusMessage(payload))
	case response.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("k8sstate: the pod may not read %s: grant its ServiceAccount the "+
			"system:service-account-issuer-discovery ClusterRole (%s)", path, statusMessage(payload))
	case response.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("k8sstate: GET %s answered %d (%s)", path, response.StatusCode, statusMessage(payload))
	case len(payload) > maxSigningBytes:
		return nil, fmt.Errorf("k8sstate: %s is larger than %d bytes", path, maxSigningBytes)
	}
	return payload, nil
}
