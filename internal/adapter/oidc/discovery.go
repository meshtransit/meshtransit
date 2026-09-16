// Package oidc implements the replaceable external OIDC provider boundary.
package oidc

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

const (
	defaultDiscoveryTimeout     = 5 * time.Second
	defaultMaximumMetadataBytes = 64 * 1024
	maximumDiscoveryTimeout     = 30 * time.Second
	maximumMetadataBytes        = 256 * 1024
)

var (
	// ErrInvalidResolver reports unsafe discovery client construction.
	ErrInvalidResolver = errors.New("oidc discovery: invalid resolver")
	// ErrDiscoveryUnavailable classifies transport and provider failures.
	ErrDiscoveryUnavailable = errors.New("oidc discovery: unavailable")
	// ErrInvalidDiscoveryResponse classifies untrusted or malformed metadata.
	ErrInvalidDiscoveryResponse = errors.New("oidc discovery: invalid response")
)

// Options bounds provider metadata I/O and parsing.
type Options struct {
	Timeout          time.Duration
	MaxMetadataBytes int64
}

type doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Resolver fetches only the exact discovery URI selected by Core authority.
type Resolver struct {
	client           doer
	maxMetadataBytes int64
}

// NewResolver constructs a TLS-only, no-proxy, no-redirect discovery client.
func NewResolver(options Options) (*Resolver, error) {
	if options.Timeout == 0 {
		options.Timeout = defaultDiscoveryTimeout
	}
	if options.MaxMetadataBytes == 0 {
		options.MaxMetadataBytes = defaultMaximumMetadataBytes
	}
	if options.Timeout <= 0 || options.Timeout > maximumDiscoveryTimeout ||
		options.MaxMetadataBytes <= 0 || options.MaxMetadataBytes > maximumMetadataBytes {
		return nil, ErrInvalidResolver
	}
	dialer := &net.Dialer{Timeout: options.Timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		MaxIdleConns:           16,
		MaxIdleConnsPerHost:    4,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    options.Timeout,
		ResponseHeaderTimeout:  options.Timeout,
		MaxResponseHeaderBytes: 64 * 1024,
		ExpectContinueTimeout:  time.Second,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   options.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Resolver{client: client, maxMetadataBytes: options.MaxMetadataBytes}, nil
}

func newResolver(client doer, maxMetadataBytes int64) (*Resolver, error) {
	if client == nil || maxMetadataBytes <= 0 || maxMetadataBytes > maximumMetadataBytes {
		return nil, ErrInvalidResolver
	}
	return &Resolver{client: client, maxMetadataBytes: maxMetadataBytes}, nil
}

// Resolve validates discovery metadata against one exact configured route.
func (resolver *Resolver) Resolve(
	ctx context.Context,
	route oidcauth.Route,
) (oidcauth.Metadata, error) {
	if ctx == nil || resolver == nil || resolver.client == nil ||
		resolver.maxMetadataBytes <= 0 || !route.IsValid() {
		return oidcauth.Metadata{}, ErrInvalidResolver
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, route.DiscoveryURI(), nil)
	if err != nil {
		return oidcauth.Metadata{}, ErrInvalidResolver
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "meshcore-oidc-discovery/1")
	response, err := resolver.client.Do(request)
	if err != nil {
		return oidcauth.Metadata{}, fmt.Errorf("%w: %w", ErrDiscoveryUnavailable, err)
	}
	if response == nil || response.Body == nil {
		return oidcauth.Metadata{}, ErrDiscoveryUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || !isJSONContentType(response.Header.Get("Content-Type")) {
		return oidcauth.Metadata{}, ErrInvalidDiscoveryResponse
	}
	limited := io.LimitReader(response.Body, resolver.maxMetadataBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return oidcauth.Metadata{}, fmt.Errorf("%w: %w", ErrDiscoveryUnavailable, err)
	}
	if int64(len(body)) > resolver.maxMetadataBytes {
		return oidcauth.Metadata{}, ErrInvalidDiscoveryResponse
	}
	params, err := decodeMetadata(body)
	if err != nil {
		return oidcauth.Metadata{}, err
	}
	metadata, err := oidcauth.NewMetadata(params)
	if err != nil || metadata.Issuer() != route.Issuer() ||
		metadata.AuthorizationEndpoint() != route.AuthorizationEndpoint() ||
		metadata.TokenEndpoint() != route.TokenEndpoint() ||
		metadata.JWKSURI() != route.JWKSURI() {
		return oidcauth.Metadata{}, ErrInvalidDiscoveryResponse
	}
	return metadata, nil
}

func decodeMetadata(body []byte) (oidcauth.MetadataParams, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return oidcauth.MetadataParams{}, ErrInvalidDiscoveryResponse
	}
	values := make(map[string]json.RawMessage)
	for decoder.More() {
		nameToken, err := decoder.Token()
		name, ok := nameToken.(string)
		if err != nil || !ok {
			return oidcauth.MetadataParams{}, ErrInvalidDiscoveryResponse
		}
		if _, exists := values[name]; exists {
			return oidcauth.MetadataParams{}, ErrInvalidDiscoveryResponse
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return oidcauth.MetadataParams{}, ErrInvalidDiscoveryResponse
		}
		values[name] = raw
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return oidcauth.MetadataParams{}, ErrInvalidDiscoveryResponse
	}
	if token, err = decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return oidcauth.MetadataParams{}, ErrInvalidDiscoveryResponse
	}
	var params oidcauth.MetadataParams
	if !decodeRequired(values, "issuer", &params.Issuer) ||
		!decodeRequired(values, "authorization_endpoint", &params.AuthorizationEndpoint) ||
		!decodeRequired(values, "token_endpoint", &params.TokenEndpoint) ||
		!decodeRequired(values, "jwks_uri", &params.JWKSURI) ||
		!decodeRequired(values, "response_types_supported", &params.ResponseTypes) ||
		!decodeRequired(values, "code_challenge_methods_supported", &params.CodeChallengeMethods) ||
		!decodeRequired(
			values,
			"id_token_signing_alg_values_supported",
			&params.IDTokenSigningAlgorithms,
		) ||
		!decodeRequired(
			values,
			"token_endpoint_auth_methods_supported",
			&params.TokenAuthMethods,
		) {
		return oidcauth.MetadataParams{}, ErrInvalidDiscoveryResponse
	}
	return params, nil
}

func decodeRequired[T any](values map[string]json.RawMessage, name string, target *T) bool {
	raw, exists := values[name]
	return exists && json.Unmarshal(raw, target) == nil
}

func isJSONContentType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil || mediaType != "application/json" {
		return false
	}
	for name, parameter := range parameters {
		if name != "charset" || !strings.EqualFold(parameter, "utf-8") {
			return false
		}
	}
	return true
}
