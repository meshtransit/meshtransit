package kubetoken

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
)

// GatewayAudience is the audience of the token a gateway shows Core: a
// token for it is not an API server token.
const GatewayAudience = "meshtransit.net/kubernetes-gateway"

// maximumTokenFile bounds a token file read for its claims.
const maximumTokenFile = 64 << 10

// Errors of ReadAudiences.
var (
	ErrNoAudiences   = errors.New("kubetoken: the token names no audience")
	ErrNotAPIToken   = errors.New("kubetoken: the token is the gateway's token for Core, not an API server token")
	errNotJWT        = errors.New("kubetoken: the token is not a JWT")
	errClaimsNotJSON = errors.New("kubetoken: the token's claims are not JSON")
)

// ReadAudiences reads the aud claim of a ServiceAccount token for the API
// server, as a pod's automounted one: the audiences the API server fills
// into every token it mints without any (K1c §7 c2). The claims are read,
// not verified; the token is never returned or logged, and only the decoded
// claims are held past the read.
func ReadAudiences(path string) ([]string, error) {
	file, err := os.Open(path) //nolint:gosec // G304: a mounted ServiceAccount token
	if err != nil {
		return nil, fmt.Errorf("kubetoken: reading the token: %w", err)
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, maximumTokenFile+1))
	defer clear(raw)
	if err != nil {
		return nil, fmt.Errorf("kubetoken: reading the token: %w", err)
	}
	if len(raw) > maximumTokenFile {
		return nil, errors.New("kubetoken: the token file is too large")
	}
	token := bytes.TrimSpace(raw)
	first := bytes.IndexByte(token, '.')
	last := bytes.LastIndexByte(token, '.')
	if first < 1 || last <= first+1 || last == len(token)-1 {
		return nil, errNotJWT
	}
	payload := make([]byte, base64.RawURLEncoding.DecodedLen(last-first-1))
	n, err := base64.RawURLEncoding.Decode(payload, token[first+1:last])
	if err != nil {
		return nil, errNotJWT
	}
	var claims struct {
		Audience json.RawMessage `json:"aud"`
	}
	if json.Unmarshal(payload[:n], &claims) != nil {
		return nil, errClaimsNotJSON
	}
	audiences, err := audienceList(claims.Audience)
	if err != nil {
		return nil, err
	}
	if slices.Contains(audiences, GatewayAudience) {
		return nil, ErrNotAPIToken
	}
	return audiences, nil
}

// audienceList reads aud: a string or a list of them (RFC 7519 §4.1.3).
func audienceList(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, ErrNoAudiences
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		if one == "" {
			return nil, ErrNoAudiences
		}
		return []string{one}, nil
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil || len(many) == 0 || slices.Contains(many, "") {
		return nil, ErrNoAudiences
	}
	return many, nil
}

// SameAudiences reports two audience lists equal as sets: the API server
// keeps its own order, a chart its values' (K1c Q91).
func SameAudiences(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}
