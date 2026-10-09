package oidcauth

import "slices"

// MetadataParams is the security-relevant subset of OIDC discovery metadata.
type MetadataParams struct {
	Issuer                   string
	AuthorizationEndpoint    string
	TokenEndpoint            string
	JWKSURI                  string
	ResponseTypes            []string
	CodeChallengeMethods     []string
	IDTokenSigningAlgorithms []string
	TokenAuthMethods         []string
}

// Metadata is validated, immutable provider discovery evidence.
type Metadata struct {
	issuer                   string
	authorizationEndpoint    string
	tokenEndpoint            string
	jwksURI                  string
	responseTypes            []string
	codeChallengeMethods     []string
	idTokenSigningAlgorithms []string
	tokenAuthMethods         []string
}

// NewMetadata rejects insecure endpoints and unsupported browser-flow metadata.
func NewMetadata(params MetadataParams) (Metadata, error) {
	if !validHTTPSURL(params.Issuer, true) ||
		!validHTTPSURL(params.AuthorizationEndpoint, false) ||
		!validHTTPSURL(params.TokenEndpoint, false) ||
		!validHTTPSURL(params.JWKSURI, false) ||
		!validMetadataValues(params.ResponseTypes, 16, 64) ||
		!validMetadataValues(params.CodeChallengeMethods, 8, 64) ||
		!validMetadataValues(params.IDTokenSigningAlgorithms, 16, 64) ||
		!validMetadataValues(params.TokenAuthMethods, 16, 64) ||
		!slices.Contains(params.ResponseTypes, "code") ||
		!slices.Contains(params.CodeChallengeMethods, "S256") {
		return Metadata{}, ErrInvalidMetadata
	}
	return Metadata{
		issuer:                   params.Issuer,
		authorizationEndpoint:    params.AuthorizationEndpoint,
		tokenEndpoint:            params.TokenEndpoint,
		jwksURI:                  params.JWKSURI,
		responseTypes:            slices.Clone(params.ResponseTypes),
		codeChallengeMethods:     slices.Clone(params.CodeChallengeMethods),
		idTokenSigningAlgorithms: slices.Clone(params.IDTokenSigningAlgorithms),
		tokenAuthMethods:         slices.Clone(params.TokenAuthMethods),
	}, nil
}

// Issuer returns the exact discovered issuer.
func (metadata Metadata) Issuer() string { return metadata.issuer }

// AuthorizationEndpoint returns the exact validated authorization endpoint.
func (metadata Metadata) AuthorizationEndpoint() string {
	return metadata.authorizationEndpoint
}

// TokenEndpoint returns the exact validated token endpoint.
func (metadata Metadata) TokenEndpoint() string { return metadata.tokenEndpoint }

// JWKSURI returns the exact discovered signing-key endpoint.
func (metadata Metadata) JWKSURI() string { return metadata.jwksURI }

// IsValid reports whether metadata still satisfies browser-flow policy.
func (metadata Metadata) IsValid() bool {
	validated, err := NewMetadata(MetadataParams{
		Issuer: metadata.issuer, AuthorizationEndpoint: metadata.authorizationEndpoint,
		TokenEndpoint: metadata.tokenEndpoint, JWKSURI: metadata.jwksURI,
		ResponseTypes:            metadata.responseTypes,
		CodeChallengeMethods:     metadata.codeChallengeMethods,
		IDTokenSigningAlgorithms: metadata.idTokenSigningAlgorithms,
		TokenAuthMethods:         metadata.tokenAuthMethods,
	})
	return err == nil && slices.Equal(validated.responseTypes, metadata.responseTypes) &&
		slices.Equal(validated.codeChallengeMethods, metadata.codeChallengeMethods) &&
		slices.Equal(validated.idTokenSigningAlgorithms, metadata.idTokenSigningAlgorithms) &&
		slices.Equal(validated.tokenAuthMethods, metadata.tokenAuthMethods)
}

func validMetadataValues(values []string, maximumCount, maximumValueBytes int) bool {
	if len(values) == 0 || len(values) > maximumCount {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validBoundedToken(value, maximumValueBytes) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
