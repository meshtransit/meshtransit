// Package kubetoken verifies the pod-bound ServiceAccount token a
// Kubernetes gateway sends when it joins and when it rotates its keys (K1.1
// design §7.3). Verification is offline, against a JWKS the caller trusts;
// the package performs no I/O and never logs.
//
// It lives in an adapter, not in the domain, because it parses JOSE: the
// domain imports no protocol codecs.
package kubetoken

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"meshtransit.net/shared/kubejoin"
)

const (
	// Audience is the only audience a gateway token may carry.
	Audience = "meshtransit.net/kubernetes-gateway"
	// MaxTokenSize bounds a token as received.
	MaxTokenSize = kubejoin.MaxTokenSize
	// MaxLifetime bounds exp − iat: kubelet asks for 600 s.
	MaxLifetime = 15 * time.Minute
	// ClockSkew is how far ahead of Core's clock iat and nbf may be.
	ClockSkew = 30 * time.Second

	maxJTI         = 128
	maxUID         = 128
	subjectPrefix  = "system:serviceaccount:"
	earliestSecond = 1577836800 // 2020-01-01
	latestSecond   = 4102444800 // 2100-01-01
)

// ErrInvalidExpectation reports an Expectation that does not say what to
// compare: a caller error, not a refused token.
var ErrInvalidExpectation = errors.New("kubetoken: invalid expectation")

// Reason says why a token was refused. The set is closed: metrics and audit
// carry it.
type Reason string

// Reasons a token is refused.
const (
	ReasonMissing    Reason = "token_missing"
	ReasonMalformed  Reason = "token_malformed"
	ReasonUnknownKey Reason = "token_unknown_key"
	ReasonSignature  Reason = "token_signature"
	ReasonExpired    Reason = "token_expired"
	ReasonAudience   Reason = "token_audience"
	ReasonIdentity   Reason = "token_identity"
)

// RefusedError reports a refused token. It carries only the reason, never
// the token or its claims.
type RefusedError struct {
	Reason Reason
}

func (err *RefusedError) Error() string { return "kubetoken: token refused: " + string(err.Reason) }

func refuse(reason Reason) error { return &RefusedError{Reason: reason} }

// Expectation is what a token must match. Issuer and JWKS are always set.
// At a rotation the identity (Namespace, ServiceAccount, PodName) is the
// cluster's trust and the Device's bound pod; at a join it is all empty, and
// Verify returns the token's own identity.
type Expectation struct {
	Issuer         string
	JWKS           kubejoin.JWKS
	Namespace      string
	ServiceAccount string
	PodName        string
}

// comparesIdentity reports whether the expectation names an identity, and
// whether it is complete.
func (expect Expectation) comparesIdentity() (compares, valid bool) {
	if expect.Issuer == "" || expect.JWKS.IsZero() {
		return false, false
	}
	set := 0
	for _, value := range []string{expect.Namespace, expect.ServiceAccount, expect.PodName} {
		if value != "" {
			set++
		}
	}
	return set == 3, set == 0 || set == 3
}

// Claims is what a verified token says.
type Claims struct {
	Issuer         string
	Namespace      string
	ServiceAccount string
	PodName        string
	PodUID         string
	JTI            string
	IssuedAt       time.Time
	NotBefore      time.Time
	Expiry         time.Time
	// KeyThumbprint is the RFC 7638 thumbprint of the key that signed.
	KeyThumbprint [32]byte
}

// Verify checks raw, a compact JWS, against expect at time now (design
// §7.3) and returns its claims. A refused token gives a *RefusedError; an
// incomplete expectation gives ErrInvalidExpectation, which a rotation
// caller reports as trust_missing (a Device without trust or bound pod).
func Verify(raw string, expect Expectation, now time.Time) (Claims, error) {
	comparesIdentity, valid := expect.comparesIdentity()
	if !valid {
		return Claims{}, ErrInvalidExpectation
	}
	if raw == "" {
		return Claims{}, refuse(ReasonMissing)
	}
	if len(raw) > MaxTokenSize {
		return Claims{}, refuse(ReasonMalformed)
	}
	segments := strings.Split(raw, ".")
	if len(segments) != 3 {
		return Claims{}, refuse(ReasonMalformed)
	}
	headerJSON, headerErr := decodeSegment(segments[0])
	signedPayload, payloadErr := decodeSegment(segments[1])
	signature, signatureErr := decodeSegment(segments[2])
	if headerErr != nil || payloadErr != nil || signatureErr != nil || len(signature) == 0 {
		return Claims{}, refuse(ReasonMalformed)
	}
	algorithm, keyID, err := readHeader(headerJSON)
	if err != nil {
		return Claims{}, err
	}
	key, found := expect.JWKS.Key(keyID)
	if !found {
		return Claims{}, refuse(ReasonUnknownKey)
	}
	if key.Algorithm != algorithm {
		return Claims{}, refuse(ReasonSignature)
	}
	object, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(algorithm)})
	if err != nil || len(object.Signatures) != 1 {
		return Claims{}, refuse(ReasonMalformed)
	}
	// The key is the trusted one, chosen by kid; never one the header
	// carries (readHeader refused those).
	payload, err := object.Verify(key.Public)
	if err != nil || !bytes.Equal(payload, signedPayload) {
		return Claims{}, refuse(ReasonSignature)
	}
	claims, err := readClaims(payload)
	if err != nil {
		return Claims{}, err
	}
	claims.KeyThumbprint = key.Thumbprint
	if err := checkTimes(claims, now); err != nil {
		return Claims{}, err
	}
	if claims.Issuer != expect.Issuer {
		return Claims{}, refuse(ReasonIdentity)
	}
	if comparesIdentity && (claims.Namespace != expect.Namespace || claims.ServiceAccount != expect.ServiceAccount ||
		claims.PodName != expect.PodName) {
		return Claims{}, refuse(ReasonIdentity)
	}
	return claims, nil
}

// decodeSegment decodes strict unpadded base64url. The decoder skips line
// breaks, so the segment must also be the decoded bytes' only spelling.
func decodeSegment(segment string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(segment)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != segment {
		return nil, errMalformedSegment
	}
	return decoded, nil
}

var errMalformedSegment = errors.New("kubetoken: malformed segment")

// readHeader reads the protected header itself: go-jose spreads members it
// knows over several fields and keeps others, so an allowlist is only sound
// on the raw JSON. Only alg, kid and typ ("JWT") may appear.
func readHeader(headerJSON []byte) (algorithm, keyID string, err error) {
	if kubejoin.CheckStrictJSON(headerJSON) != nil {
		return "", "", refuse(ReasonMalformed)
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(headerJSON, &members) != nil {
		return "", "", refuse(ReasonMalformed)
	}
	values := map[string]string{}
	for name, raw := range members {
		if name != "alg" && name != "kid" && name != "typ" {
			return "", "", refuse(ReasonMalformed)
		}
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return "", "", refuse(ReasonMalformed)
		}
		values[name] = value
	}
	algorithm, keyID = values["alg"], values["kid"]
	if typ, present := values["typ"]; present && typ != "JWT" {
		return "", "", refuse(ReasonMalformed)
	}
	if (algorithm != kubejoin.AlgorithmRS256 && algorithm != kubejoin.AlgorithmES256) || keyID == "" {
		return "", "", refuse(ReasonMalformed)
	}
	return algorithm, keyID, nil
}

// tokenClaims are the members a pod-bound token must carry. Others (node,
// warnafter) are ignored.
type tokenClaims struct {
	Issuer     *string         `json:"iss"`
	Subject    *string         `json:"sub"`
	Audience   json.RawMessage `json:"aud"`
	IssuedAt   json.RawMessage `json:"iat"`
	NotBefore  json.RawMessage `json:"nbf"`
	Expiry     json.RawMessage `json:"exp"`
	JTI        *string         `json:"jti"`
	Kubernetes *struct {
		Namespace      *string     `json:"namespace"`
		Pod            *objectName `json:"pod"`
		ServiceAccount *objectName `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

type objectName struct {
	Name *string `json:"name"`
	UID  *string `json:"uid"`
}

func (name *objectName) complete() bool {
	return name != nil && name.Name != nil && *name.Name != "" && name.UID != nil && *name.UID != ""
}

// readClaims reads and checks the claims' form: every required member, a
// token bound to a pod, a subject that agrees with the claims beside it.
func readClaims(payload []byte) (Claims, error) {
	if kubejoin.CheckStrictJSON(payload) != nil {
		return Claims{}, refuse(ReasonMalformed)
	}
	var token tokenClaims
	if json.Unmarshal(payload, &token) != nil {
		return Claims{}, refuse(ReasonMalformed)
	}
	kubernetes := token.Kubernetes
	if token.Issuer == nil || token.Subject == nil || token.JTI == nil || token.Audience == nil ||
		kubernetes == nil || kubernetes.Namespace == nil || !kubernetes.Pod.complete() ||
		!kubernetes.ServiceAccount.complete() || !printable(*token.JTI, maxJTI) ||
		!printable(*kubernetes.Pod.UID, maxUID) || !kubejoin.ValidNamespace(*kubernetes.Namespace) ||
		!kubejoin.ValidName(*kubernetes.ServiceAccount.Name) || !kubejoin.ValidName(*kubernetes.Pod.Name) {
		return Claims{}, refuse(ReasonMalformed)
	}
	// The audience first: a token meant for the API server (often long-lived)
	// is the likeliest mistake, and must be reported as such.
	if err := checkAudience(token.Audience); err != nil {
		return Claims{}, err
	}
	issuedAt, iatErr := numericDate(token.IssuedAt)
	notBefore, nbfErr := numericDate(token.NotBefore)
	expiry, expErr := numericDate(token.Expiry)
	if iatErr != nil || nbfErr != nil || expErr != nil || issuedAt.After(expiry) || notBefore.After(expiry) ||
		expiry.Sub(issuedAt) > MaxLifetime {
		return Claims{}, refuse(ReasonMalformed)
	}
	namespace, account, ok := strings.Cut(strings.TrimPrefix(*token.Subject, subjectPrefix), ":")
	if !ok || !strings.HasPrefix(*token.Subject, subjectPrefix) || namespace != *kubernetes.Namespace ||
		account != *kubernetes.ServiceAccount.Name {
		return Claims{}, refuse(ReasonMalformed)
	}
	return Claims{
		Issuer: *token.Issuer, Namespace: namespace, ServiceAccount: account,
		PodName: *kubernetes.Pod.Name, PodUID: *kubernetes.Pod.UID, JTI: *token.JTI,
		IssuedAt: issuedAt, NotBefore: notBefore, Expiry: expiry,
	}, nil
}

// checkAudience accepts the audience as a string or an array holding exactly
// Audience.
func checkAudience(raw json.RawMessage) error {
	if string(raw) == "null" {
		return refuse(ReasonMalformed)
	}
	var single string
	if json.Unmarshal(raw, &single) == nil {
		if single != Audience {
			return refuse(ReasonAudience)
		}
		return nil
	}
	var list []string
	if json.Unmarshal(raw, &list) != nil {
		return refuse(ReasonMalformed)
	}
	if len(list) != 1 || list[0] != Audience {
		return refuse(ReasonAudience)
	}
	return nil
}

// numericDate reads a JSON integer of seconds between 2020 and 2100. go-jose
// reads dates as floats and truncates them; a token never needs either.
func numericDate(raw json.RawMessage) (time.Time, error) {
	text := string(raw)
	if text == "" || len(text) > 10 || strings.Trim(text, "0123456789") != "" {
		return time.Time{}, refuse(ReasonMalformed)
	}
	seconds, err := strconv.ParseInt(text, 10, 64)
	if err != nil || seconds < earliestSecond || seconds > latestSecond {
		return time.Time{}, refuse(ReasonMalformed)
	}
	return time.Unix(seconds, 0).UTC(), nil
}

// checkTimes refuses a token that is not valid at now, by Core's clock.
func checkTimes(claims Claims, now time.Time) error {
	latest := now.Add(ClockSkew)
	if !claims.Expiry.After(now) || claims.NotBefore.After(latest) || claims.IssuedAt.After(latest) {
		return refuse(ReasonExpired)
	}
	return nil
}

// printable reports whether value is 1 to limit printable ASCII characters
// other than space. The jti is part of a primary key; the pod UID goes into
// audit.
func printable(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}
