package kubejoin

import (
	"bytes"
	"cmp"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"
)

// A replica's trust is the ServiceAccount signing material its pod sends
// when it joins (K1.1 design §6): the cluster's issuer and public keys
// (JWKS), and the namespace, ServiceAccount and pod its token names. The
// join code v2 binds a digest of it, so an administrator who reads the code
// from the real pod cannot anchor keys someone else attached.

var (
	// ErrInvalidJWKS reports a JWKS outside the accepted form (design §7.3).
	// The wrapping error names the rule broken, never the input.
	ErrInvalidJWKS = errors.New("kubejoin: invalid JWKS")
	// ErrInvalidTrust reports trust material that cannot be digested.
	ErrInvalidTrust = errors.New("kubejoin: invalid trust")
	// ErrInvalidJSON reports text that is not exactly one JSON value, or an
	// object naming a member twice.
	ErrInvalidJSON = errors.New("kubejoin: invalid JSON")
)

const (
	// MaxJWKSSize bounds a JWKS as received, before canonicalization.
	MaxJWKSSize = 16 << 10
	// MaxTokenSize bounds a pod's ServiceAccount token as sent and received.
	MaxTokenSize = 8 << 10
	// MaxSigningKeys bounds the keys of one JWKS.
	MaxSigningKeys = 8
	// MaxIssuerSize bounds an issuer URL.
	MaxIssuerSize = 255

	// AlgorithmRS256 is RSASSA-PKCS1-v1_5 with SHA-256.
	AlgorithmRS256 = "RS256"
	// AlgorithmES256 is ECDSA on P-256 with SHA-256.
	AlgorithmES256 = "ES256"

	trustLabel   = "meshtransit/kube-sa-trust/v1"
	labelV2      = "meshtransit/kube-join-code/v2"
	maxKeyID     = 128
	minRSABits   = 2048
	maxRSABits   = 4096
	ecCoordSize  = 32
	maxLabel     = 63
	maxSubdomain = 253
)

// rsaExponent is 65537, the only public exponent accepted.
var rsaExponent = []byte{1, 0, 1}

func invalidJWKS(rule string) error { return fmt.Errorf("%w: %s", ErrInvalidJWKS, rule) }

// SigningKey is one public key of a JWKS.
type SigningKey struct {
	ID        string
	Algorithm string
	// Thumbprint is the key's RFC 7638 SHA-256 thumbprint.
	Thumbprint [32]byte
	// Public is a *rsa.PublicKey or a *ecdsa.PublicKey.
	Public crypto.PublicKey
}

// JWKS is a set of signing keys in canonical form (kube-sa-trust/v1):
// public members only, sorted by key ID, members in lexicographic order, no
// whitespace, and strings escaped only where JSON requires it (no HTML
// escaping). The zero JWKS has no keys.
type JWKS struct {
	canonical []byte
	keys      []SigningKey
}

// IsZero reports whether the JWKS holds no keys.
func (jwks JWKS) IsZero() bool { return len(jwks.keys) == 0 }

// Canonical returns a copy of the canonical JSON.
func (jwks JWKS) Canonical() []byte { return bytes.Clone(jwks.canonical) }

// Keys returns a copy of the keys, sorted by ID.
func (jwks JWKS) Keys() []SigningKey { return slices.Clone(jwks.keys) }

// Key returns the key named id.
func (jwks JWKS) Key(id string) (SigningKey, bool) {
	index := slices.IndexFunc(jwks.keys, func(key SigningKey) bool { return key.ID == id })
	if index < 0 {
		return SigningKey{}, false
	}
	return jwks.keys[index], true
}

// Members of a JWK: those kept in the canonical form and those dropped.
// Any other member, private ones included, refuses the key.
var (
	keptMembers    = []string{"kty", "kid", "alg", "use", "n", "e", "crv", "x", "y"}
	droppedMembers = []string{"x5c", "x5t", "x5t#S256", "x5u"}
)

// canonicalKey is a JWK as the canonical form writes it: members in
// lexicographic order.
type canonicalKey struct {
	Alg string `json:"alg"`
	Crv string `json:"crv,omitempty"`
	E   string `json:"e,omitempty"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// ParseJWKS reads a JWKS as a cluster serves it (`/openid/v1/jwks`) and
// returns its canonical form. It accepts RSA keys of 2048 to 4096 bits with
// exponent 65537 for RS256, and P-256 keys for ES256; every binary member is
// strict unpadded base64url with no leading zero bytes in the modulus.
func ParseJWKS(raw []byte) (JWKS, error) {
	if len(raw) > MaxJWKSSize {
		return JWKS{}, invalidJWKS("larger than 16 KiB")
	}
	if err := CheckStrictJSON(raw); err != nil {
		return JWKS{}, invalidJWKS("not one JSON value with distinct member names")
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil || len(document) != 1 || document["keys"] == nil {
		return JWKS{}, invalidJWKS(`not an object with only "keys"`)
	}
	var members []map[string]json.RawMessage
	if err := json.Unmarshal(document["keys"], &members); err != nil {
		return JWKS{}, invalidJWKS(`"keys" is not an array of objects`)
	}
	if len(members) == 0 || len(members) > MaxSigningKeys {
		return JWKS{}, invalidJWKS("not 1 to 8 keys")
	}
	keys := make([]SigningKey, 0, len(members))
	written := make([]canonicalKey, 0, len(members))
	for _, member := range members {
		key, canonical, err := parseKey(member)
		if err != nil {
			return JWKS{}, err
		}
		if _, found := (JWKS{keys: keys}).Key(key.ID); found {
			return JWKS{}, invalidJWKS("two keys share a kid")
		}
		keys = append(keys, key)
		written = append(written, canonical)
	}
	slices.SortFunc(keys, func(a, b SigningKey) int { return cmp.Compare(a.ID, b.ID) })
	slices.SortFunc(written, func(a, b canonicalKey) int { return cmp.Compare(a.Kid, b.Kid) })
	canonical, err := encodeCanonical(written)
	if err != nil {
		return JWKS{}, invalidJWKS("cannot be encoded")
	}
	return JWKS{canonical: canonical, keys: keys}, nil
}

// encodeCanonical writes the keys without HTML escaping, so any JSON
// encoder that escapes only what JSON requires writes the same bytes.
func encodeCanonical(keys []canonicalKey) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(struct {
		Keys []canonicalKey `json:"keys"`
	}{Keys: keys}); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

func parseKey(member map[string]json.RawMessage) (SigningKey, canonicalKey, error) {
	for name := range member {
		if !slices.Contains(keptMembers, name) && !slices.Contains(droppedMembers, name) {
			return SigningKey{}, canonicalKey{}, invalidJWKS("a key has a member that is private or unknown")
		}
	}
	values := map[string]string{}
	for _, name := range keptMembers {
		raw, present := member[name]
		if !present {
			continue
		}
		var value *string
		if err := json.Unmarshal(raw, &value); err != nil || value == nil {
			return SigningKey{}, canonicalKey{}, invalidJWKS("a key member is not a string")
		}
		values[name] = *value
	}
	if use, present := values["use"]; present && use != "sig" {
		return SigningKey{}, canonicalKey{}, invalidJWKS(`a key's "use" is not "sig"`)
	}
	kid := values["kid"]
	if !printable(kid, maxKeyID) {
		return SigningKey{}, canonicalKey{}, invalidJWKS("a kid is not 1 to 128 printable characters")
	}
	switch values["kty"] {
	case "RSA":
		return parseRSAKey(kid, values)
	case "EC":
		return parseECKey(kid, values)
	default:
		return SigningKey{}, canonicalKey{}, invalidJWKS(`a key's "kty" is neither "RSA" nor "EC"`)
	}
}

func parseRSAKey(kid string, values map[string]string) (SigningKey, canonicalKey, error) {
	if !onlyMembers(values, "kty", "kid", "alg", "use", "n", "e") {
		return SigningKey{}, canonicalKey{}, invalidJWKS("an RSA key has EC members")
	}
	if !algorithmIs(values, AlgorithmRS256) {
		return SigningKey{}, canonicalKey{}, invalidJWKS(`an RSA key's "alg" is not "RS256"`)
	}
	modulus, err := decodeMember(values["n"])
	if err != nil || len(modulus) == 0 || modulus[0] == 0 {
		return SigningKey{}, canonicalKey{}, invalidJWKS("an RSA modulus is not minimal base64url")
	}
	exponent, err := decodeMember(values["e"])
	if err != nil || !bytes.Equal(exponent, rsaExponent) {
		return SigningKey{}, canonicalKey{}, invalidJWKS("an RSA exponent is not 65537")
	}
	n := new(big.Int).SetBytes(modulus)
	if n.BitLen() < minRSABits || n.BitLen() > maxRSABits {
		return SigningKey{}, canonicalKey{}, invalidJWKS("an RSA key is not 2048 to 4096 bits")
	}
	// crypto/rsa refuses an even modulus when it verifies: trusting one
	// would refuse every token later.
	if n.Bit(0) == 0 {
		return SigningKey{}, canonicalKey{}, invalidJWKS("an RSA modulus is even")
	}
	canonical := canonicalKey{Alg: AlgorithmRS256, E: values["e"], Kid: kid, Kty: "RSA", N: values["n"]}
	// RFC 7638 §3.2: the required members, in lexicographic order, no
	// whitespace. Base64url strings need no JSON escaping.
	thumbprint := sha256.Sum256([]byte(`{"e":"` + canonical.E + `","kty":"RSA","n":"` + canonical.N + `"}`))
	return SigningKey{
		ID: kid, Algorithm: AlgorithmRS256, Thumbprint: thumbprint,
		Public: &rsa.PublicKey{N: n, E: 65537},
	}, canonical, nil
}

func parseECKey(kid string, values map[string]string) (SigningKey, canonicalKey, error) {
	if !onlyMembers(values, "kty", "kid", "alg", "use", "crv", "x", "y") {
		return SigningKey{}, canonicalKey{}, invalidJWKS("an EC key has RSA members")
	}
	if !algorithmIs(values, AlgorithmES256) || values["crv"] != "P-256" {
		return SigningKey{}, canonicalKey{}, invalidJWKS(`an EC key is not P-256 with "alg" "ES256"`)
	}
	x, xErr := decodeMember(values["x"])
	y, yErr := decodeMember(values["y"])
	if xErr != nil || yErr != nil || len(x) != ecCoordSize || len(y) != ecCoordSize {
		return SigningKey{}, canonicalKey{}, invalidJWKS("an EC coordinate is not 32 bytes of base64url")
	}
	point := append(append([]byte{4}, x...), y...)
	public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return SigningKey{}, canonicalKey{}, invalidJWKS("an EC point is not on P-256")
	}
	canonical := canonicalKey{Alg: AlgorithmES256, Crv: "P-256", Kid: kid, Kty: "EC", X: values["x"], Y: values["y"]}
	thumbprint := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + canonical.X + `","y":"` + canonical.Y + `"}`))
	return SigningKey{ID: kid, Algorithm: AlgorithmES256, Thumbprint: thumbprint, Public: public}, canonical, nil
}

// onlyMembers reports whether values holds no member but allowed.
func onlyMembers(values map[string]string, allowed ...string) bool {
	for name := range values {
		if !slices.Contains(allowed, name) {
			return false
		}
	}
	return true
}

// algorithmIs reports whether the key's alg is absent or want.
func algorithmIs(values map[string]string, want string) bool {
	alg, present := values["alg"]
	return !present || alg == want
}

// decodeMember decodes strict unpadded base64url: other spellings of the
// same bytes, line breaks included, would give the key another thumbprint.
func decodeMember(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidJWKS
	}
	return decoded, nil
}

// printable reports whether value is 1 to limit printable ASCII characters
// other than space.
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

// CheckStrictJSON reads raw as exactly one JSON value and refuses an object
// that names a member twice, even in another letter case: decoders keep one
// of the two silently, and encoding/json matches names ignoring case, so two
// readers of the same bytes could see different values.
func CheckStrictJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	type frame struct {
		object bool
		names  []string
		// expectName is whether the next token of an object is a member name.
		expectName bool
	}
	var stack []*frame
	read := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ErrInvalidJSON
		}
		read = true
		top := (*frame)(nil)
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.object && top.expectName {
			if name, isName := token.(string); isName {
				if slices.ContainsFunc(top.names, func(seen string) bool { return strings.EqualFold(seen, name) }) {
					return ErrInvalidJSON
				}
				top.names = append(top.names, name)
				top.expectName = false
				continue
			}
		}
		if top != nil && top.object {
			top.expectName = true
		}
		switch token {
		case json.Delim('{'):
			stack = append(stack, &frame{object: true, expectName: true})
		case json.Delim('['):
			stack = append(stack, &frame{})
		case json.Delim('}'), json.Delim(']'):
			stack = stack[:len(stack)-1]
			if len(stack) > 0 && stack[len(stack)-1].object {
				stack[len(stack)-1].expectName = true
			}
		}
		if len(stack) == 0 && decoder.More() {
			return ErrInvalidJSON // a second top-level value
		}
	}
	if !read || len(stack) != 0 {
		return ErrInvalidJSON // no value, or one cut short
	}
	return nil
}

// Trust is what a replica's join binds besides its keys (design §6.2).
type Trust struct {
	Issuer         string
	JWKS           JWKS
	Namespace      string
	ServiceAccount string
	PodName        string
}

// StatefulSetOf returns the StatefulSet a pod name belongs to: the name
// without its "-<ordinal>" suffix, itself a valid name. A name with no
// ordinal has none.
func StatefulSetOf(pod string) (string, bool) {
	cut := strings.LastIndexByte(pod, '-')
	if cut <= 0 || cut == len(pod)-1 {
		return "", false
	}
	ordinal := pod[cut+1:]
	if len(ordinal) > 1 && ordinal[0] == '0' {
		return "", false
	}
	for index := range len(ordinal) {
		if ordinal[index] < '0' || ordinal[index] > '9' {
			return "", false
		}
	}
	if !ValidName(pod[:cut]) {
		return "", false
	}
	return pod[:cut], true
}

// TrustDigest digests a replica's trust (design §6.2):
//
//	SHA-256(label || 0x00 || u16 issuer || u32 JWKS || u16 namespace
//	        || u16 ServiceAccount || u16 pod)
//
// with each length big-endian before its bytes and the JWKS canonical.
func TrustDigest(trust Trust) ([32]byte, error) {
	if trust.JWKS.IsZero() || len(trust.JWKS.canonical) > MaxJWKSSize || !ValidIssuer(trust.Issuer) ||
		!ValidNamespace(trust.Namespace) || !ValidName(trust.ServiceAccount) || !ValidName(trust.PodName) {
		return [32]byte{}, ErrInvalidTrust
	}
	if _, ok := StatefulSetOf(trust.PodName); !ok {
		return [32]byte{}, ErrInvalidTrust
	}
	hash := sha256.New()
	hash.Write([]byte(trustLabel))
	hash.Write([]byte{0})
	writeU16(hash, trust.Issuer)
	hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(trust.JWKS.canonical)))) //nolint:gosec // G115: at most MaxJWKSSize
	hash.Write(trust.JWKS.canonical)
	writeU16(hash, trust.Namespace)
	writeU16(hash, trust.ServiceAccount)
	writeU16(hash, trust.PodName)
	return [32]byte(hash.Sum(nil)), nil
}

func writeU16(writer io.Writer, value string) {
	_, _ = writer.Write(binary.BigEndian.AppendUint16(nil, uint16(len(value)))) //nolint:gosec // G115: at most maxSubdomain
	_, _ = io.WriteString(writer, value)
}

// ValidIssuer reports whether issuer is an https URL the schema accepts
// (design §8.1): at most 255 bytes of printable ASCII, "https://", a host of
// letters, digits, dots and hyphens, an optional numeric port, and an
// optional path; no user, query or fragment. Issuers that are not URLs are
// refused.
func ValidIssuer(issuer string) bool {
	rest, ok := strings.CutPrefix(issuer, "https://")
	if !ok || len(issuer) > MaxIssuerSize || !printable(issuer, MaxIssuerSize) ||
		strings.ContainsAny(issuer, "?#@\\") {
		return false
	}
	authority, _, _ := strings.Cut(rest, "/")
	host, port, hasPort := strings.Cut(authority, ":")
	if host == "" || strings.Trim(host, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") != "" {
		return false
	}
	return !hasPort || (port != "" && len(port) <= 5 && strings.Trim(port, "0123456789") == "")
}

// ValidNamespace reports whether value is an RFC 1123 label, as Kubernetes
// names namespaces.
func ValidNamespace(value string) bool { return len(value) <= maxLabel && dnsLabel(value) }

// ValidName reports whether value is an RFC 1123 subdomain, as Kubernetes
// names ServiceAccounts, pods and StatefulSets: at most 253 characters in
// all, with no limit per label (IsDNS1123Subdomain).
func ValidName(value string) bool {
	if len(value) > maxSubdomain {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if !dnsLabel(label) {
			return false
		}
	}
	return true
}

// dnsLabel reports whether value is lowercase letters, digits and hyphens,
// starting and ending with a letter or digit.
func dnsLabel(value string) bool {
	if len(value) == 0 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

// ComputeV2 derives the join code v2, which also binds the replica's trust:
//
//	digest = SHA-256(label v2 || 0x00 || machine key || node key || cluster ID
//	                 || nonce || trust digest)
//	code   = the first 50 bits of digest in RFC 4648 base32, upper case
func ComputeV2(inputs Inputs, trustDigest [32]byte) (Code, error) {
	if !inputs.complete() || trustDigest == ([32]byte{}) {
		return Code{}, ErrInvalid
	}
	hash := sha256.New()
	hash.Write([]byte(labelV2))
	hash.Write([]byte{0})
	inputs.write(hash)
	hash.Write(trustDigest[:])
	return Code{text: base32.StdEncoding.EncodeToString(hash.Sum(nil))[:Length]}, nil
}

// TokenPod reads the namespace, ServiceAccount and pod a pod-bound token
// names, without verifying it: a replica computes its code from the token it
// sends, and Core verifies the token before it digests the same names.
func TokenPod(token string) (namespace, serviceAccount, pod string, err error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return "", "", "", ErrInvalidTrust
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil || CheckStrictJSON(payload) != nil {
		return "", "", "", ErrInvalidTrust
	}
	var claims struct {
		Kubernetes struct {
			Namespace string `json:"namespace"`
			Pod       struct {
				Name string `json:"name"`
			} `json:"pod"`
			ServiceAccount struct {
				Name string `json:"name"`
			} `json:"serviceaccount"`
		} `json:"kubernetes.io"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", "", ErrInvalidTrust
	}
	kubernetes := claims.Kubernetes
	if kubernetes.Namespace == "" || kubernetes.ServiceAccount.Name == "" || kubernetes.Pod.Name == "" {
		return "", "", "", ErrInvalidTrust
	}
	return kubernetes.Namespace, kubernetes.ServiceAccount.Name, kubernetes.Pod.Name, nil
}
