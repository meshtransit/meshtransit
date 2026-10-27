package kubejoin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// rfc7638N is the RSA modulus of RFC 7638 §3.1, whose thumbprint the RFC
// gives.
const rfc7638N = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjB" +
	"ZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0" +
	"zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-k" +
	"EgU8awapJzKnqDKgw"

// kubernetesJWKS is shaped like `kubectl get --raw /openid/v1/jwks`.
func kubernetesJWKS() []byte {
	return []byte(`{"keys":[{"use":"sig","kty":"RSA","kid":"2011-04-29","alg":"RS256","n":"` + rfc7638N +
		`","e":"AQAB"}]}`)
}

func mustParseJWKS(t *testing.T, raw []byte) JWKS {
	t.Helper()
	jwks, err := ParseJWKS(raw)
	if err != nil {
		t.Fatalf("ParseJWKS() error = %v", err)
	}
	return jwks
}

func rawURL(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

// syntheticModulus returns a modulus of exactly bits bits: the parser checks
// its size and encoding, never whether it is a product of primes.
func syntheticModulus(bits int) string {
	modulus := bytes.Repeat([]byte{0xc5}, bits/8)
	return rawURL(modulus)
}

func ecKeyJSON(t *testing.T, kid string) (string, *ecdsa.PublicKey) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, err := private.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"kty":"EC","crv":"P-256","kid":%q,"x":%q,"y":%q}`, kid, rawURL(point[1:33]),
		rawURL(point[33:65])), &private.PublicKey
}

func TestParseJWKSCanonicalVector(t *testing.T) {
	t.Parallel()
	jwks := mustParseJWKS(t, kubernetesJWKS())
	want := `{"keys":[{"alg":"RS256","e":"AQAB","kid":"2011-04-29","kty":"RSA","n":"` + rfc7638N + `"}]}`
	if got := string(jwks.Canonical()); got != want {
		t.Fatalf("Canonical() = %s\nwant %s", got, want)
	}
	keys := jwks.Keys()
	if len(keys) != 1 || keys[0].ID != "2011-04-29" || keys[0].Algorithm != AlgorithmRS256 {
		t.Fatalf("Keys() = %+v", keys)
	}
	// RFC 7638 §3.1.
	if got := base64.RawURLEncoding.EncodeToString(keys[0].Thumbprint[:]); got !=
		"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("Thumbprint = %s", got)
	}
	public, ok := keys[0].Public.(*rsa.PublicKey)
	if !ok || public.E != 65537 || public.N.BitLen() != 2048 {
		t.Fatalf("Public = %T", keys[0].Public)
	}
	if key, found := jwks.Key("2011-04-29"); !found || key.Thumbprint != keys[0].Thumbprint {
		t.Fatalf("Key() = %+v, %v", key, found)
	}
	if _, found := jwks.Key("other"); found {
		t.Fatal("Key(other) found")
	}
}

// Order of keys and members, and members the canonical form drops, do not
// change the canonical form.
func TestParseJWKSCanonicalIsStable(t *testing.T) {
	t.Parallel()
	ecJSON, ecPublic := ecKeyJSON(t, "b-ec")
	rsaJSON := `{"kid":"a-rsa","e":"AQAB","n":"` + rfc7638N + `","kty":"RSA","x5c":["MIIB"],"x5t":"abc"}`
	first := mustParseJWKS(t, []byte(`{"keys":[`+ecJSON+`,`+rsaJSON+`]}`))
	second := mustParseJWKS(t, []byte(`{"keys":[{"kty":"RSA","n":"`+rfc7638N+`","e":"AQAB","kid":"a-rsa","use":"sig"},`+
		ecJSON+`]}`))
	if !bytes.Equal(first.Canonical(), second.Canonical()) {
		t.Fatalf("canonical forms differ:\n%s\n%s", first.Canonical(), second.Canonical())
	}
	if !strings.HasPrefix(string(first.Canonical()), `{"keys":[{"alg":"RS256","e":"AQAB","kid":"a-rsa"`) {
		t.Fatalf("keys are not sorted by kid: %s", first.Canonical())
	}
	key, found := first.Key("b-ec")
	if !found || key.Algorithm != AlgorithmES256 {
		t.Fatalf("Key(b-ec) = %+v, %v", key, found)
	}
	if public, ok := key.Public.(*ecdsa.PublicKey); !ok || !public.Equal(ecPublic) {
		t.Fatalf("Public = %T", key.Public)
	}
}

// Parsed keys and their canonical bytes are copies: callers cannot change
// what the JWKS holds.
func TestJWKSReturnsCopies(t *testing.T) {
	t.Parallel()
	jwks := mustParseJWKS(t, kubernetesJWKS())
	canonical := jwks.Canonical()
	canonical[0] = 'X'
	keys := jwks.Keys()
	keys[0].ID = "changed"
	if jwks.Canonical()[0] != '{' || jwks.Keys()[0].ID != "2011-04-29" {
		t.Fatal("JWKS changed through a returned value")
	}
}

func TestParseJWKSRefuses(t *testing.T) {
	t.Parallel()
	ecJSON, _ := ecKeyJSON(t, "ec")
	rsaKey := func(members string) string {
		return `{"keys":[{"kty":"RSA","kid":"k","n":"` + rfc7638N + `","e":"AQAB"` + members + `}]}`
	}
	ecPoint := func(t *testing.T) (string, string) {
		t.Helper()
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		point, err := private.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		y := bytes.Clone(point[33:65])
		y[31] ^= 1
		return rawURL(point[1:33]), rawURL(y)
	}
	offX, offY := ecPoint(t)
	nineKeys := make([]string, 0, 9)
	for index := range 9 {
		nineKeys = append(nineKeys, `{"kty":"RSA","kid":"k`+fmt.Sprint(index)+`","n":"`+rfc7638N+`","e":"AQAB"}`)
	}
	padded := base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xc5}, 256)) // 344 characters, one '='
	leadingZero := rawURL(append([]byte{0}, bytes.Repeat([]byte{0xc5}, 256)...))
	for name, raw := range map[string]string{
		"not JSON":                   `{`,
		"not an object":              `[]`,
		"trailing data":              `{"keys":[]} {}`,
		"no keys":                    `{}`,
		"empty keys":                 `{"keys":[]}`,
		"other top-level member":     `{"keys":[` + ecJSON + `],"extra":1}`,
		"duplicate top-level member": `{"keys":[` + ecJSON + `],"keys":[` + ecJSON + `]}`,
		"duplicate key member":       `{"keys":[{"kty":"RSA","kid":"k","kid":"j","n":"` + rfc7638N + `","e":"AQAB"}]}`,
		"nine keys":                  `{"keys":[` + strings.Join(nineKeys, ",") + `]}`,
		"duplicate kid":              `{"keys":[` + ecJSON + `,` + ecJSON + `]}`,
		"one key under two kids": `{"keys":[{"kty":"RSA","kid":"a","n":"` + rfc7638N + `","e":"AQAB"},` +
			`{"kty":"RSA","kid":"b","n":"` + rfc7638N + `","e":"AQAB"}]}`,
		"missing kid": `{"keys":[{"kty":"RSA","n":"` + rfc7638N + `","e":"AQAB"}]}`,
		"empty kid":   `{"keys":[{"kty":"RSA","kid":"","n":"` + rfc7638N + `","e":"AQAB"}]}`,
		"long kid": `{"keys":[{"kty":"RSA","kid":"` + strings.Repeat("k", 129) + `","n":"` + rfc7638N +
			`","e":"AQAB"}]}`,
		"kid with a control character": `{"keys":[{"kty":"RSA","kid":"a\u0001","n":"` + rfc7638N + `","e":"AQAB"}]}`,
		"kid not a string":             `{"keys":[{"kty":"RSA","kid":7,"n":"` + rfc7638N + `","e":"AQAB"}]}`,
		"oct key":                      `{"keys":[{"kty":"oct","kid":"k","k":"c2VjcmV0"}]}`,
		"OKP key":                      `{"keys":[{"kty":"OKP","kid":"k","crv":"Ed25519","x":"` + rawURL(make([]byte, 32)) + `"}]}`,
		"use enc":                      rsaKey(`,"use":"enc"`),
		"RSA under ES256":              rsaKey(`,"alg":"ES256"`),
		"RSA under PS256":              rsaKey(`,"alg":"PS256"`),
		"private exponent":             rsaKey(`,"d":"AQAB"`),
		"private prime":                rsaKey(`,"p":"AQAB"`),
		"other private member":         rsaKey(`,"qi":"AQAB"`),
		"key_ops":                      rsaKey(`,"key_ops":["verify"]`),
		"unknown member":               rsaKey(`,"extra":"x"`),
		"RSA 1024 bits":                `{"keys":[{"kty":"RSA","kid":"k","n":"` + syntheticModulus(1024) + `","e":"AQAB"}]}`,
		"RSA 4104 bits":                `{"keys":[{"kty":"RSA","kid":"k","n":"` + syntheticModulus(4104) + `","e":"AQAB"}]}`,
		"exponent 3":                   `{"keys":[{"kty":"RSA","kid":"k","n":"` + rfc7638N + `","e":"Aw"}]}`,
		"exponent with a leading zero": `{"keys":[{"kty":"RSA","kid":"k","n":"` + rfc7638N + `","e":"AAEAAQ"}]}`,
		"modulus with a leading zero":  `{"keys":[{"kty":"RSA","kid":"k","n":"` + leadingZero + `","e":"AQAB"}]}`,
		"padded base64url":             `{"keys":[{"kty":"RSA","kid":"k","n":"` + padded + `","e":"AQAB"}]}`,
		"standard base64":              `{"keys":[{"kty":"RSA","kid":"k","n":"` + strings.ReplaceAll(rfc7638N, "_", "/") + `","e":"AQAB"}]}`,
		"no modulus":                   `{"keys":[{"kty":"RSA","kid":"k","e":"AQAB"}]}`,
		"P-384": `{"keys":[{"kty":"EC","crv":"P-384","kid":"k","x":"` + rawURL(make([]byte, 48)) + `","y":"` +
			rawURL(make([]byte, 48)) + `"}]}`,
		"EC under RS256":     strings.Replace(`{"keys":[`+ecJSON+`]}`, `"kty":"EC"`, `"kty":"EC","alg":"RS256"`, 1),
		"EC point off curve": `{"keys":[{"kty":"EC","crv":"P-256","kid":"k","x":"` + offX + `","y":"` + offY + `"}]}`,
		"EC short coordinate": `{"keys":[{"kty":"EC","crv":"P-256","kid":"k","x":"` + rawURL(make([]byte, 31)) +
			`","y":"` + rawURL(make([]byte, 32)) + `"}]}`,
		"EC with RSA members": strings.Replace(`{"keys":[`+ecJSON+`]}`, `"kty":"EC"`, `"kty":"EC","e":"AQAB"`, 1),
		"too large":           `{"keys":[` + ecJSON + `],"pad":"` + strings.Repeat("x", MaxJWKSSize) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseJWKS([]byte(raw))
			if !errors.Is(err, ErrInvalidJWKS) {
				t.Fatalf("ParseJWKS() error = %v, want ErrInvalidJWKS", err)
			}
			// Each refusal names its rule, for an administrator's paste.
			refused, ok := errors.AsType[*JWKSError](err)
			if !ok || refused.Rule != refusalRules[name] || refusalRules[name] == "" {
				t.Fatalf("ParseJWKS() rule = %+v, want %q", refused, refusalRules[name])
			}
		})
	}
}

// RSA moduli from 2048 to 4096 bits are accepted.
func TestParseJWKSAcceptsRSASizes(t *testing.T) {
	t.Parallel()
	for _, bits := range []int{2048, 3072, 4096} {
		raw := `{"keys":[{"kty":"RSA","kid":"k","n":"` + syntheticModulus(bits) + `","e":"AQAB"}]}`
		if _, err := ParseJWKS([]byte(raw)); err != nil {
			t.Errorf("%d bits: ParseJWKS() error = %v", bits, err)
		}
	}
}

func vectorTrust(t *testing.T) Trust {
	t.Helper()
	return Trust{
		Issuer:         "https://kubernetes.default.svc.cluster.local",
		JWKS:           mustParseJWKS(t, kubernetesJWKS()),
		Namespace:      "mt-kube-k1",
		ServiceAccount: "meshgw",
		PodName:        "meshgw-1",
	}
}

// The vector was computed independently, with Python's hashlib and struct.
func TestTrustDigestVector(t *testing.T) {
	t.Parallel()
	digest, err := TrustDigest(vectorTrust(t))
	if err != nil {
		t.Fatalf("TrustDigest() error = %v", err)
	}
	if got := hex.EncodeToString(digest[:]); got !=
		"55602c6b1c540551e1f029ac3d123ac81b2f89ddf793e4996ffec82a238b412d" {
		t.Fatalf("TrustDigest() = %s", got)
	}
}

func TestTrustDigestBindsEveryInput(t *testing.T) {
	t.Parallel()
	base, err := TrustDigest(vectorTrust(t))
	if err != nil {
		t.Fatal(err)
	}
	ecJSON, _ := ecKeyJSON(t, "ec")
	for name, change := range map[string]func(*Trust){
		"issuer":          func(trust *Trust) { trust.Issuer += "/x" },
		"JWKS":            func(trust *Trust) { trust.JWKS = mustParseJWKS(t, []byte(`{"keys":[`+ecJSON+`]}`)) },
		"namespace":       func(trust *Trust) { trust.Namespace = "mt-kube-k2" },
		"service account": func(trust *Trust) { trust.ServiceAccount = "meshgw2" },
		"pod":             func(trust *Trust) { trust.PodName = "meshgw-0" },
		// Lengths are written, so moving bytes between fields is seen.
		"boundary": func(trust *Trust) { trust.Namespace, trust.ServiceAccount = "mt-kube-k1m", "eshgw" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			trust := vectorTrust(t)
			change(&trust)
			digest, err := TrustDigest(trust)
			if err != nil || digest == base {
				t.Fatalf("TrustDigest() = %x, %v; want a different digest", digest, err)
			}
		})
	}
}

func TestTrustDigestRefuses(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*Trust){
		"no JWKS":             func(trust *Trust) { trust.JWKS = JWKS{} },
		"no issuer":           func(trust *Trust) { trust.Issuer = "" },
		"http issuer":         func(trust *Trust) { trust.Issuer = "http://kubernetes.default.svc.cluster.local" },
		"issuer not a URL":    func(trust *Trust) { trust.Issuer = "kubernetes" },
		"long issuer":         func(trust *Trust) { trust.Issuer = "https://" + strings.Repeat("a", 248) },
		"no namespace":        func(trust *Trust) { trust.Namespace = "" },
		"bad namespace":       func(trust *Trust) { trust.Namespace = "Mt_Kube" },
		"no service account":  func(trust *Trust) { trust.ServiceAccount = "" },
		"bad service account": func(trust *Trust) { trust.ServiceAccount = "meshgw:x" },
		"no pod":              func(trust *Trust) { trust.PodName = "" },
		"pod without ordinal": func(trust *Trust) { trust.PodName = "meshgw" },
		"long namespace":      func(trust *Trust) { trust.Namespace = strings.Repeat("n", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			trust := vectorTrust(t)
			change(&trust)
			if _, err := TrustDigest(trust); !errors.Is(err, ErrInvalidTrust) {
				t.Fatalf("TrustDigest() error = %v, want ErrInvalidTrust", err)
			}
		})
	}
}

func TestStatefulSetOf(t *testing.T) {
	t.Parallel()
	for pod, want := range map[string]string{
		"meshgw-0": "meshgw", "meshgw-63": "meshgw", "a-b-c-12": "a-b-c",
		"meshgw": "", "meshgw-": "", "-1": "", "meshgw-01": "", "meshgw-x": "", "a--1": "", "A-1": "",
		strings.Repeat("a", 254) + "-1": "", "a.b-2": "a.b",
	} {
		got, ok := StatefulSetOf(pod)
		if got != want || ok != (want != "") {
			t.Errorf("StatefulSetOf(%q) = %q, %v; want %q", pod, got, ok, want)
		}
	}
}

// The vector was computed independently, with Python's hashlib and base64.
func TestCodeV2Vector(t *testing.T) {
	t.Parallel()
	digest, err := TrustDigest(vectorTrust(t))
	if err != nil {
		t.Fatal(err)
	}
	code, err := ComputeV2(vectorInputs(t), digest)
	if err != nil {
		t.Fatalf("ComputeV2() error = %v", err)
	}
	if code.String() != "MJPAI-HQFYX" {
		t.Fatalf("ComputeV2() = %q, want MJPAI-HQFYX", code)
	}
	v1, err := Compute(vectorInputs(t))
	if err != nil || v1.Equal(code) {
		t.Fatalf("Compute() = %q, %v; want a v1 code different from v2", v1, err)
	}
}

func TestCodeV2BindsTheTrust(t *testing.T) {
	t.Parallel()
	digest, err := TrustDigest(vectorTrust(t))
	if err != nil {
		t.Fatal(err)
	}
	base, err := ComputeV2(vectorInputs(t), digest)
	if err != nil {
		t.Fatal(err)
	}
	digest[31] ^= 1
	if code, err := ComputeV2(vectorInputs(t), digest); err != nil || code == base {
		t.Fatalf("ComputeV2() = %q, %v; want a different code", code, err)
	}
	if _, err := ComputeV2(vectorInputs(t), [32]byte{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ComputeV2(zero digest) error = %v, want ErrInvalid", err)
	}
	inputs := vectorInputs(t)
	inputs.RequestNonce = [32]byte{}
	if _, err := ComputeV2(inputs, digest); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ComputeV2(zero nonce) error = %v, want ErrInvalid", err)
	}
}

func FuzzParseJWKS(f *testing.F) {
	f.Add(kubernetesJWKS())
	f.Add([]byte(`{"keys":[{"kty":"EC","crv":"P-256","kid":"k","x":"AA","y":"AA"}]}`))
	f.Add([]byte(`{"keys":[{"kty":"RSA","kid":"k","kid":"k"}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		jwks, err := ParseJWKS(raw)
		if err != nil {
			if !errors.Is(err, ErrInvalidJWKS) {
				t.Fatalf("ParseJWKS() error = %v, want ErrInvalidJWKS", err)
			}
			return
		}
		// The canonical form is a fixed point.
		again, err := ParseJWKS(jwks.Canonical())
		if err != nil || !bytes.Equal(again.Canonical(), jwks.Canonical()) {
			t.Fatalf("canonical form is not stable: %v", err)
		}
	})
}

func TestCheckStrictJSON(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{`{}`, `{"a":{"a":1},"b":[{"a":1},{"a":2}]}`, `[1,2]`, `"x"`, ` {"a":1} `} {
		if err := CheckStrictJSON([]byte(raw)); err != nil {
			t.Errorf("CheckStrictJSON(%s) error = %v", raw, err)
		}
	}
	for _, raw := range []string{
		``, `{`, `{"a":1,"a":2}`, `{"a":{"b":1,"b":1}}`, `[{"a":1,"a":1}]`, `{} {}`,
		`{"a":1}x`,
	} {
		if err := CheckStrictJSON([]byte(raw)); !errors.Is(err, ErrInvalidJSON) {
			t.Errorf("CheckStrictJSON(%s) error = %v, want ErrInvalidJSON", raw, err)
		}
	}
}

// A kid needing JSON escapes: the canonical form escapes only what JSON
// requires, like any encoder without HTML escaping. The digest was computed
// independently, with Python's json.dumps.
func TestCanonicalEscapesOnlyWhatJSONRequires(t *testing.T) {
	t.Parallel()
	kid := `a<b>&"\`
	quoted := `"a<b>&\"\\"`
	jwks := mustParseJWKS(t, []byte(`{"keys":[{"kty":"RSA","kid":`+quoted+`,"n":"`+rfc7638N+`","e":"AQAB"}]}`))
	want := `{"keys":[{"alg":"RS256","e":"AQAB","kid":` + quoted + `,"kty":"RSA","n":"` + rfc7638N + `"}]}`
	if got := string(jwks.Canonical()); got != want {
		t.Fatalf("Canonical() = %s\nwant %s", got, want)
	}
	if _, found := jwks.Key(kid); !found {
		t.Fatalf("Key(%q) not found", kid)
	}
	trust := vectorTrust(t)
	trust.JWKS = jwks
	digest, err := TrustDigest(trust)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(digest[:]); got != "18d8d5179b694201e3c7f7b66fd718df0d7471e29d41906860ae61d583f1eb62" {
		t.Fatalf("TrustDigest() = %s", got)
	}
}

// The EC key of RFC 7517 Appendix A.1; its thumbprint was computed
// independently, with Python's hashlib.
func TestECThumbprintVector(t *testing.T) {
	t.Parallel()
	jwks := mustParseJWKS(t, []byte(`{"keys":[{"kty":"EC","crv":"P-256","kid":"1",`+
		`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}`))
	key, _ := jwks.Key("1")
	if got := base64.RawURLEncoding.EncodeToString(key.Thumbprint[:]); got != "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s" {
		t.Fatalf("Thumbprint = %s", got)
	}
}

func TestParseJWKSRefusesEvenModulusAndLineBreaks(t *testing.T) {
	t.Parallel()
	even := bytes.Repeat([]byte{0xc4}, 256)
	broken := rfc7638N[:40] + `\n` + rfc7638N[40:]
	for name, n := range map[string]string{"even modulus": rawURL(even), "line break": broken} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw := `{"keys":[{"kty":"RSA","kid":"k","n":"` + n + `","e":"AQAB"}]}`
			if _, err := ParseJWKS([]byte(raw)); !errors.Is(err, ErrInvalidJWKS) {
				t.Fatalf("ParseJWKS() error = %v, want ErrInvalidJWKS", err)
			}
		})
	}
}

// A refusal names the rule broken, never the input.
func TestParseJWKSErrorsNameTheRule(t *testing.T) {
	t.Parallel()
	_, err := ParseJWKS([]byte(`{"keys":[{"kty":"RSA","kid":"secret-kid","n":"` + rfc7638N + `","e":"Aw"}]}`))
	if err == nil || !strings.Contains(err.Error(), "65537") || strings.Contains(err.Error(), "secret-kid") {
		t.Fatalf("ParseJWKS() error = %v", err)
	}
}

func TestValidIssuer(t *testing.T) {
	t.Parallel()
	for issuer, want := range map[string]bool{
		"https://kubernetes.default.svc.cluster.local":                          true,
		"https://oidc.eks.ap-southeast-1.amazonaws.com/id/ABCDEF0123456789":     true,
		"https://container.googleapis.com/v1/projects/p/locations/l/clusters/c": true,
		"https://issuer.example:8443/path":                                      true,
		"HTTPS://issuer.example":                                                false,
		"http://issuer.example":                                                 false,
		"https://":                                                              false,
		"https://issuer.example?":                                               false,
		"https://issuer.example#":                                               false,
		"https://issuer.example:":                                               false,
		"https://issuer.example:443x":                                           false,
		"https://user@issuer.example":                                           false,
		"https://issuér.example":                                                false,
		"https://issuer.example/a b":                                            false,
		"https://issuer_example":                                                false,
		"kubernetes":                                                            false,
		"https://" + strings.Repeat("a", 248):                                   false,
	} {
		if got := ValidIssuer(issuer); got != want {
			t.Errorf("ValidIssuer(%q) = %v, want %v", issuer, got, want)
		}
	}
}

func TestValidNames(t *testing.T) {
	t.Parallel()
	if !ValidName(strings.Repeat("s", 64)) || !ValidName("a.b-c") || ValidName(strings.Repeat("s", 254)) ||
		ValidName("a..b") || ValidName("A") || ValidName("") {
		t.Error("ValidName does not follow IsDNS1123Subdomain")
	}
	if !ValidNamespace(strings.Repeat("n", 63)) || ValidNamespace(strings.Repeat("n", 64)) || ValidNamespace("a.b") {
		t.Error("ValidNamespace does not follow IsDNS1123Label")
	}
}

func TestCheckStrictJSONMore(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		raw   string
		valid bool
	}{
		"sibling objects share names":   {`{"a":{"x":1},"b":{"x":2}}`, true},
		"number beyond float64":         {`{"a":1e400}`, true},
		"duplicate deep inside":         {`{"a":[{"b":{"c":1,"c":2}}]}`, false},
		"names differing only in case":  {`{"iss":"a","ISS":"b"}`, false},
		"Kelvin sign folds to k":        {`{"kubernetes.io":{},"Kubernetes.io":{}}`, false},
		"stray closing brace":           {`{}}`, false},
		"stray closing bracket":         {`{}]`, false},
		"whitespace only":               {"  \n", false},
		"value after a top-level value": {`1 2`, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := CheckStrictJSON([]byte(test.raw))
			if test.valid != (err == nil) || (err != nil && !errors.Is(err, ErrInvalidJSON)) {
				t.Fatalf("CheckStrictJSON(%s) error = %v, want valid %v", test.raw, err, test.valid)
			}
		})
	}
}

// Without duplicate names CheckStrictJSON agrees with json.Valid.
func FuzzCheckStrictJSON(f *testing.F) {
	for _, seed := range []string{`{}`, `[1,{"a":2}]`, `{"a":1,"a":1}`, `{`, `"x"`, `1e400`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		err := CheckStrictJSON(raw)
		if err == nil && !json.Valid(raw) {
			t.Fatalf("CheckStrictJSON accepted invalid JSON %q", raw)
		}
		if err != nil && !errors.Is(err, ErrInvalidJSON) {
			t.Fatalf("error = %v", err)
		}
	})
}

// TokenPod reads, without verifying, the identity a pod's own token names:
// the replica computes its code from what it sends.
func TestTokenPod(t *testing.T) {
	t.Parallel()
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"system:serviceaccount:mt-kube-k1:meshgw",` +
		`"kubernetes.io":{"namespace":"mt-kube-k1","pod":{"name":"meshgw-2","uid":"u"},` +
		`"serviceaccount":{"name":"meshgw","uid":"s"}}}`))
	namespace, account, pod, err := TokenPod("eyJhbGciOiJFUzI1NiJ9." + payload + ".c2ln")
	if err != nil || namespace != "mt-kube-k1" || account != "meshgw" || pod != "meshgw-2" {
		t.Fatalf("TokenPod() = %q, %q, %q, %v", namespace, account, pod, err)
	}
	for name, token := range map[string]string{
		"empty":          "",
		"two segments":   "a." + payload,
		"not base64":     "a.!!.c",
		"not JSON":       "a." + base64.RawURLEncoding.EncodeToString([]byte("x")) + ".c",
		"no pod":         "a." + base64.RawURLEncoding.EncodeToString([]byte(`{"kubernetes.io":{"namespace":"n"}}`)) + ".c",
		"not pod-bound":  "a." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"system:serviceaccount:n:s"}`)) + ".c",
		"duplicate name": "a." + base64.RawURLEncoding.EncodeToString([]byte(`{"kubernetes.io":{},"kubernetes.io":{}}`)) + ".c",
	} {
		if _, _, _, err := TokenPod(token); !errors.Is(err, ErrInvalidTrust) {
			t.Errorf("%s: TokenPod() error = %v, want ErrInvalidTrust", name, err)
		}
	}
}

// The rule each refusal of TestParseJWKSRefuses names.
var refusalRules = map[string]JWKSRule{
	"not JSON": RuleJSON, "not an object": RuleJSON, "trailing data": RuleJSON, "no keys": RuleJSON,
	"empty keys": RuleNoKeys, "other top-level member": RuleJSON, "duplicate top-level member": RuleJSON,
	"duplicate key member": RuleJSON, "nine keys": RuleTooManyKeys, "duplicate kid": RuleKeyID, "one key under two kids": RuleKeyID,
	"missing kid": RuleKeyID, "empty kid": RuleKeyID, "long kid": RuleKeyID,
	"kid with a control character": RuleKeyID, "kid not a string": RuleEncoding, "oct key": RulePrivateMember,
	"OKP key": RuleKeyType, "use enc": RuleKeyType, "RSA under ES256": RuleKeyType, "RSA under PS256": RuleKeyType,
	"private exponent": RulePrivateMember, "private prime": RulePrivateMember,
	"other private member": RulePrivateMember, "key_ops": RulePrivateMember, "unknown member": RulePrivateMember,
	"RSA 1024 bits": RuleKeySize, "RSA 4104 bits": RuleKeySize, "exponent 3": RuleKeyType,
	"exponent with a leading zero": RuleKeyType, "modulus with a leading zero": RuleEncoding,
	"padded base64url": RuleEncoding, "standard base64": RuleEncoding, "no modulus": RuleEncoding,
	"P-384": RuleKeyType, "EC under RS256": RuleKeyType, "EC point off curve": RuleKeyType,
	"EC short coordinate": RuleEncoding, "EC with RSA members": RuleKeyType, "too large": RuleSize,
}

// Kubernetes names a key by the SHA-256 of its public key in PKIX DER, which
// kubectl shows; a JWKS may declare any other kid (vector: kind meshgw-a).
func TestKubernetesKeyID(t *testing.T) {
	t.Parallel()
	jwks, err := ParseJWKS([]byte(kindJWKS))
	if err != nil {
		t.Fatal(err)
	}
	key := jwks.Keys()[0]
	if got := key.KubernetesKeyID(); got != "W5g6JhuNGLKpWbGKkY1h_vyNJWNV3OHpeiEJLThDJhE" || got != key.ID {
		t.Fatalf("KubernetesKeyID() = %q, kid %q", got, key.ID)
	}
	renamed, err := ParseJWKS([]byte(strings.Replace(kindJWKS, key.ID, "another-name", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if renamed.Keys()[0].KubernetesKeyID() != key.ID {
		t.Fatal("the computed kid follows the declared one")
	}
	ecJSON, _ := ecKeyJSON(t, "ec")
	ec, err := ParseJWKS([]byte(`{"keys":[` + ecJSON + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(ec.Keys()[0].Public)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	if ec.Keys()[0].KubernetesKeyID() != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("an EC key's computed kid is not the SHA-256 of its PKIX DER")
	}
}

// kindJWKS is the JWKS kind meshgw-a served on 2026-10-27.
const kindJWKS = `{"keys":[{"use":"sig","kty":"RSA","kid":"W5g6JhuNGLKpWbGKkY1h_vyNJWNV3OHpeiEJLThDJhE","alg":"RS256","n":"ulb6f8XOFK8q2EKPjPXlwDQuMhPTiee6zlEDZu0twbQecr0w7uG6Vqghhovln3lwCtJdM_eHsWfgmd6I-HdaFUv738BlNvEZXanR9d5mSBmnIDtIUTpwrNOVTuskzBOMceJf86g7QwfL_ixA8xaavgt27B5dqZJcM34ORUy6O2qcm18keFqKhMoQ_FPnFS1xZmEPTw3VzBLpOAaI6sTh0-LBTtszztX-F6GYSw3bZenJUVQ9CHAPr4AtJRrRA0lpZj__gCz9CpajdNfJY712HzBv6tMb8ElqO3DaEr2ka40yqIug9wkMmlLg85MrMhtOZViuZq0hf_SAPFipqjVQKw","e":"AQAB"}]}`
