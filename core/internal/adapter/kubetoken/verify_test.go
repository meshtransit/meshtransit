package kubetoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"meshtransit.net/shared/kubejoin"
)

var (
	testNow = time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)

	keysOnce   sync.Once
	rsaPrivate *rsa.PrivateKey
	ecPrivate  *ecdsa.PrivateKey
)

const testIssuer = "https://kubernetes.default.svc.cluster.local"

func testKeys(t *testing.T) (*rsa.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()
	keysOnce.Do(func() {
		var err error
		if rsaPrivate, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if ecPrivate, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			panic(err)
		}
	})
	return rsaPrivate, ecPrivate
}

func b64(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

func testJWKS(t *testing.T) kubejoin.JWKS {
	t.Helper()
	rsaKey, ecKey := testKeys(t)
	point, err := ecKey.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"rsa-1","alg":"RS256","use":"sig","n":%q,"e":"AQAB"},`+
		`{"kty":"EC","kid":"ec-1","crv":"P-256","x":%q,"y":%q}]}`,
		b64(rsaKey.N.Bytes()), b64(point[1:33]), b64(point[33:65]))
	jwks, err := kubejoin.ParseJWKS([]byte(raw))
	if err != nil {
		t.Fatalf("ParseJWKS() error = %v", err)
	}
	return jwks
}

// claims returns the claims kubelet puts in a pod-bound token, as JSON
// values, so a test can remove or replace any of them.
func claims() map[string]any {
	return map[string]any{
		"iss": testIssuer,
		"aud": []string{Audience},
		"sub": "system:serviceaccount:mt-kube-k1:meshgw",
		"iat": testNow.Add(-time.Minute).Unix(),
		"nbf": testNow.Add(-time.Minute).Unix(),
		"exp": testNow.Add(9 * time.Minute).Unix(),
		"jti": "6c1e5b8e-6d7c-4f62-9a1b-0d3e4f5a6b7c",
		"kubernetes.io": map[string]any{
			"namespace":      "mt-kube-k1",
			"node":           map[string]any{"name": "kind-worker", "uid": "node-uid"},
			"pod":            map[string]any{"name": "meshgw-1", "uid": "pod-uid-1"},
			"serviceaccount": map[string]any{"name": "meshgw", "uid": "sa-uid"},
		},
	}
}

func header(alg, kid string) map[string]any {
	return map[string]any{"alg": alg, "kid": kid}
}

func encodeJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b64(raw)
}

// sign makes a compact JWS over raw header and payload segments with the
// key alg names, whatever the header says.
func sign(t *testing.T, alg, signingInput string) string {
	t.Helper()
	rsaKey, ecKey := testKeys(t)
	digest := sha256.Sum256([]byte(signingInput))
	switch alg {
	case "RS256":
		signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return b64(signature)
	case "ES256":
		r, s, err := ecdsa.Sign(rand.Reader, ecKey, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		signature := make([]byte, 64)
		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])
		return b64(signature)
	case "HS256":
		// The public key as an HMAC secret.
		public, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		mac := hmac.New(sha256.New, public)
		mac.Write([]byte(signingInput))
		return b64(mac.Sum(nil))
	case "none":
		return ""
	}
	t.Fatalf("unknown alg %s", alg)
	return ""
}

func token(t *testing.T, head map[string]any, body map[string]any, signer string) string {
	t.Helper()
	input := encodeJSON(t, head) + "." + encodeJSON(t, body)
	return input + "." + sign(t, signer, input)
}

func rotationExpectation(t *testing.T) Expectation {
	t.Helper()
	return Expectation{
		Issuer: testIssuer, JWKS: testJWKS(t),
		Namespace: "mt-kube-k1", ServiceAccount: "meshgw", PodName: "meshgw-1",
	}
}

func TestVerifyAcceptsPodTokens(t *testing.T) {
	t.Parallel()
	jwks := testJWKS(t)
	for _, test := range []struct{ alg, kid string }{{"RS256", "rsa-1"}, {"ES256", "ec-1"}} {
		raw := token(t, header(test.alg, test.kid), claims(), test.alg)
		got, err := Verify(raw, rotationExpectation(t), testNow)
		if err != nil {
			t.Fatalf("%s: Verify() error = %v", test.alg, err)
		}
		key, _ := jwks.Key(test.kid)
		want := Claims{
			Issuer: testIssuer, Namespace: "mt-kube-k1", ServiceAccount: "meshgw", PodName: "meshgw-1",
			PodUID: "pod-uid-1", JTI: "6c1e5b8e-6d7c-4f62-9a1b-0d3e4f5a6b7c",
			IssuedAt: testNow.Add(-time.Minute), NotBefore: testNow.Add(-time.Minute),
			Expiry: testNow.Add(9 * time.Minute), KeyThumbprint: key.Thumbprint,
		}
		if got != want {
			t.Fatalf("%s: Verify() = %+v\nwant %+v", test.alg, got, want)
		}
	}
}

// At join there is no identity to compare: the token's own identity is
// returned, and the issuer and keys are the ones the pod sent.
func TestVerifyAtJoinReturnsTheTokensIdentity(t *testing.T) {
	t.Parallel()
	body := claims()
	body["kubernetes.io"].(map[string]any)["pod"] = map[string]any{"name": "meshgw-0", "uid": "u0"}
	got, err := Verify(token(t, header("RS256", "rsa-1"), body, "RS256"),
		Expectation{Issuer: testIssuer, JWKS: testJWKS(t)}, testNow)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got.PodName != "meshgw-0" || got.Namespace != "mt-kube-k1" || got.ServiceAccount != "meshgw" {
		t.Fatalf("Verify() = %+v", got)
	}
}

func TestVerifyAcceptsTypJWTAndAudienceString(t *testing.T) {
	t.Parallel()
	head := header("RS256", "rsa-1")
	head["typ"] = "JWT"
	body := claims()
	body["aud"] = Audience
	if _, err := Verify(token(t, head, body, "RS256"), rotationExpectation(t), testNow); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func refusal(t *testing.T, err error) Reason {
	t.Helper()
	var refused *RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("error = %v, want a RefusedError", err)
	}
	return refused.Reason
}

func TestVerifyRefusesHeaders(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		change func(map[string]any)
		signer string
		want   Reason
	}{
		"alg none":           {func(h map[string]any) { h["alg"] = "none" }, "none", ReasonMalformed},
		"HS256 public key":   {func(h map[string]any) { h["alg"] = "HS256" }, "HS256", ReasonMalformed},
		"PS256":              {func(h map[string]any) { h["alg"] = "PS256" }, "RS256", ReasonMalformed},
		"RS256 on an EC key": {func(h map[string]any) { h["kid"] = "ec-1" }, "RS256", ReasonSignature},
		"ES256 on an RSA key": {func(h map[string]any) { h["alg"], h["kid"] = "ES256", "rsa-1" }, "ES256",
			ReasonSignature},
		"no kid":       {func(h map[string]any) { delete(h, "kid") }, "RS256", ReasonMalformed},
		"unknown kid":  {func(h map[string]any) { h["kid"] = "other" }, "RS256", ReasonUnknownKey},
		"kid a number": {func(h map[string]any) { h["kid"] = 7 }, "RS256", ReasonMalformed},
		"typ at+jwt":   {func(h map[string]any) { h["typ"] = "at+jwt" }, "RS256", ReasonMalformed},
		"crit":         {func(h map[string]any) { h["crit"] = []string{"exp"} }, "RS256", ReasonMalformed},
		"b64":          {func(h map[string]any) { h["b64"], h["crit"] = false, []string{"b64"} }, "RS256", ReasonMalformed},
		"jku":          {func(h map[string]any) { h["jku"] = "https://attacker.example/jwks" }, "RS256", ReasonMalformed},
		"embedded jwk": {func(h map[string]any) { h["jwk"] = map[string]any{"kty": "oct", "k": "AA"} }, "RS256", ReasonMalformed},
		"x5u":          {func(h map[string]any) { h["x5u"] = "https://attacker.example/cert" }, "RS256", ReasonMalformed},
		"x5c":          {func(h map[string]any) { h["x5c"] = []string{"MIIB"} }, "RS256", ReasonMalformed},
		"cty":          {func(h map[string]any) { h["cty"] = "JWT" }, "RS256", ReasonMalformed},
		"nonce":        {func(h map[string]any) { h["nonce"] = "n" }, "RS256", ReasonMalformed},
		"other member": {func(h map[string]any) { h["zip"] = "DEF" }, "RS256", ReasonMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			head := header("RS256", "rsa-1")
			test.change(head)
			_, err := Verify(token(t, head, claims(), test.signer), rotationExpectation(t), testNow)
			if got := refusal(t, err); got != test.want {
				t.Fatalf("reason = %s, want %s", got, test.want)
			}
		})
	}
}

func TestVerifyRefusesFormats(t *testing.T) {
	t.Parallel()
	valid := token(t, header("RS256", "rsa-1"), claims(), "RS256")
	parts := strings.Split(valid, ".")
	duplicateHeader := b64([]byte(`{"alg":"RS256","kid":"rsa-1","kid":"ec-1"}`))
	duplicateInput := duplicateHeader + "." + parts[1]
	duplicateClaims := b64([]byte(`{"iss":"x","iss":"` + testIssuer + `"}`))
	for name, test := range map[string]struct {
		raw  string
		want Reason
	}{
		"empty":               {"", ReasonMissing},
		"two segments":        {parts[0] + "." + parts[1], ReasonMalformed},
		"JWE (five segments)": {strings.Join([]string{parts[0], "", parts[1], parts[2], "tag"}, "."), ReasonMalformed},
		"JSON serialization":  {`{"payload":"` + parts[1] + `","signatures":[]}`, ReasonMalformed},
		"padded segment":      {parts[0] + "=." + parts[1] + "." + parts[2], ReasonMalformed},
		"whitespace":          {" " + valid, ReasonMalformed},
		"line break in a segment": {parts[0] + "." + parts[1][:10] + "\n" + parts[1][10:] + "." + parts[2],
			ReasonMalformed},
		"too large":              {valid + strings.Repeat("A", MaxTokenSize), ReasonMalformed},
		"bad signature":          {parts[0] + "." + parts[1] + "." + b64(make([]byte, 256)), ReasonSignature},
		"duplicate header kid":   {duplicateInput + "." + sign(t, "RS256", duplicateInput), ReasonMalformed},
		"duplicate claim member": {parts[0] + "." + duplicateClaims + "." + sign(t, "RS256", parts[0]+"."+duplicateClaims), ReasonMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Verify(test.raw, rotationExpectation(t), testNow)
			if got := refusal(t, err); got != test.want {
				t.Fatalf("reason = %s, want %s", got, test.want)
			}
		})
	}
}

func TestVerifyRefusesClaims(t *testing.T) {
	t.Parallel()
	pod := func(body map[string]any) map[string]any { return body["kubernetes.io"].(map[string]any) }
	for name, test := range map[string]struct {
		change func(map[string]any)
		want   Reason
	}{
		"no iss":           {func(b map[string]any) { delete(b, "iss") }, ReasonMalformed},
		"no aud":           {func(b map[string]any) { delete(b, "aud") }, ReasonMalformed},
		"no sub":           {func(b map[string]any) { delete(b, "sub") }, ReasonMalformed},
		"no iat":           {func(b map[string]any) { delete(b, "iat") }, ReasonMalformed},
		"no nbf":           {func(b map[string]any) { delete(b, "nbf") }, ReasonMalformed},
		"no exp":           {func(b map[string]any) { delete(b, "exp") }, ReasonMalformed},
		"no jti":           {func(b map[string]any) { delete(b, "jti") }, ReasonMalformed},
		"empty jti":        {func(b map[string]any) { b["jti"] = "" }, ReasonMalformed},
		"long jti":         {func(b map[string]any) { b["jti"] = strings.Repeat("j", 129) }, ReasonMalformed},
		"jti control char": {func(b map[string]any) { b["jti"] = "a\nb" }, ReasonMalformed},
		"no kubernetes.io": {func(b map[string]any) { delete(b, "kubernetes.io") }, ReasonMalformed},
		"bound to a Secret": {func(b map[string]any) {
			delete(pod(b), "pod")
			pod(b)["secret"] = map[string]any{"name": "s", "uid": "u"}
		}, ReasonMalformed},
		"no pod uid":      {func(b map[string]any) { pod(b)["pod"] = map[string]any{"name": "meshgw-1"} }, ReasonMalformed},
		"wrong audience":  {func(b map[string]any) { b["aud"] = []string{"https://kubernetes.default.svc"} }, ReasonAudience},
		"two audiences":   {func(b map[string]any) { b["aud"] = []string{Audience, "other"} }, ReasonAudience},
		"empty audiences": {func(b map[string]any) { b["aud"] = []string{} }, ReasonAudience},
		"null audience":   {func(b map[string]any) { b["aud"] = nil }, ReasonMalformed},
		"API server token living an hour": {func(b map[string]any) {
			b["aud"] = []string{"https://kubernetes.default.svc.cluster.local"}
			b["iat"], b["nbf"] = testNow.Add(-time.Minute).Unix(), testNow.Add(-time.Minute).Unix()
			b["exp"] = testNow.Add(3606 * time.Second).Unix()
		}, ReasonAudience},
		"negative iat":      {func(b map[string]any) { b["iat"] = -1 }, ReasonMalformed},
		"iat with exponent": {func(b map[string]any) { b["iat"] = json.RawMessage("1.7e9") }, ReasonMalformed},
		"iat as 1.0":        {func(b map[string]any) { b["iat"] = json.RawMessage("1761555540.0") }, ReasonMalformed},
		"null iat":          {func(b map[string]any) { b["iat"] = nil }, ReasonMalformed},
		"iat in 2019":       {func(b map[string]any) { b["iat"] = 1546300800 }, ReasonMalformed},
		"exp in 2101":       {func(b map[string]any) { b["exp"] = 4133980800 }, ReasonMalformed},
		"pod uid too long": {func(b map[string]any) {
			pod(b)["pod"] = map[string]any{"name": "meshgw-1", "uid": strings.Repeat("u", 129)}
		}, ReasonMalformed},
		"pod name not DNS": {func(b map[string]any) { pod(b)["pod"] = map[string]any{"name": "Meshgw_1", "uid": "u"} }, ReasonMalformed},
		"namespace not DNS": {func(b map[string]any) {
			b["sub"] = "system:serviceaccount:MT:meshgw"
			pod(b)["namespace"] = "MT"
		}, ReasonMalformed},
		"case-variant duplicate claim": {func(b map[string]any) { b["ISS"] = "https://evil.example" }, ReasonMalformed},
		"expired":                      {func(b map[string]any) { b["exp"] = testNow.Unix() }, ReasonExpired},
		"nbf in the future":            {func(b map[string]any) { b["nbf"] = testNow.Add(31 * time.Second).Unix() }, ReasonExpired},
		"iat in the future":            {func(b map[string]any) { b["iat"] = testNow.Add(31 * time.Second).Unix() }, ReasonExpired},
		"lives 16 minutes": {func(b map[string]any) {
			b["iat"], b["nbf"] = testNow.Add(-7*time.Minute).Unix(), testNow.Add(-7*time.Minute).Unix()
		}, ReasonMalformed},
		"iat after exp":   {func(b map[string]any) { b["iat"] = testNow.Add(10 * time.Minute).Unix() }, ReasonMalformed},
		"nbf after exp":   {func(b map[string]any) { b["nbf"] = testNow.Add(10 * time.Minute).Unix() }, ReasonMalformed},
		"fractional iat":  {func(b map[string]any) { b["iat"] = float64(testNow.Unix()) - 0.5 }, ReasonMalformed},
		"huge exp":        {func(b map[string]any) { b["exp"] = 1e300 }, ReasonMalformed},
		"exp as a string": {func(b map[string]any) { b["exp"] = fmt.Sprint(testNow.Add(time.Minute).Unix()) }, ReasonMalformed},
		"wrong issuer":    {func(b map[string]any) { b["iss"] = "https://oidc.eks.example" }, ReasonIdentity},
		"another ServiceAccount": {func(b map[string]any) {
			b["sub"] = "system:serviceaccount:mt-kube-k1:other"
			pod(b)["serviceaccount"] = map[string]any{"name": "other", "uid": "u"}
		}, ReasonIdentity},
		"another namespace": {func(b map[string]any) {
			b["sub"] = "system:serviceaccount:default:meshgw"
			pod(b)["namespace"] = "default"
		}, ReasonIdentity},
		"subject disagrees": {func(b map[string]any) { b["sub"] = "system:serviceaccount:mt-kube-k1:other" },
			ReasonMalformed},
		"subject not a SA":   {func(b map[string]any) { b["sub"] = "admin" }, ReasonMalformed},
		"namespace mismatch": {func(b map[string]any) { pod(b)["namespace"] = "other" }, ReasonMalformed},
		"SA mismatch": {func(b map[string]any) {
			pod(b)["serviceaccount"] = map[string]any{"name": "other", "uid": "u"}
		}, ReasonMalformed},
		"other pod": {func(b map[string]any) { pod(b)["pod"] = map[string]any{"name": "meshgw-0", "uid": "u"} },
			ReasonIdentity},
		"pod of another StatefulSet": {func(b map[string]any) {
			pod(b)["pod"] = map[string]any{"name": "other-1", "uid": "u"}
		}, ReasonIdentity},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			body := claims()
			test.change(body)
			_, err := Verify(token(t, header("RS256", "rsa-1"), body, "RS256"), rotationExpectation(t), testNow)
			if got := refusal(t, err); got != test.want {
				t.Fatalf("reason = %s, want %s", got, test.want)
			}
		})
	}
}

// Another cluster with the same issuer (every kind cluster has it) signs
// with other keys: its tokens fail.
func TestVerifyRefusesAnotherClusterWithTheSameIssuer(t *testing.T) {
	t.Parallel()
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	input := encodeJSON(t, header("RS256", "rsa-1")) + "." + encodeJSON(t, claims())
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, other, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(input+"."+b64(signature), rotationExpectation(t), testNow)
	if got := refusal(t, err); got != ReasonSignature {
		t.Fatalf("reason = %s, want %s", got, ReasonSignature)
	}
}

// Expectations missing what a rotation compares are refused before any
// token is read: a caller cannot skip the identity checks by accident.
func TestVerifyRefusesPartialExpectations(t *testing.T) {
	t.Parallel()
	raw := token(t, header("RS256", "rsa-1"), claims(), "RS256")
	for name, change := range map[string]func(*Expectation){
		"no issuer":        func(e *Expectation) { e.Issuer = "" },
		"no keys":          func(e *Expectation) { e.JWKS = kubejoin.JWKS{} },
		"pod without SA":   func(e *Expectation) { e.ServiceAccount = "" },
		"SA without pod":   func(e *Expectation) { e.PodName = "" },
		"pod without name": func(e *Expectation) { e.Namespace = "" },
	} {
		expect := rotationExpectation(t)
		change(&expect)
		if _, err := Verify(raw, expect, testNow); !errors.Is(err, ErrInvalidExpectation) {
			t.Errorf("%s: Verify() error = %v, want ErrInvalidExpectation", name, err)
		}
	}
}

// A refusal never carries the token or its claims.
func TestRefusalsCarryNoToken(t *testing.T) {
	t.Parallel()
	body := claims()
	body["sub"] = "system:serviceaccount:mt-kube-k1:secret-looking-name"
	raw := token(t, header("RS256", "rsa-1"), body, "RS256")
	_, err := Verify(raw, rotationExpectation(t), testNow)
	if err == nil {
		t.Fatal("Verify() accepted another subject")
	}
	text := err.Error()
	for _, leak := range append(strings.Split(raw, "."), "secret-looking-name", "6c1e5b8e") {
		if leak != "" && strings.Contains(text, leak) {
			t.Fatalf("error %q contains %q", text, leak)
		}
	}
}

func FuzzVerify(f *testing.F) {
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0xIn0.e30.AA")
	f.Fuzz(func(t *testing.T, raw string) {
		_, err := Verify(raw, rotationExpectation(t), testNow)
		var refused *RefusedError
		if err == nil || !errors.As(err, &refused) {
			t.Fatalf("Verify(%q) error = %v, want a refusal", raw, err)
		}
	})
}

// The edges of the time rules are accepted.
func TestVerifyAcceptsTimeEdges(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(map[string]any){
		"nbf and iat at the skew": func(b map[string]any) {
			b["iat"], b["nbf"] = testNow.Add(ClockSkew).Unix(), testNow.Add(ClockSkew).Unix()
		},
		"one second left": func(b map[string]any) { b["exp"] = testNow.Add(time.Second).Unix() },
		"lives exactly 15 minutes": func(b map[string]any) {
			b["iat"], b["nbf"] = testNow.Add(-6*time.Minute).Unix(), testNow.Add(-6*time.Minute).Unix()
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			body := claims()
			change(body)
			if _, err := Verify(token(t, header("RS256", "rsa-1"), body, "RS256"), rotationExpectation(t),
				testNow); err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}

// A token signed by a key the trust lacks names that key, so an
// administrator knows which key the cluster signs with now (K1.1b); a kid
// that is not 1 to 128 printable characters is not passed on.
func TestUnknownKeyRefusalNamesTheKey(t *testing.T) {
	t.Parallel()
	for kid, want := range map[string]string{ //nolint:gosec // G101: key IDs, which are public
		"W5g6JhuNGLKpWbGKkY1h_vyNJWNV3OHpeiEJLThDJhE": "W5g6JhuNGLKpWbGKkY1h_vyNJWNV3OHpeiEJLThDJhE",
		strings.Repeat("k", 129):                      "",
		"a\u0001b":                                    "",
	} {
		_, err := Verify(token(t, header("RS256", kid), claims(), "RS256"), rotationExpectation(t), testNow)
		refused, ok := errors.AsType[*RefusedError](err)
		if !ok || refused.Reason != ReasonUnknownKey || refused.KeyID != want {
			t.Fatalf("Verify(kid %q) = %+v, want unknown key %q", kid, refused, want)
		}
	}
	// Other refusals name no key.
	_, err := Verify(token(t, header("RS256", "rsa-1"), claims(), "ES256"), rotationExpectation(t), testNow)
	if refused, ok := errors.AsType[*RefusedError](err); !ok || refused.KeyID != "" {
		t.Fatalf("Verify(bad signature) = %+v", refused)
	}
}
