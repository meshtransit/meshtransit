package flowlog

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Fixed vectors: Core and the receiver must canonicalise a URL to the same
// bytes, or a sealed secret does not open (push destinations design N-6).
func TestCanonicalURL(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		"https://es.example.com":                      "https://es.example.com:443",
		"HTTPS://ES.Example.COM/":                     "https://es.example.com:443",
		"https://es.example.com:9243":                 "https://es.example.com:9243",
		"https://es.example.com:443/proxy/es/":        "https://es.example.com:443/proxy/es",
		"https://my-deploy.es.us-east-1.aws.found.io": "https://my-deploy.es.us-east-1.aws.found.io:443",
		"https://203.0.113.7:9200":                    "https://203.0.113.7:9200",
		"https://xn--bcher-kva.example":               "https://xn--bcher-kva.example:443",
		"https://es.example.com/A_b-9":                "https://es.example.com:443/A_b-9",
	} {
		got, err := CanonicalURL(raw)
		if err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", raw, got, err, want)
		}
		again, err := CanonicalURL(got)
		if err != nil || again != got {
			t.Errorf("%q is not stable: %q %v", got, again, err)
		}
	}
	for _, raw := range []string{
		"", "http://es.example.com", "https://user:pass@es.example.com", "https://es.example.com?x=1",
		"https://es.example.com#x", "https://es.example.com:8080", "https://es.example.com:0443",
		"https://es.example.com:", "https://localhost", "https://es", "https://[::1]:9200", "https://es.example.com.",
		"https://es.example.com/a/../b", "https://es.example.com/a//b", "https://es.example.com/a.b",
		"https://es.example.com/%2e%2e", "https://bücher.example", "https://es.example.com/ a", "https://-es.example.com",
		"https://es_x.example.com", "https://1.2.3", "https://999.1.1.1", "https://01.2.3.4", "ftp://es.example.com",
		"//es.example.com", "https:es.example.com", "https://es.example.com\\x", "https://" + strings.Repeat("a", 64) + ".com",
		"https://es.example.com:9200:9200", "https://1.2.3.0x4", "https://a.0x7f", "https://a.1b", "https://h.example:9200#",
		"https://h.example?", "https://u@h.example",
	} {
		if got, err := CanonicalURL(raw); err == nil {
			t.Errorf("%q: accepted as %q", raw, got)
		}
	}
}

func TestDestinationFields(t *testing.T) {
	t.Parallel()
	if !ValidDatadogSite("datadoghq.eu") || ValidDatadogSite("ddog-gov.com") || ValidDatadogSite("evil.com") {
		t.Fatal("datadog sites")
	}
	if region, ok := ParseStreamARN("arn:aws:kinesis:eu-west-1:123456789012:stream/flow-logs"); !ok || region != "eu-west-1" {
		t.Fatalf("arn: %q %t", region, ok)
	}
	for _, arn := range []string{
		"arn:aws-cn:kinesis:cn-north-1:123456789012:stream/x", "arn:aws:kinesis:eu-west-1:12345678901:stream/x",
		"arn:aws:firehose:eu-west-1:123456789012:deliverystream/x", "arn:aws:kinesis:moon-1:123456789012:stream/x",
		"arn:aws:kinesis:eu-west-1:123456789012:stream/a/b",
	} {
		if _, ok := ParseStreamARN(arn); ok {
			t.Errorf("%q accepted", arn)
		}
	}
	for target, want := range map[string]bool{
		"logs-meshtransit.connection-default": true, "meshtransit-connections": true, "Logs": false, "-x": false,
		"_x": false, ".x": false, "a b": false, "a/b": false, "a:b": false, "a*": false, "": false,
		strings.Repeat("a", 256): false,
	} {
		if ValidTarget(target) != want {
			t.Errorf("target %q: want %t", target, want)
		}
	}
}

func destinationBinding(provider string) DestinationBinding {
	binding := DestinationBinding{ //nolint:gosec // test IDs, no secret
		WorkspaceID: "01a11ae3-a2eb-721d-81f8-af13a32493a0", CredentialID: "01a19ad3-1e1b-7298-950b-9538264e51ea",
		Version: 3, Provider: provider,
	}
	switch provider {
	case ProviderElasticsearch:
		binding.URL, binding.Flavor = "https://es.example.com:9243", FlavorElasticsearch
	case ProviderDatadog:
		binding.Site = "datadoghq.eu"
	case ProviderKinesis:
		binding.Region, binding.StreamARN = "eu-west-1", "arn:aws:kinesis:eu-west-1:123456789012:stream/flow-logs"
	}
	return binding
}

func testSecret(provider string) Secret {
	switch provider {
	case ProviderElasticsearch:
		return Secret{Kind: SecretAPIKey, ID: "VuaCfGcBCdbkQm-e5aOx", Key: "ui2lp2axTNmsyakw9tvNnw"}
	case ProviderDatadog:
		return Secret{Kind: SecretDatadogKey, Key: strings.Repeat("ab", 16)}
	}
	return Secret{Kind: SecretAWSKeys, ID: "AKIAIOSFODNN7EXAMPLE", Key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"} //nolint:gosec // AWS's documented example key
}

const testCA = "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n"

// The info bytes are the contract between Core and the receiver: these
// vectors fail on any reordering (review p1a T1).
func TestBindingInfoVectors(t *testing.T) {
	t.Parallel()
	head := "meshtransit/log-destination-credential/v2\x0001a11ae3-a2eb-721d-81f8-af13a32493a0\x00" +
		"01a19ad3-1e1b-7298-950b-9538264e51ea\x003\x00"
	withCA := destinationBinding(ProviderElasticsearch)
	withCA.CAPEM = []byte(testCA)
	for name, test := range map[string]struct {
		binding DestinationBinding
		want    string
	}{
		"elasticsearch": {destinationBinding(ProviderElasticsearch),
			head + "elasticsearch\x00https://es.example.com:9243\x00elasticsearch\x00\x00\x00\x00"},
		"elasticsearch with a CA": {withCA, head + "elasticsearch\x00https://es.example.com:9243\x00elasticsearch\x00" +
			CAHash([]byte(testCA)) + "\x00\x00\x00"},
		"datadog": {destinationBinding(ProviderDatadog), head + "datadog\x00\x00\x00\x00datadoghq.eu\x00\x00"},
		"kinesis": {destinationBinding(ProviderKinesis),
			head + "kinesis\x00\x00\x00\x00\x00eu-west-1\x00arn:aws:kinesis:eu-west-1:123456789012:stream/flow-logs"},
	} {
		if err := test.binding.check(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := string(test.binding.info()); got != test.want {
			t.Errorf("%s:\n got %q\nwant %q", name, got, test.want)
		}
	}
	if CAHash(nil) != "" || len(CAHash([]byte(testCA))) != 64 {
		t.Fatal("CAHash")
	}
}

func TestBindingChecks(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*DestinationBinding){
		"a URL not canonical": func(b *DestinationBinding) { b.URL = "https://ES.example.com:9243" },
		"an upper-case UUID":  func(b *DestinationBinding) { b.WorkspaceID = strings.ToUpper(b.WorkspaceID) },
		"version 0":           func(b *DestinationBinding) { b.Version = 0 },
		"an unknown flavor":   func(b *DestinationBinding) { b.Flavor = "solr" },
		"a CA that is no PEM": func(b *DestinationBinding) { b.CAPEM = []byte("x") },
		"a CA too large": func(b *DestinationBinding) {
			b.CAPEM = []byte(testCA + strings.Repeat("x", MaxCAPEM))
		},
		"a site on elasticsearch":   func(b *DestinationBinding) { b.Site = "datadoghq.eu" },
		"a region on elasticsearch": func(b *DestinationBinding) { b.Region = "eu-west-1" },
	} {
		binding := destinationBinding(ProviderElasticsearch)
		change(&binding)
		if binding.check() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	kinesis := destinationBinding(ProviderKinesis)
	kinesis.Region = "us-east-1"
	datadog := destinationBinding(ProviderDatadog)
	datadog.URL = "https://es.example.com:443"
	unknown := destinationBinding(ProviderDatadog)
	unknown.Provider = ProviderS3
	for name, binding := range map[string]DestinationBinding{
		"a region not the stream's": kinesis, "a URL on datadog": datadog, "an S3 provider": unknown,
	} {
		if binding.check() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Plaintexts the receiver must refuse even when they open: another version
// byte, a kind the provider does not take, bad lengths, trailing bytes.
func TestOpenSecretRefusesBadPlaintext(t *testing.T) {
	t.Parallel()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := destinationBinding(ProviderKinesis)
	good := func(edit func([]byte) []byte) []byte {
		plain := []byte{sealedSecretVersion, byte(SecretAWSKeys), 0, 20}
		plain = append(plain, "AKIAIOSFODNN7EXAMPLE"...)
		plain = append(plain, 0, 1, 'x')
		return edit(plain)
	}
	for name, plain := range map[string][]byte{
		"version 1":      good(func(p []byte) []byte { p[0] = 1; return p }),
		"a basic kind":   good(func(p []byte) []byte { p[1] = byte(SecretBasic); return p }),
		"trailing bytes": good(func(p []byte) []byte { return append(p, 0) }),
		"a short key":    good(func(p []byte) []byte { return p[:len(p)-1] }),
		"a long ID":      good(func(p []byte) []byte { p[3] = 200; return p }),
		"empty":          {},
	} {
		public, err := hpke.NewDHKEMPublicKey(key.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		kdf, aead := suite()
		sealed, err := hpke.Seal(public, kdf, aead, binding.info(), plain)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSecret(key, sealed, binding); !errors.Is(err, ErrSealedCredential) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The same bytes, well formed, open.
	public, _ := hpke.NewDHKEMPublicKey(key.PublicKey())
	kdf, aead := suite()
	sealed, _ := hpke.Seal(public, kdf, aead, binding.info(), good(func(p []byte) []byte { return p }))
	if _, err := OpenSecret(key, sealed, binding); err != nil {
		t.Fatalf("well formed: %v", err)
	}
}

// OpenSearch takes no Elastic API key: neither sealed nor opened.
func TestOpenSearchRefusesAPIKey(t *testing.T) {
	t.Parallel()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := destinationBinding(ProviderElasticsearch)
	binding.Flavor = FlavorOpenSearch
	if _, err := SealSecret(key.PublicKey(), testSecret(ProviderElasticsearch), binding); err == nil {
		t.Fatal("sealed")
	}
	if _, err := SealSecret(key.PublicKey(), Secret{Kind: SecretBasic, ID: "admin", Key: "x"}, binding); err != nil {
		t.Fatalf("basic: %v", err)
	}
}

// A sealed secret opens only under the binding it was sealed for: another
// URL, flavor, CA, site, stream, version or provider fails (design §5 S1).
func TestSecretBinding(t *testing.T) {
	t.Parallel()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{ProviderElasticsearch, ProviderDatadog, ProviderKinesis} {
		binding, secret := destinationBinding(provider), testSecret(provider)
		sealed, err := SealSecret(key.PublicKey(), secret, binding)
		if err != nil {
			t.Fatalf("%s: %v", provider, err)
		}
		opened, err := OpenSecret(key, sealed, binding)
		if err != nil || opened.Kind != secret.Kind || opened.ID != secret.ID || opened.Key != secret.Key {
			t.Fatalf("%s: %v", provider, err)
		}
		for name, change := range map[string]func(*DestinationBinding){
			"version":   func(b *DestinationBinding) { b.Version++ },
			"workspace": func(b *DestinationBinding) { b.WorkspaceID = "01a11ae3-a2eb-721d-81f8-af13a32493a1" },
			"url":       func(b *DestinationBinding) { b.URL = "https://attacker.example.com:443" },
			"flavor":    func(b *DestinationBinding) { b.Flavor = FlavorOpenSearch },
			"ca":        func(b *DestinationBinding) { b.CAPEM = []byte(testCA) },
			"site":      func(b *DestinationBinding) { b.Site = "datadoghq.com" },
			"stream": func(b *DestinationBinding) {
				b.StreamARN = "arn:aws:kinesis:eu-west-1:123456789012:stream/other"
			},
		} {
			changed := binding
			change(&changed)
			_, err := OpenSecret(key, sealed, changed)
			if err == nil {
				t.Errorf("%s: opened under another %s", provider, name)
			}
			// A change that applies to the provider is a valid binding: HPKE
			// refuses it, not the field checks.
			if changed.check() == nil && !errors.Is(err, ErrSealedCredential) {
				t.Errorf("%s: another %s: %v", provider, name, err)
			}
		}
	}
	// A v1 storage credential is not a v2 secret, nor the reverse.
	s3 := CredentialBinding{ //nolint:gosec // test IDs, no secret
		WorkspaceID: "01a11ae3-a2eb-721d-81f8-af13a32493a0", CredentialID: "01a19ad3-1e1b-7298-950b-9538264e51ea",
		Version: 3, Provider: ProviderS3,
	}
	sealed, err := SealCredential(key.PublicKey(), Credential{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "x"}, s3) //nolint:gosec // AWS's documented example key
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSecret(key, sealed, destinationBinding(ProviderKinesis)); !errors.Is(err, ErrSealedCredential) {
		t.Fatalf("a v1 credential opened as v2: %v", err)
	}
}

func TestSecretBounds(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		provider string
		secret   Secret
		valid    bool
	}{
		"api key":                {ProviderElasticsearch, testSecret(ProviderElasticsearch), true},
		"basic":                  {ProviderElasticsearch, Secret{Kind: SecretBasic, ID: "elastic", Key: "p@ss"}, true},
		"basic with colon":       {ProviderElasticsearch, Secret{Kind: SecretBasic, ID: "a:b", Key: "x"}, false},
		"api key on datadog":     {ProviderDatadog, testSecret(ProviderElasticsearch), false},
		"datadog key":            {ProviderDatadog, testSecret(ProviderDatadog), true},
		"datadog key upper case": {ProviderDatadog, Secret{Kind: SecretDatadogKey, Key: strings.Repeat("AB", 16)}, false},
		"datadog with an ID":     {ProviderDatadog, Secret{Kind: SecretDatadogKey, ID: "x", Key: strings.Repeat("ab", 16)}, false},
		"aws keys":               {ProviderKinesis, testSecret(ProviderKinesis), true},
		"aws short ID":           {ProviderKinesis, Secret{Kind: SecretAWSKeys, ID: "AKIA", Key: "x"}, false},
		"empty key":              {ProviderElasticsearch, Secret{Kind: SecretAPIKey, ID: "abc", Key: ""}, false},
		"S3 provider":            {ProviderS3, testSecret(ProviderKinesis), false},
	} {
		if err := test.secret.Check(test.provider); (err == nil) != test.valid {
			t.Errorf("%s: %v", name, err)
		}
	}
	for secret, want := range map[Secret]string{
		testSecret(ProviderElasticsearch):    "5aOx",
		{Kind: SecretBasic, ID: "elastic"}:   "stic",
		{Kind: SecretBasic, ID: "a.b"}:       "****",
		{Kind: SecretBasic, ID: "user@x.io"}: "****",
		testSecret(ProviderDatadog):          "abab",
		testSecret(ProviderKinesis):          "MPLE",
	} {
		if got := secret.Suffix(); got != want {
			t.Errorf("%v suffix %q, want %q", secret.Kind, got, want)
		}
	}
}

// A secret never prints, logs or encodes its key.
func TestSecretRedacted(t *testing.T) {
	t.Parallel()
	for _, secret := range []Secret{testSecret(ProviderKinesis), testSecret(ProviderDatadog)} {
		secretRedacted(t, secret)
	}
}

func secretRedacted(t *testing.T, secret Secret) {
	t.Helper()
	for _, shown := range []string{fmt.Sprint(secret), fmt.Sprintf("%+v %#v %s", secret, secret, secret), secret.LogValue().String()} {
		if strings.Contains(shown, secret.Key) || secret.ID != "" && strings.Contains(shown, secret.ID) {
			t.Fatalf("shown: %s", shown)
		}
	}
	if _, err := json.Marshal(secret); err == nil {
		t.Fatal("encoded")
	}
}
