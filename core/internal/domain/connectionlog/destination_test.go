package connectionlog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/shared/flowlog"
)

// testCA is a self-signed certificate in PEM, made once.
var testCA = func() string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, NotBefore: time.Unix(1_800_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}()

func TestValidCAPEM(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		pem   string
		valid bool
	}{
		"one certificate":  {testCA, true},
		"two certificates": {testCA + testCA, true},
		"CRLF line ends":   {strings.ReplaceAll(testCA, "\n", "\r\n"), true},
		"no certificate":   {"-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n", false},
		"a private key":    {strings.ReplaceAll(testCA, "CERTIFICATE", "PRIVATE KEY"), false},
		"trailing text":    {testCA + "x", false},
		"a NUL":            {testCA + "\x00", false},
		"not UTF-8":        {testCA + "\xff", false},
		"empty":            {"", false},
		"too large":        {testCA + strings.Repeat(" ", flowlog.MaxCAPEM), false},
	} {
		if ValidCAPEM([]byte(test.pem)) != test.valid {
			t.Errorf("%s: want %t", name, test.valid)
		}
	}
}

func pushPut(provider string) CredentialPut {
	put := CredentialPut{Name: "Logs", Provider: provider, Networks: []network.ID{}}
	switch provider {
	case flowlog.ProviderElasticsearch:
		put.PushSecret = &flowlog.Secret{Kind: flowlog.SecretAPIKey, ID: "VuaCfGcBCdbkQm-e5aOx", Key: "ui2lp2axTNmsyakw9tvNnw"}
		put.Destination = Destination{URL: "https://es.example.com:9243", Flavor: flowlog.FlavorElasticsearch,
			CAPEM: []byte(testCA)}
	case flowlog.ProviderDatadog:
		put.PushSecret = &flowlog.Secret{Kind: flowlog.SecretDatadogKey, Key: strings.Repeat("ab", 16)}
		put.Destination = Destination{Site: "datadoghq.eu"}
	case flowlog.ProviderKinesis:
		put.PushSecret = &flowlog.Secret{Kind: flowlog.SecretAWSKeys, ID: "AKIAIOSFODNN7EXAMPLE", Key: "x"} //nolint:gosec // AWS's documented example key ID
		put.Destination = Destination{Region: "eu-west-1",
			StreamARN: "arn:aws:kinesis:eu-west-1:123456789012:stream/flow-logs"}
	}
	return put
}

// A push credential takes its own secret and destination, together; the
// destination changes only with the secret (push destinations design §5 S1).
func TestPushCredentialChecks(t *testing.T) {
	t.Parallel()
	for _, provider := range []string{flowlog.ProviderElasticsearch, flowlog.ProviderDatadog, flowlog.ProviderKinesis} {
		if err := pushPut(provider).Check(); err != nil {
			t.Fatalf("%s: %v", provider, err)
		}
	}
	for name, edit := range map[string]func(*CredentialPut){
		"no secret on create": func(p *CredentialPut) { p.PushSecret = nil },
		"a destination without its secret": func(p *CredentialPut) {
			p.PushSecret, p.ExpectedVersion = nil, 3
		},
		"an S3 secret too": func(p *CredentialPut) {
			p.Secret = &flowlog.Credential{AccessKeyID: "TESTKEYID0000000EXAMPLE", SecretAccessKey: "s"}
		},
		"an account":          func(p *CredentialPut) { p.AccountID = strings.Repeat("a", 32) },
		"a URL not canonical": func(p *CredentialPut) { p.Destination.URL = "https://ES.example.com" },
		"a CA hash given":     func(p *CredentialPut) { p.Destination.CASHA256 = strings.Repeat("0", 64) },
		"a site":              func(p *CredentialPut) { p.Destination.Site = "datadoghq.eu" },
		"an unknown flavor":   func(p *CredentialPut) { p.Destination.Flavor = "solr" },
		"OpenSearch API key":  func(p *CredentialPut) { p.Destination.Flavor = flowlog.FlavorOpenSearch },
		"a Datadog secret":    func(p *CredentialPut) { p.PushSecret = pushPut(flowlog.ProviderDatadog).PushSecret },
		"another provider":    func(p *CredentialPut) { p.Provider = "splunk" },
		"an S3 provider":      func(p *CredentialPut) { p.Provider = flowlog.ProviderS3 },
		"a CA too large":      func(p *CredentialPut) { p.Destination.CAPEM = []byte(strings.Repeat("x", flowlog.MaxCAPEM+1)) },
		"a CA that is no certificate": func(p *CredentialPut) {
			p.Destination.CAPEM = []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
		},
		"no destination field": func(p *CredentialPut) { p.Destination = Destination{} },
	} {
		put := pushPut(flowlog.ProviderElasticsearch)
		edit(&put)
		if put.Check() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A rename keeps the destination: no secret, no destination.
	rename := pushPut(flowlog.ProviderKinesis)
	rename.PushSecret, rename.Destination, rename.ExpectedVersion = nil, Destination{}, 2
	if err := rename.Check(); err != nil {
		t.Fatalf("rename: %v", err)
	}
	region := pushPut(flowlog.ProviderKinesis)
	region.Destination.Region = "us-east-1"
	if region.Check() == nil {
		t.Fatal("a region not the stream's")
	}
	// S3 takes no push fields.
	s3 := CredentialPut{
		Name: "Logs", Provider: flowlog.ProviderS3, Networks: []network.ID{},
		Secret:      &flowlog.Credential{AccessKeyID: "TESTKEYID0000000EXAMPLE", SecretAccessKey: "s"},
		Destination: Destination{Site: "datadoghq.eu"},
	}
	if s3.Check() == nil {
		t.Fatal("an S3 credential with a destination")
	}
}

func TestPushSettingsChecks(t *testing.T) {
	t.Parallel()
	id := CredentialID(mustID(t, "01890f00-0000-7000-8000-000000000002"))
	base := Settings{Enabled: true, Credential: &id, WindowSeconds: 60}
	valid := map[string]func(*Settings){
		"elasticsearch": func(s *Settings) {
			s.Target, s.TargetKind = "logs-meshtransit.connection-default", TargetKindDataStream
		},
		"datadog": func(s *Settings) { s.Service, s.Tags = DefaultDatadogService, []string{"env:prod", "team/net"} },
		"kinesis": func(s *Settings) { s.RecordFormat = RecordFormatNDJSONBatch },
	}
	for name, edit := range valid {
		settings := base
		edit(&settings)
		if err := (SettingsReplacement{Settings: settings}).Check(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	tooMany := make([]string, MaximumDatadogTags+1)
	for index := range tooMany {
		tooMany[index] = "t"
	}
	for name, edit := range map[string]func(*Settings){
		"a target without kind":  func(s *Settings) { s.Target = "logs" },
		"a kind without target":  func(s *Settings) { s.TargetKind = TargetKindIndex },
		"an upper-case target":   func(s *Settings) { s.Target, s.TargetKind = "Logs", TargetKindIndex },
		"an unknown kind":        func(s *Settings) { s.Target, s.TargetKind = "logs", "alias" },
		"tags without a service": func(s *Settings) { s.Tags = []string{"a"} },
		"a tag with a comma":     func(s *Settings) { s.Service, s.Tags = "svc", []string{"a,b"} },
		"a service in capitals":  func(s *Settings) { s.Service = "Svc" },
		"21 tags":                func(s *Settings) { s.Service, s.Tags = "svc", tooMany },
		"an unknown format":      func(s *Settings) { s.RecordFormat = "csv" },
		"push fields without a credential": func(s *Settings) {
			s.Enabled, s.Credential, s.RecordFormat = false, nil, RecordFormatJSONLine
		},
	} {
		settings := base
		edit(&settings)
		if (SettingsReplacement{Settings: settings}).Check() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
