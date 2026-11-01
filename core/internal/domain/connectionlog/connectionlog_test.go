package connectionlog

import (
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/flowlog"
)

// The validators accept and refuse what the schema's do (schema 266).
func TestValidators(t *testing.T) {
	t.Parallel()
	for bucket, want := range map[string]bool{
		"logs": true, "meshtransit-logs-1": true, "ab": false, strings.Repeat("a", 64): false,
		"Logs": false, "my.logs": false, "-logs": false, "logs-": false, "xn--logs": false, "sthree-logs": false,
		"logs-s3alias": false, "logs--ol-s3": false, "logs--x-s3": false, "lo_gs": false,
	} {
		if ValidBucket(bucket) != want {
			t.Errorf("ValidBucket(%q) = %t", bucket, !want)
		}
	}
	for region, want := range map[string]bool{
		"eu-central-1": true, "ap-southeast-1": true, "us-east-1": true, "auto": false, "eu-central": false,
		"eu.central-1": false, "xx-central-1": false, "eu-central-0": false,
	} {
		if ValidRegion(flowlog.ProviderS3, region) != want {
			t.Errorf("ValidRegion(s3, %q) = %t", region, !want)
		}
	}
	if !ValidRegion(flowlog.ProviderR2, "auto") || ValidRegion(flowlog.ProviderR2, "eu-central-1") ||
		ValidRegion("gcs", "auto") {
		t.Error("R2 regions")
	}
	for prefix, want := range map[string]bool{
		"": true, "mesh": true, "mesh/logs_1-a": true, "/mesh": false, "mesh//logs": false, "mesh/../x": false,
		"Mesh": false, "a=b": false, strings.Repeat("a", 129): false,
	} {
		if ValidPrefix(prefix) != want {
			t.Errorf("ValidPrefix(%q) = %t", prefix, !want)
		}
	}
	for name, want := range map[string]bool{
		"Audit bucket": true, "a": true, "a.b_c-d": true, " a": false, "a ": false, "": false,
		strings.Repeat("a", 65): false, "a\nb": false,
	} {
		if ValidName(name) != want {
			t.Errorf("ValidName(%q) = %t", name, !want)
		}
	}
}

func TestPutAndReplacementChecks(t *testing.T) {
	t.Parallel()
	secret := &flowlog.Credential{AccessKeyID: "TESTKEYID0000000EXAMPLE", SecretAccessKey: "s"}
	network1 := network.ID(mustID(t, "01890f00-0000-7000-8000-000000000001"))
	good := CredentialPut{Name: "Logs", Provider: flowlog.ProviderS3, Secret: secret, Networks: []network.ID{network1}}
	if err := good.Check(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*CredentialPut){
		"create without secret": func(p *CredentialPut) { p.Secret = nil },
		"bad name":              func(p *CredentialPut) { p.Name = " x" },
		"s3 with account":       func(p *CredentialPut) { p.AccountID = strings.Repeat("a", 32) },
		"r2 without account":    func(p *CredentialPut) { p.Provider = flowlog.ProviderR2 },
		"unknown provider":      func(p *CredentialPut) { p.Provider = "gcs" },
		"duplicate network":     func(p *CredentialPut) { p.Networks = []network.ID{network1, network1} },
		"bad secret":            func(p *CredentialPut) { p.Secret = &flowlog.Credential{AccessKeyID: "x"} },
		"negative version":      func(p *CredentialPut) { p.ExpectedVersion = -1 },
	} {
		put := good
		change(&put)
		if put.Check() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	rename := good
	rename.ExpectedVersion, rename.Secret = 2, nil
	if rename.Check() != nil {
		t.Error("a rename without a secret was refused")
	}
	credential := CredentialID(mustID(t, "01890f00-0000-7000-8000-000000000002"))
	on := SettingsReplacement{Settings: Settings{
		Enabled: true, Credential: &credential, Bucket: "logs",
		Region: "eu-central-1", WindowSeconds: 60,
	}}
	if on.Check() != nil {
		t.Fatal("valid settings refused")
	}
	for name, change := range map[string]func(*Settings){
		"on without credential":     func(s *Settings) { s.Credential, s.Bucket, s.Region = nil, "", "" },
		"bucket without credential": func(s *Settings) { s.Credential = nil },
		"region without credential": func(s *Settings) { s.Credential, s.Bucket, s.Enabled = nil, "", false },
		"window small":              func(s *Settings) { s.WindowSeconds = 59 },
		"window large":              func(s *Settings) { s.WindowSeconds = 301 },
		"bad bucket":                func(s *Settings) { s.Bucket = "Logs" },
		"bad prefix":                func(s *Settings) { s.Prefix = "/x" },
	} {
		replacement := on
		change(&replacement.Settings)
		if replacement.Check() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if (SettingsReplacement{Settings: Settings{WindowSeconds: 60}}).Check() != nil {
		t.Error("off with nothing set refused")
	}
}

func mustID(t *testing.T, text string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
