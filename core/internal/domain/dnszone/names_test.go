package dnszone

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/dnsname"
)

func TestParseLabel(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]string{
		"@":                     "@",
		" Git ":                 "git",
		"a.b":                   "a.b",
		"bücher":                "xn--bcher-kva",
		"":                      "",
		".git":                  "",
		"git.":                  "",
		"-git":                  "",
		"git_lab":               "",
		"a..b":                  "",
		strings.Repeat("a", 64): "",
	} {
		got, err := ParseLabel(input)
		if (err != nil) != (want == "") || got != want {
			t.Errorf("ParseLabel(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
}

func TestNameIn(t *testing.T) {
	t.Parallel()
	if name, err := NameIn("git", "corp.internal"); err != nil || name != "git.corp.internal" {
		t.Errorf("git: %q, %v", name, err)
	}
	if name, err := NameIn(Apex, "corp.internal"); err != nil || name != "corp.internal" {
		t.Errorf("apex: %q, %v", name, err)
	}
	if _, err := NameIn("git", Root); err == nil {
		t.Error("a name in the root zone")
	}
	long := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 50)
	if _, err := NameIn(long, "corp.internal"); err == nil {
		t.Error("a name longer than 253 bytes")
	}
}

func TestParseCNAME(t *testing.T) {
	t.Parallel()
	names := Names{Suffix: dnsname.Default()}
	for input, want := range map[string]string{
		"Corp.Atlassian.NET.":            "corp.atlassian.net",
		"wiki.home.arpa":                 "wiki.home.arpa",
		"büro.example.com":               "xn--bro-hoa.example.com",
		"printer.local":                  "",
		"x.onion":                        "",
		"mesh.internal":                  "",
		"git.073438549244.mesh.internal": "",
		"":                               "",
		"a..b":                           "",
	} {
		got, err := ParseCNAME(input, names)
		if want == "" {
			if !errors.Is(err, ErrNameTargetInvalid) {
				t.Errorf("ParseCNAME(%q) = %q, %v; want ErrNameTargetInvalid", input, got, err)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("ParseCNAME(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
}

func TestNameDefinitionValidate(t *testing.T) {
	t.Parallel()
	device := mustDevice(t)
	addresses := func(values ...string) []netip.Addr {
		parsed := make([]netip.Addr, 0, len(values))
		for _, value := range values {
			parsed = append(parsed, netip.MustParseAddr(value))
		}
		return parsed
	}
	nine := make([]string, 0, 9)
	for index := range 9 {
		nine = append(nine, netip.AddrFrom4([4]byte{10, 0, 0, byte(index + 1)}).String())
	}
	for name, test := range map[string]struct {
		definition NameDefinition
		want       error
	}{
		"device":    {NameDefinition{Kind: NameAddress, Target: NameTarget{DeviceID: device}}, nil},
		"private":   {NameDefinition{Kind: NameAddress, Target: NameTarget{Addresses: addresses("10.0.5.20")}}, nil},
		"both":      {NameDefinition{Kind: NameAddress, Target: NameTarget{Addresses: addresses("2001:db8::1", "192.0.2.1")}}, nil},
		"cname":     {NameDefinition{Kind: NameCNAME, Target: NameTarget{CNAME: "corp.atlassian.net"}}, nil},
		"no target": {NameDefinition{Kind: NameAddress}, ErrInvalid},
		"device and address": {NameDefinition{Kind: NameAddress, Target: NameTarget{DeviceID: device,
			Addresses: addresses("10.0.5.20")}}, ErrInvalid},
		"nine":             {NameDefinition{Kind: NameAddress, Target: NameTarget{Addresses: addresses(nine...)}}, ErrInvalid},
		"twice":            {NameDefinition{Kind: NameAddress, Target: NameTarget{Addresses: addresses("10.0.5.20", "10.0.5.20")}}, ErrInvalid},
		"mesh":             {NameDefinition{Kind: NameAddress, Target: NameTarget{Addresses: addresses("100.64.1.2")}}, ErrNameTargetInvalid},
		"share alias":      {NameDefinition{Kind: NameAddress, Target: NameTarget{Addresses: addresses("198.18.0.9")}}, ErrNameTargetInvalid},
		"unique local":     {NameDefinition{Kind: NameAddress, Target: NameTarget{Addresses: addresses("fd7a::1")}}, ErrNameTargetInvalid},
		"loopback":         {NameDefinition{Kind: NameAddress, Target: NameTarget{Addresses: addresses("127.0.0.1")}}, ErrNameTargetInvalid},
		"link-local":       {NameDefinition{Kind: NameAddress, Target: NameTarget{Addresses: addresses("fe80::1")}}, ErrNameTargetInvalid},
		"multicast":        {NameDefinition{Kind: NameAddress, Target: NameTarget{Addresses: addresses("239.1.1.1")}}, ErrNameTargetInvalid},
		"broadcast":        {NameDefinition{Kind: NameAddress, Target: NameTarget{Addresses: addresses("255.255.255.255")}}, ErrNameTargetInvalid},
		"unspecified":      {NameDefinition{Kind: NameAddress, Target: NameTarget{Addresses: addresses("::")}}, ErrNameTargetInvalid},
		"IPv4-mapped":      {NameDefinition{Kind: NameAddress, Target: NameTarget{Addresses: addresses("::ffff:10.0.0.1")}}, ErrNameTargetInvalid},
		"cname and device": {NameDefinition{Kind: NameCNAME, Target: NameTarget{CNAME: "a.example.com", DeviceID: device}}, ErrInvalid},
		"empty cname":      {NameDefinition{Kind: NameCNAME}, ErrInvalid},
		"unknown kind":     {NameDefinition{Kind: "txt", Target: NameTarget{CNAME: "a.example.com"}}, ErrInvalid},
	} {
		if err := test.definition.Validate(); !errors.Is(err, test.want) {
			t.Errorf("%s: %v, want %v", name, err, test.want)
		}
	}
}
