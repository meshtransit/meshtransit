package dnszone

import (
	"errors"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/dnsname"
)

func testNames(t *testing.T) Names {
	t.Helper()
	return Names{Suffix: dnsname.Default(), Protected: []string{"control.example.net", "id.example.net"}}
}

func TestParseDomainCanonicalizesAndClassifies(t *testing.T) {
	t.Parallel()
	names := testNames(t)
	for _, test := range []struct {
		input  string
		domain Domain
		class  Class
	}{
		{".", Root, ClassPrivate},
		{"corp.internal", "corp.internal", ClassPrivate},
		{"Corp.Internal.", "corp.internal", ClassPrivate},
		{"lan", "lan", ClassPrivate},
		{"corp", "corp", ClassPrivate},
		{"home.arpa", "home.arpa", ClassPrivate},
		{"nas.home.arpa", "nas.home.arpa", ClassPrivate},
		{"corp.com", "corp.com", ClassPublic},
		{"ad.corp.co.uk", "ad.corp.co.uk", ClassPublic},
		{"bücher.de", "xn--bcher-kva.de", ClassPublic},
		{"intranet.xn--p1ai", "intranet.xn--p1ai", ClassPublic},
	} {
		domain, class, err := ParseDomain(test.input, names)
		if err != nil || domain != test.domain || class != test.class {
			t.Errorf("ParseDomain(%q) = %q, %q, %v; want %q, %q", test.input, domain, class, err, test.domain,
				test.class)
		}
	}
}

func TestParseDomainRefuses(t *testing.T) {
	t.Parallel()
	names := testNames(t)
	for _, test := range []struct {
		input string
		want  error
	}{
		{"", ErrInvalid},
		{"..", ErrInvalid},
		{".corp", ErrInvalid},
		{"a..b", ErrInvalid},
		{"-bad.corp", ErrInvalid},
		{"under_score.corp", ErrInvalid},
		{strings.Repeat("a", 64) + ".corp", ErrInvalid},
		{strings.Repeat("abcdefghi.", 26) + "corp", ErrInvalid},
		{"printer.local", ErrDomainSpecialUse},
		{"localhost", ErrDomainSpecialUse},
		{"x.test", ErrDomainSpecialUse},
		{"10.in-addr.arpa", ErrDomainSpecialUse},
		{"example", ErrDomainSpecialUse},
		{"onion", ErrDomainSpecialUse},
		{"thing.alt", ErrDomainSpecialUse},
		{"com", ErrDomainPublicSuffix},
		{"co.uk", ErrDomainPublicSuffix},
		{"vn", ErrDomainPublicSuffix},
		{"github.io", ErrDomainPublicSuffix},
		{"xn--p1ai", ErrDomainPublicSuffix},
		{"рф", ErrDomainPublicSuffix},
		{"mesh.internal", ErrDomainMeshSuffix},
		{"internal", ErrDomainMeshSuffix},
		{"a.b.mesh.internal", ErrDomainMeshSuffix},
		{"shared.mesh.internal", ErrDomainMeshSuffix},
		{"example.net", ErrDomainCoversControl},
		{"control.example.net", ErrDomainCoversControl},
	} {
		if _, _, err := ParseDomain(test.input, names); !errors.Is(err, test.want) {
			t.Errorf("ParseDomain(%q) = %v, want %v", test.input, err, test.want)
		}
	}
	// A deployment without a valid suffix decides nothing.
	if _, _, err := ParseDomain("corp.internal", Names{}); !errors.Is(err, ErrDomainMeshSuffix) {
		t.Errorf("no suffix: %v", err)
	}
}

func TestDomainCovers(t *testing.T) {
	t.Parallel()
	if !Domain("corp.com").Covers("A.corp.com.") || !Domain("corp.com").Covers("corp.com") ||
		Domain("corp.com").Covers("notcorp.com") || !Domain(Root).Covers("anything") {
		t.Fatal("Covers")
	}
}

func TestPublicListVersionNamesTheList(t *testing.T) {
	t.Parallel()
	if version := PublicListVersion(); !strings.HasPrefix(version, "x/net ") || len(version) > 64 {
		t.Fatalf("PublicListVersion() = %q", version)
	}
}
