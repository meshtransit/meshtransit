package dnszone

import (
	"runtime/debug"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"meshtransit.net/core/internal/domain/dnsname"
)

// Root is the domain of the root zone: every name no other zone holds.
const Root = "."

// Domain is a canonical zone domain: lowercase A-labels without a trailing
// dot, or Root.
type Domain string

// String returns the domain as stored.
func (domain Domain) String() string { return string(domain) }

// IsRoot reports the root zone.
func (domain Domain) IsRoot() bool { return domain == Root }

// Covers reports whether name is the domain or under it; the root covers
// every name.
func (domain Domain) Covers(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	return domain.IsRoot() || name == string(domain) || strings.HasSuffix(name, "."+string(domain))
}

// Class says whether a domain exists on the Internet (under a top-level
// domain ICANN delegates) or is private.
type Class string

// Domain classes.
const (
	ClassPrivate Class = "private"
	ClassPublic  Class = "public"
)

// Names are what a domain is checked against: the deployment's mesh suffix
// and the names of its own services, which no zone may cover.
type Names struct {
	Suffix    dnsname.Suffix
	Protected []string
}

// specialUse are names no zone may be: they are answered by the host or
// never resolved (RFC 6761, RFC 6762, RFC 7686, RFC 9476).
var specialUse = []string{"local", "localhost", "invalid", "test", "onion", "example", "arpa", "alt"}

// homeArpa is the one name under arpa a zone may forward (RFC 8375).
const homeArpa = "home.arpa"

// maximumDomainBytes bounds a domain without its trailing dot.
const maximumDomainBytes = 253

var lookup = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(true))

// ParseDomain canonicalizes input (case, trailing dot, Unicode labels to
// A-labels) and checks it: a hostname of 1 to 253 bytes, no special-use name
// but home.arpa, no public suffix, nothing overlapping the mesh names, and no
// zone but the root holding a protected name. It returns the domain and its
// class.
func ParseDomain(input string, names Names) (Domain, Class, error) {
	if input == Root {
		return Root, ClassPrivate, nil
	}
	trimmed := strings.TrimSuffix(strings.TrimSpace(input), ".")
	if trimmed == "" || strings.HasPrefix(trimmed, ".") {
		return "", "", ErrInvalid
	}
	ascii, err := lookup.ToASCII(trimmed)
	if err != nil {
		return "", "", ErrInvalid
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > maximumDomainBytes || !hostname(ascii) {
		return "", "", ErrInvalid
	}
	domain := Domain(ascii)
	if specialUseDomain(ascii) {
		return "", "", ErrDomainSpecialUse
	}
	if !names.Suffix.IsValid() || overlaps(ascii, names.Suffix.String()) {
		return "", "", ErrDomainMeshSuffix
	}
	for _, protected := range names.Protected {
		if domain.Covers(protected) {
			return "", "", ErrDomainCoversControl
		}
	}
	class, err := classify(ascii)
	if err != nil {
		return "", "", err
	}
	return domain, class, nil
}

// classify finds a domain's class: private under a top-level domain ICANN
// does not delegate (internal, lan, corp) and under home.arpa; public under
// one ICANN delegates, unless it is itself a public suffix.
func classify(domain string) (Class, error) {
	if domain == homeArpa || strings.HasSuffix(domain, "."+homeArpa) {
		return ClassPrivate, nil
	}
	topLevel := domain[strings.LastIndexByte(domain, '.')+1:]
	if _, icann := publicsuffix.PublicSuffix(topLevel); !icann {
		return ClassPrivate, nil
	}
	if suffix, _ := publicsuffix.PublicSuffix(domain); suffix == domain {
		return "", ErrDomainPublicSuffix
	}
	return ClassPublic, nil
}

func specialUseDomain(domain string) bool {
	if domain == homeArpa || strings.HasSuffix(domain, "."+homeArpa) {
		return false
	}
	for _, name := range specialUse {
		if domain == name || strings.HasSuffix(domain, "."+name) {
			return true
		}
	}
	return false
}

// overlaps reports a domain that is suffix, lies under it, or holds it.
func overlaps(domain, suffix string) bool {
	return domain == suffix || strings.HasSuffix(domain, "."+suffix) || strings.HasSuffix(suffix, "."+domain)
}

// hostname reports lowercase letter-digit-hyphen labels of 1 to 63 bytes,
// none starting or ending with a hyphen.
func hostname(domain string) bool {
	for label := range strings.SplitSeq(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			character := label[i]
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

// PublicListVersion names the Public Suffix List this binary classifies
// with: the version of golang.org/x/net it is built with. A zone keeps the
// class it got when created; a newer list never reclassifies it.
func PublicListVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, module := range info.Deps {
			if module.Path == "golang.org/x/net" {
				return "x/net " + module.Version
			}
		}
	}
	return "x/net unknown"
}
