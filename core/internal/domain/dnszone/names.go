package dnszone

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// Apex is the label of a zone's own domain.
const Apex = "@"

// Bounds of one name and of one name change (DNS design D2 §3.4, §6).
const (
	MaximumAddressesPerName = 8
	MaximumCNAMEChain       = 8
	MaximumNameOperations   = 100
)

// NameID identifies a name.
type NameID publicid.ID

// ParseNameID parses a name's public ID.
func ParseNameID(value string) (NameID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return NameID{}, ErrInvalid
	}
	return NameID(id), nil
}

// String returns the canonical public ID.
func (id NameID) String() string { return publicid.ID(id).String() }

// IsValid reports a UUIDv7 public ID.
func (id NameID) IsValid() bool { return publicid.ID(id).IsValid() }

// NameKind is what a name answers.
type NameKind string

// Name kinds.
const (
	// NameAddress answers A and AAAA: a Device's mesh addresses or fixed
	// addresses.
	NameAddress NameKind = "address"
	// NameCNAME answers with another name.
	NameCNAME NameKind = "cname"
)

// IsKnown reports a kind a name can store.
func (kind NameKind) IsKnown() bool { return kind == NameAddress || kind == NameCNAME }

// NameTarget is what a name points at: one Device of the Network, 1 to 8
// fixed addresses, or one other name; exactly one is set.
type NameTarget struct {
	DeviceID  node.ID
	Addresses []netip.Addr
	CNAME     string
}

// NameDefinition is what a create or update sends: the whole name. Label
// is set on create only (Apex for the zone's own domain); a name never
// moves.
type NameDefinition struct {
	Label  string
	Kind   NameKind
	Target NameTarget
}

// unanswerable are the ranges no fixed address may be in: the overlay
// frame every Device's mesh addresses and every share alias lie in (a name
// to a Device uses its Device target), and ranges an answer never names.
var unanswerable = [...]netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("fd00::/8"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// validFixedAddress reports an address a name may answer: a plain IPv4 or
// IPv6 host address (no zone, no IPv4-mapped form) outside unanswerable.
// Private addresses are allowed: Devices reach them through a Site.
func validFixedAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" || address.Is4In6() {
		return false
	}
	for _, prefix := range unanswerable {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// ParseLabel canonicalizes a label relative to a zone (case, Unicode labels
// to A-labels): Apex, or one or more hostname labels. ParseName checks the
// whole name.
func ParseLabel(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == Apex {
		return Apex, nil
	}
	if trimmed == "" || strings.HasPrefix(trimmed, ".") || strings.HasSuffix(trimmed, ".") {
		return "", ErrInvalid
	}
	ascii, err := lookup.ToASCII(trimmed)
	if err != nil {
		return "", ErrInvalid
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > maximumDomainBytes || !hostname(ascii) {
		return "", ErrInvalid
	}
	return ascii, nil
}

// NameIn returns the full name of a label in a zone's domain, or why it
// cannot be one: longer than 253 bytes.
func NameIn(label string, domain Domain) (string, error) {
	if domain.IsRoot() || domain == "" {
		return "", ErrInvalid
	}
	name := domain.String()
	if label != Apex {
		name = label + "." + name
	}
	if len(name) > maximumDomainBytes {
		return "", ErrInvalid
	}
	return name, nil
}

// ParseCNAME canonicalizes a CNAME target (case, trailing dot, Unicode
// labels to A-labels) and checks it: a hostname of 1 to 253 bytes, no
// special-use name but home.arpa, and nothing under the mesh names, which a
// name reaches with a Device target instead (policy then decides who sees
// it).
func ParseCNAME(input string, names Names) (string, error) {
	trimmed := strings.TrimSuffix(strings.TrimSpace(input), ".")
	if trimmed == "" || strings.HasPrefix(trimmed, ".") {
		return "", ErrNameTargetInvalid
	}
	ascii, err := lookup.ToASCII(trimmed)
	if err != nil {
		return "", ErrNameTargetInvalid
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > maximumDomainBytes || !hostname(ascii) || specialUseDomain(ascii) {
		return "", ErrNameTargetInvalid
	}
	suffix := names.Suffix.String()
	if !names.Suffix.IsValid() || ascii == suffix || strings.HasSuffix(ascii, "."+suffix) {
		return "", ErrNameTargetInvalid
	}
	return ascii, nil
}

// Validate checks a definition's kind and target: an address name points at
// one Device or 1 to 8 distinct fixed addresses, a CNAME at one canonical
// name (ParseCNAME). It does not check the label.
func (definition NameDefinition) Validate() error {
	target := definition.Target
	switch definition.Kind {
	case NameAddress:
		if target.CNAME != "" || target.DeviceID.IsValid() == (len(target.Addresses) > 0) {
			return ErrInvalid
		}
		if target.DeviceID.IsValid() {
			return nil
		}
		if len(target.Addresses) > MaximumAddressesPerName {
			return ErrInvalid
		}
		for index, address := range target.Addresses {
			if !validFixedAddress(address) {
				return ErrNameTargetInvalid
			}
			if slices.Contains(target.Addresses[:index], address) {
				return ErrInvalid
			}
		}
		return nil
	case NameCNAME:
		if target.DeviceID.IsValid() || len(target.Addresses) != 0 || target.CNAME == "" {
			return ErrInvalid
		}
		return nil
	default:
		return ErrInvalid
	}
}

// NameDevice is what Core knows of a target Device: its name and state
// (removed once it is gone).
type NameDevice struct {
	Name  string
	State string
}

// Name is one stored name.
type Name struct {
	ID     NameID
	ZoneID ID
	FQDN   string
	// Label is the name relative to its zone, Apex for the zone's domain.
	Label  string
	Kind   NameKind
	Target NameTarget
	// Device is set for a Device target.
	Device    *NameDevice
	Deleted   bool
	Version   int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NameOperation is one operation of a name change. A create carries the
// whole definition and the ID the service gives the new name; an update
// the name, its expected version and the kind and target; a delete the
// name and its expected version.
type NameOperation struct {
	Operation       Operation
	NameID          NameID
	ExpectedVersion int64
	Definition      NameDefinition
}

// NameChange is one validated change of a zone's names. ZoneClass is the
// zone's class as the service read it, for the audit trail.
type NameChange struct {
	Session       accountsession.Session
	Scope         network.Scope
	ZoneID        ID
	ZoneClass     Class
	Operations    []NameOperation
	Limits        Limits
	CorrelationID publicid.ID
}

// NameOutcome is what one operation did. Changed is false for an update
// that asked for what was stored.
type NameOutcome struct {
	Index     int
	Operation Operation
	Name      Name
	Previous  *Name
	Changed   bool
	// AppliesWithin, for a one-operation change, is when maps carry it at
	// the latest.
	AppliesWithin time.Duration
}

// NameResult is what a name change did, in request order. Changed is false
// when no operation wrote anything.
type NameResult struct {
	Outcomes []NameOutcome
	Changed  bool
	// AppliesWithin is when maps carry the change at the latest.
	AppliesWithin time.Duration
}

// NameListing is one page of a zone's names in name order, with the zone.
type NameListing struct {
	Zone    Zone
	Names   []Name
	HasMore bool
	Abilities
}

// NameReading is one name and what the reader may do with it.
type NameReading struct {
	Name Name
	Abilities
}
