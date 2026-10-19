// Package inventory owns bounded, freshly authorized Device inventory reads.
package inventory

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/site"
)

// MaximumPageSize bounds each authenticated inventory page.
const MaximumPageSize = 100

var (
	// ErrInvalidRequest reports invalid input before durable reads.
	ErrInvalidRequest = errors.New("device inventory: invalid request")
	// ErrInvalidResult conceals malformed durable evidence.
	ErrInvalidResult = errors.New("device inventory: invalid result")
	// ErrForbidden conceals missing or revoked exact-scope authority.
	ErrForbidden = errors.New("device inventory: forbidden")
	// ErrUnavailable reports a failed durable dependency.
	ErrUnavailable = errors.New("device inventory: unavailable")
	// ErrNotFound reports a Device the scope does not hold.
	ErrNotFound = errors.New("device inventory: not found")
)

// Device contains durable registration metadata, never ephemeral presence.
type Device struct {
	id                              node.ID
	hostname                        node.Hostname
	state                           string
	ephemeral                       bool
	version                         int64
	createdAt, updatedAt, expiresAt time.Time
	lifecycle                       Lifecycle
	dnsLabel                        node.DNSLabel
	// offer holds the first prefixes of what the Device offers to forward
	// (all of them on one Device's read); offerCount counts them all.
	offer      []netip.Prefix
	offerCount int
}

// Member names one member a Device belongs to or is handed over to.
type Member struct {
	PrincipalID publicid.ID
	DisplayName string
}

// Lifecycle is who owns a Device and why it is suspended (schema 125).
type Lifecycle struct {
	// Ownership is "member" or "workspace".
	Ownership string
	// Owner is set for a member Device.
	Owner Member
	// SuspendedReason is "admin", "handover" or "member" for a suspended
	// Device.
	SuspendedReason string
	// HandoverTo is the member a handover waits for.
	HandoverTo Member
}

// IsValid reports a consistent lifecycle for a Device in state.
func (lifecycle Lifecycle) IsValid(state string) bool {
	switch lifecycle.Ownership {
	case "member":
		if !lifecycle.Owner.PrincipalID.IsValid() {
			return false
		}
	case "workspace":
		if lifecycle.Owner != (Member{}) {
			return false
		}
	default:
		return false
	}
	if (state == "suspended") != (lifecycle.SuspendedReason != "") {
		return false
	}
	switch lifecycle.SuspendedReason {
	case "", "admin", "member":
		return lifecycle.HandoverTo == (Member{})
	case "handover":
		return lifecycle.HandoverTo.PrincipalID.IsValid()
	default:
		return false
	}
}

// WithLifecycle returns the Device with its ownership and suspension.
func (device Device) WithLifecycle(lifecycle Lifecycle) (Device, error) {
	if !device.IsValid() || !lifecycle.IsValid(device.state) {
		return Device{}, ErrInvalidResult
	}
	device.lifecycle = lifecycle
	return device, nil
}

// Lifecycle returns who owns the Device and why it is suspended.
func (device Device) Lifecycle() Lifecycle { return device.lifecycle }

// NewDevice validates a non-secret durable projection.
func NewDevice(id node.ID, hostname node.Hostname, state string, ephemeral bool,
	version int64, createdAt, updatedAt, expiresAt time.Time,
) (Device, error) {
	device := Device{id: id, hostname: hostname, state: state, ephemeral: ephemeral,
		version: version, createdAt: createdAt, updatedAt: updatedAt, expiresAt: expiresAt}
	if !device.IsValid() {
		return Device{}, ErrInvalidResult
	}
	return device, nil
}

// WithDNSLabel returns the Device with the DNS label it holds in its
// Network (only a live Device holds one).
func (device Device) WithDNSLabel(label node.DNSLabel) (Device, error) {
	if !device.IsValid() || !label.IsValid() {
		return Device{}, ErrInvalidResult
	}
	device.dnsLabel = label
	return device, nil
}

// DNSLabel returns the Device's DNS label, if it holds one.
func (device Device) DNSLabel() (node.DNSLabel, bool) {
	return device.dnsLabel, device.dnsLabel.IsValid()
}

// WithOffer returns the Device with what it offers to forward as a subnet
// router: listed, canonical and sorted as Core stores offers, the first of
// count prefixes (all of them when len(listed) == count).
func (device Device) WithOffer(listed []netip.Prefix, count int) (Device, error) {
	if !device.IsValid() || count < len(listed) || count > site.MaximumOfferedPrefixes ||
		(count > 0 && len(listed) == 0) || !slices.Equal(listed, site.CanonicalOffer(listed)) {
		return Device{}, ErrInvalidResult
	}
	for _, prefix := range listed {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return Device{}, ErrInvalidResult
		}
	}
	device.offer, device.offerCount = slices.Clone(listed), count
	return device, nil
}

// Offer returns the listed prefixes the Device offers to forward and how
// many it offers in all.
func (device Device) Offer() ([]netip.Prefix, int) {
	return slices.Clone(device.offer), device.offerCount
}

// ID returns the public Device identity.
func (device Device) ID() node.ID { return device.id }

// Hostname returns the canonical registered name.
func (device Device) Hostname() string { return device.hostname.String() }

// State returns durable registration state, not online presence.
func (device Device) State() string { return device.state }

// Ephemeral reports the registered lifetime mode.
func (device Device) Ephemeral() bool { return device.ephemeral }

// Version returns the durable object version.
func (device Device) Version() int64 { return device.version }

// CreatedAt returns the registration time.
func (device Device) CreatedAt() time.Time { return device.createdAt }

// UpdatedAt returns the last durable object change time.
func (device Device) UpdatedAt() time.Time { return device.updatedAt }

// ExpiresAt returns the current registration expiry.
func (device Device) ExpiresAt() time.Time { return device.expiresAt }

// IsValid checks the entire safe registration projection.
func (device Device) IsValid() bool {
	validState := device.state == "active" || device.state == "expired" || device.state == "suspended" ||
		device.state == "revoked" || device.state == "deleted"
	return device.id.IsValid() && device.hostname.IsValid() && validState && device.version > 0 &&
		!device.createdAt.IsZero() && !device.updatedAt.Before(device.createdAt) &&
		device.expiresAt.After(device.createdAt)
}

// StateFilter selects Devices by whether they can connect now.
type StateFilter string

const (
	// StateAll keeps every Device.
	StateAll StateFilter = ""
	// StateActive keeps active Devices that have not expired.
	StateActive StateFilter = "active"
	// StateInactive keeps suspended, expired and removed Devices.
	StateInactive StateFilter = "inactive"
)

// MaximumNamePrefix bounds a name search to the longest hostname.
const MaximumNamePrefix = 253

// Cursor continues a list after the last Device of a page, in name order.
type Cursor struct {
	AfterHostname string
	After         node.ID
}

// IsValid reports whether the cursor names a Device to continue after.
func (cursor Cursor) IsValid() bool { return cursor.After.IsValid() && cursor.AfterHostname != "" }

// Query selects one page of a Network's Devices in name order.
type Query struct {
	// NamePrefix keeps Devices whose name starts with it; "" keeps all.
	NamePrefix string
	State      StateFilter
	Limit      int
	Cursor     Cursor
}

// IsValid reports a known filter, a page of 1 to MaximumPageSize and a
// name prefix written the way hostnames are: lower-case [a-z0-9.-].
func (query Query) IsValid() bool {
	if query.Limit < 1 || query.Limit > MaximumPageSize || len(query.NamePrefix) > MaximumNamePrefix ||
		(query.Cursor != (Cursor{}) && !query.Cursor.IsValid()) {
		return false
	}
	switch query.State {
	case StateAll, StateActive, StateInactive:
	default:
		return false
	}
	for index := range len(query.NamePrefix) {
		character := query.NamePrefix[index]
		lower, digit := character >= 'a' && character <= 'z', character >= '0' && character <= '9'
		if !lower && !digit && character != '-' && character != '.' {
			return false
		}
	}
	return true
}

// ReadResult is untrusted storage evidence, validated before disclosure.
type ReadResult struct {
	Scope    network.Scope
	Revision int64
	Devices  []Device
	// The Workspace and Network display codes of the scope's DNS zone.
	WorkspaceCode, NetworkCode identity.DisplayCode
}

// Enrollment says how a Device joined: by a browser sign-in, or by an
// enrollment key someone created.
type Enrollment struct {
	ByKey          bool
	KeyID          publicid.ID
	KeyDescription string
	KeyCreatedBy   Member
}

// Tag is one tag a Device carries.
type Tag struct {
	ID   publicid.ID
	Name string
}

// Record is one Device of the scope with how it was enrolled.
type Record struct {
	Scope      network.Scope
	Device     Device
	Enrollment Enrollment
	// Tags are the Device's tags by name.
	Tags []Tag
	// Found is false when the scope holds no such Device.
	Found                      bool
	WorkspaceCode, NetworkCode identity.DisplayCode
}

// Reader authorizes and reads from durable authority on the database clock.
// ReadDevices returns up to query.Limit Devices.
type Reader interface {
	ReadDevices(context.Context, accountsession.Session, network.Scope, Query) (ReadResult, error)
	ReadDevice(context.Context, accountsession.Session, network.Scope, node.ID) (Record, error)
	ReadDeviceNames(context.Context, accountsession.Session, network.Scope, []node.ID) (map[node.ID]string, error)
}

// MaximumNames bounds one name lookup, a page of peers.
const MaximumNames = MaximumPageSize

// Clock supplies this host's time, used only to refuse early a session that
// has already ended; the reader authorizes on the database clock.
type Clock interface{ Now() time.Time }

// Service validates scoped, revision-bound inventory evidence.
type Service struct {
	reader Reader
	clock  Clock
}

// NewService constructs an inventory reader through explicit dependencies.
func NewService(reader Reader, clock Clock) (*Service, error) {
	if reader == nil || clock == nil {
		return nil, ErrInvalidRequest
	}
	return &Service{reader: reader, clock: clock}, nil
}

// Page is an immutable, scope-bound inventory page.
type Page struct {
	scope                      network.Scope
	revision                   int64
	devices                    []Device
	next                       Cursor
	workspaceCode, networkCode identity.DisplayCode
}

// DisplayCodes returns the Workspace and Network display codes that, with
// the deployment's DNS suffix, form the Network's DNS zone.
func (page Page) DisplayCodes() (identity.DisplayCode, identity.DisplayCode) {
	return page.workspaceCode, page.networkCode
}

// Scope returns the exact authorized Workspace and Network.
func (page Page) Scope() network.Scope { return page.scope }

// Revision returns the snapshot inventory revision.
func (page Page) Revision() int64 { return page.revision }

// Devices returns a defensive copy of registered Devices.
func (page Page) Devices() []Device { return append([]Device(nil), page.devices...) }

// Next returns the next scope-bound cursor, if another page exists.
func (page Page) Next() (Cursor, bool) { return page.next, page.next.IsValid() }

// List independently requires exact-scope device.read in durable storage.
func (service *Service) List(ctx context.Context, session accountsession.Session, scope network.Scope,
	query Query,
) (Page, error) {
	if ctx == nil || service == nil || service.reader == nil || service.clock == nil ||
		!session.IsValid() || !scope.IsValid() || !query.IsValid() {
		return Page{}, ErrInvalidRequest
	}
	if err := service.requireActive(session); err != nil {
		return Page{}, err
	}
	limit := query.Limit
	query.Limit = limit + 1
	result, err := service.reader.ReadDevices(ctx, session, scope, query)
	if err != nil {
		return Page{}, err
	}
	if result.Scope != scope || result.Revision < 1 || len(result.Devices) > limit+1 ||
		!result.WorkspaceCode.IsValid() || !result.NetworkCode.IsValid() {
		return Page{}, ErrInvalidResult
	}
	previous := query.Cursor
	for _, device := range result.Devices {
		if !device.IsValid() || !strings.HasPrefix(device.Hostname(), query.NamePrefix) ||
			previous.IsValid() && !nameOrderAfter(device, previous) {
			return Page{}, ErrInvalidResult
		}
		previous = Cursor{AfterHostname: device.Hostname(), After: device.ID()}
	}
	page := Page{scope: scope, revision: result.Revision, devices: append([]Device(nil), result.Devices...),
		workspaceCode: result.WorkspaceCode, networkCode: result.NetworkCode}
	if len(page.devices) > limit {
		page.devices = page.devices[:limit]
		last := page.devices[limit-1]
		page.next = Cursor{AfterHostname: last.Hostname(), After: last.ID()}
	}
	return page, nil
}

// Get reads one Device of the scope and how it was enrolled.
func (service *Service) Get(ctx context.Context, session accountsession.Session, scope network.Scope,
	id node.ID,
) (Record, error) {
	if ctx == nil || service == nil || service.reader == nil || service.clock == nil ||
		!session.IsValid() || !scope.IsValid() || !id.IsValid() {
		return Record{}, ErrInvalidRequest
	}
	if err := service.requireActive(session); err != nil {
		return Record{}, err
	}
	record, err := service.reader.ReadDevice(ctx, session, scope, id)
	if err != nil {
		return Record{}, err
	}
	if record.Scope != scope || !record.WorkspaceCode.IsValid() || !record.NetworkCode.IsValid() {
		return Record{}, ErrInvalidResult
	}
	if !record.Found {
		return Record{}, ErrNotFound
	}
	if !record.Device.IsValid() || record.Device.ID() != id ||
		record.Enrollment.ByKey && !record.Enrollment.KeyID.IsValid() {
		return Record{}, ErrInvalidResult
	}
	return record, nil
}

// Names returns the hostnames of the scope's Devices among ids, to name the
// peers a Device reports; IDs of other Networks are left out.
func (service *Service) Names(ctx context.Context, session accountsession.Session, scope network.Scope,
	ids []node.ID,
) (map[node.ID]string, error) {
	if ctx == nil || service == nil || service.reader == nil || service.clock == nil ||
		!session.IsValid() || !scope.IsValid() || len(ids) > MaximumNames {
		return nil, ErrInvalidRequest
	}
	asked := make(map[node.ID]bool, len(ids))
	for _, id := range ids {
		if !id.IsValid() {
			return nil, ErrInvalidRequest
		}
		asked[id] = true
	}
	if len(ids) == 0 {
		return map[node.ID]string{}, nil
	}
	if err := service.requireActive(session); err != nil {
		return nil, err
	}
	names, err := service.reader.ReadDeviceNames(ctx, session, scope, ids)
	if err != nil {
		return nil, err
	}
	for id, name := range names {
		if !asked[id] || name == "" {
			return nil, ErrInvalidResult
		}
	}
	return names, nil
}

func (service *Service) requireActive(session accountsession.Session) error {
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return ErrForbidden
	}
	return nil
}

// nameOrderAfter reports whether device comes after cursor in byte order of
// (hostname, public ID), the order storage returns.
func nameOrderAfter(device Device, cursor Cursor) bool {
	if device.Hostname() != cursor.AfterHostname {
		return device.Hostname() > cursor.AfterHostname
	}
	return device.ID().String() > cursor.After.String()
}
