// Package inventory owns bounded, freshly authorized Device inventory reads.
package inventory

import (
	"context"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
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
	// ErrRevisionChanged requires a new first page after inventory changes.
	ErrRevisionChanged = errors.New("device inventory: revision changed")
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
	// SuspendedReason is "admin" or "handover" for a suspended Device.
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
	case "", "admin":
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

// Cursor pins a public Device identity to the inventory revision.
type Cursor struct {
	After    node.ID
	Revision int64
}

// IsValid reports whether the cursor pins an exact inventory revision.
func (cursor Cursor) IsValid() bool { return cursor.After.IsValid() && cursor.Revision > 0 }

// ReadResult is untrusted storage evidence, validated before disclosure.
type ReadResult struct {
	Scope    network.Scope
	Revision int64
	Devices  []Device
}

// Reader authorizes and reads one snapshot from durable authority.
type Reader interface {
	ReadDevices(context.Context, accountsession.Session, network.Scope, node.ID, int, time.Time) (ReadResult, error)
}

// Clock provides the current authority-evaluation instant.
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
	scope    network.Scope
	revision int64
	devices  []Device
	next     Cursor
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
func (service *Service) List(ctx context.Context, session accountsession.Session,
	scope network.Scope, limit int, cursor Cursor,
) (Page, error) {
	if ctx == nil || service == nil || service.reader == nil || service.clock == nil ||
		!session.IsValid() || !scope.IsValid() || limit < 1 || limit > MaximumPageSize ||
		(cursor != (Cursor{}) && !cursor.IsValid()) {
		return Page{}, ErrInvalidRequest
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return Page{}, ErrForbidden
	}
	result, err := service.reader.ReadDevices(ctx, session, scope, cursor.After, limit+1, now)
	if err != nil {
		return Page{}, err
	}
	if result.Scope != scope || result.Revision < 1 || len(result.Devices) > limit+1 {
		return Page{}, ErrInvalidResult
	}
	if cursor.IsValid() && cursor.Revision != result.Revision {
		return Page{}, ErrRevisionChanged
	}
	for index, device := range result.Devices {
		if !device.IsValid() || (cursor.After.IsValid() && device.ID().String() <= cursor.After.String()) ||
			(index > 0 && result.Devices[index-1].ID().String() >= device.ID().String()) {
			return Page{}, ErrInvalidResult
		}
	}
	page := Page{scope: scope, revision: result.Revision, devices: append([]Device(nil), result.Devices...)}
	if len(page.devices) > limit {
		page.devices = page.devices[:limit]
		page.next = Cursor{After: page.devices[limit-1].ID(), Revision: page.revision}
	}
	return page, nil
}
