package kubecluster

import (
	"time"

	"meshtransit.net/core/internal/domain/node"
)

// KeyEventReason is why the control plane reported a gateway's key
// (K1a1 plan §15.1). Each reason has one audit action.
type KeyEventReason string

// Reasons a gateway's key is reported.
const (
	// KeyEventRetiredMachineKey: a handshake with a machine key the
	// gateway no longer holds.
	KeyEventRetiredMachineKey KeyEventReason = "retired_machine_key"
	// KeyEventStaleNodeKey: the current machine key presented a node key
	// that is not current; only the machine key is proven.
	KeyEventStaleNodeKey KeyEventReason = "stale_node_key"
	// KeyEventSessionFight: on one replica the machine key replaced its own
	// live, receiving map stream twice within five minutes.
	KeyEventSessionFight KeyEventReason = "session_fight"
	// KeyEventReplayedHandshake: a valid proof whose timestamp another
	// holder of the keys already used.
	KeyEventReplayedHandshake KeyEventReason = "replayed_handshake"
)

// IsKnown reports one of the reasons above.
func (reason KeyEventReason) IsKnown() bool {
	switch reason {
	case KeyEventRetiredMachineKey, KeyEventStaleNodeKey, KeyEventSessionFight, KeyEventReplayedHandshake:
		return true
	}
	return false
}

// StaleKey reports a stale key, as opposed to keys two holders contest.
func (reason KeyEventReason) StaleKey() bool {
	return reason == KeyEventRetiredMachineKey || reason == KeyEventStaleNodeKey
}

// MaximumSuppressedReports bounds the reports one event says were folded
// into it.
const MaximumSuppressedReports = 1_000_000

// KeyEventOutcome is what recording one report did. The zero value is
// invalid.
type KeyEventOutcome uint8

// Outcomes of recording a key report.
const (
	_ KeyEventOutcome = iota
	// KeyEventRecorded: a sealed audit event was written.
	KeyEventRecorded
	// KeyEventLimited: an event for the key, Device or Network is recent
	// enough, or a daily budget is spent.
	KeyEventLimited
	// KeyEventBusy: another report of the gateway, or a change to its
	// Network's audit stream, held the lock; nothing was written.
	KeyEventBusy
	// KeyEventNotGateway: the key is not, and was not, a gateway's.
	KeyEventNotGateway
)

// IsKnown reports a valid outcome.
func (outcome KeyEventOutcome) IsKnown() bool {
	return outcome >= KeyEventRecorded && outcome <= KeyEventNotGateway
}

// ReportedKeyState is how a reported key stands now.
type ReportedKeyState string

// Key states.
const (
	// ReportedKeyCurrent: the gateway's current machine key.
	ReportedKeyCurrent ReportedKeyState = "current"
	// ReportedKeyRotated: a key the gateway moved away from while it still
	// runs; another holder of an older copy, the strongest signal.
	ReportedKeyRotated ReportedKeyState = "rotated"
	// ReportedKeyDeviceRemoved: the gateway Device is revoked or deleted.
	ReportedKeyDeviceRemoved ReportedKeyState = "device_removed"
	// ReportedKeyDeviceExpired: the gateway Device expired.
	ReportedKeyDeviceExpired ReportedKeyState = "device_expired"
	// ReportedKeyDeviceSuspended: the gateway Device is suspended, so the
	// gate takes none of its keys.
	ReportedKeyDeviceSuspended ReportedKeyState = "device_suspended"
)

// IsKnown reports one of the states above.
func (state ReportedKeyState) IsKnown() bool {
	switch state {
	case ReportedKeyCurrent, ReportedKeyRotated, ReportedKeyDeviceRemoved, ReportedKeyDeviceExpired,
		ReportedKeyDeviceSuspended:
		return true
	}
	return false
}

// MaximumKeyWarnings bounds the gateway Devices a cluster's read sums.
const MaximumKeyWarnings = 64

// KeyWarning sums one gateway Device's key events of the last seven days,
// removed Devices included.
type KeyWarning struct {
	DeviceID   node.ID
	Hostname   string
	Last24h    int
	Last7Days  int
	LastAt     time.Time
	LastReason KeyEventReason
	KeyState   ReportedKeyState
}

// KeyWarnings are a cluster's key warnings, newest first; Truncated when
// more gateway Devices had events than MaximumKeyWarnings.
type KeyWarnings struct {
	Devices   []KeyWarning
	Truncated bool
}
