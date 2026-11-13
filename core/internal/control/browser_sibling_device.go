package control

// The states of a person's Device the approval page names (duplicate-device
// design §7).
const (
	SiblingActive    = "active"
	SiblingSignedOut = "signed_out"
	SiblingExpired   = "expired"
	SiblingSuspended = "suspended"
)

// BrowserSiblingDevice is one of the signed-in person's Devices on the
// machine of a pending sign-in, held through a sibling profile's machine key.
type BrowserSiblingDevice struct {
	DeviceID, Hostname, State, WorkspaceID, NetworkID, NetworkName string
}

// Usable reports whether "Use that account" (or "Sign back in") is offered:
// not for a suspended Device (Q1).
func (device BrowserSiblingDevice) Usable() bool { return device.State != SiblingSuspended }
