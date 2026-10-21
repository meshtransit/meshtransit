package peercred

// Well-known Windows SIDs the local API trusts.
const (
	SIDLocalSystem    = "S-1-5-18"
	SIDAdministrators = "S-1-5-32-544"
	// OperatorsGroupName is the local group whose members may use meshctl
	// without elevation, as the meshtransit group does on macOS. The
	// installer creates it.
	OperatorsGroupName = "MeshTransit Users"
)

// Group is one group of a Windows caller's access token.
type Group struct {
	SID     string
	Enabled bool
}

// Caller describes the access token of a Windows named-pipe client.
type Caller struct {
	UserSID string
	Groups  []Group
}

// IsOperator reports whether the caller may use the local API: it is
// LocalSystem, or an enabled member of Administrators (an elevated token;
// UAC leaves the group deny-only otherwise) or of the operators group, whose
// SID is operatorsSID when that group exists.
func (c Caller) IsOperator(operatorsSID string) bool {
	if c.UserSID == SIDLocalSystem {
		return true
	}
	for _, group := range c.Groups {
		if !group.Enabled {
			continue
		}
		if group.SID == SIDAdministrators || (operatorsSID != "" && group.SID == operatorsSID) {
			return true
		}
	}

	return false
}

// IsAdministrator reports whether the caller is LocalSystem or an enabled
// (elevated) member of Administrators: what changing the host's trust in
// exit nodes needs, beyond the operators group.
func (c Caller) IsAdministrator() bool {
	return c.IsOperator("")
}
