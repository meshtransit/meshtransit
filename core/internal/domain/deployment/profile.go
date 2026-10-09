package deployment

// Profile is the immutable server-owned Deployment product boundary.
// The zero value and unknown values are invalid and grant no capability.
type Profile string

const (
	// ProfileSelfHosted is the official single-Workspace baseline.
	ProfileSelfHosted Profile = "self_hosted"
	// ProfileCloud requires separately verified entitlement authority.
	ProfileCloud Profile = "cloud"
)

// IsValid reports whether the profile name is recognized. A recognized profile
// still requires its own entitlement and runtime admission before use.
func (profile Profile) IsValid() bool {
	return profile == ProfileSelfHosted || profile == ProfileCloud
}
