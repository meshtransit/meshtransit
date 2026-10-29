package postgres

import "testing"

// The audit.export authority of a settings change is a role binding, or the
// Workspace's ownership: no binding and an owner generation (review d1d-a
// N1); anything else is evidence Core does not write.
func TestAuditSettingsExportAuthority(t *testing.T) {
	t.Parallel()
	const binding, role = "01890f00-0000-7000-8000-000000000c01", "01890f00-0000-7000-8000-000000000c02"
	for name, test := range map[string]struct {
		authority auditSettingsExportAuthority
		want      bool
	}{
		"a binding": {auditSettingsExportAuthority{catalogAuthority{BindingID: binding, RoleID: role,
			BindingGeneration: 1, MembershipGeneration: 1}, "network"}, true},
		"the owner":                     {auditSettingsExportAuthority{catalogAuthority{OwnerGeneration: 3}, "workspace"}, true},
		"an owner without a generation": {auditSettingsExportAuthority{catalogAuthority{}, "workspace"}, false},
		"a binding without its role": {auditSettingsExportAuthority{catalogAuthority{BindingID: binding},
			"workspace"}, false},
		"another scope": {auditSettingsExportAuthority{catalogAuthority{OwnerGeneration: 3}, "deployment"}, false},
	} {
		if got := test.authority.valid(); got != test.want {
			t.Errorf("%s: valid() = %t", name, got)
		}
	}
}
