//go:build windows

package privatefile

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// Stock Windows layouts pass; hostile ones do not (K1e design §3.1, review
// e1b M2/M4). Descriptors are SDDL as icacls and Get-Acl show them.
func TestPublicDescriptors(t *testing.T) {
	t.Parallel()
	const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	for _, test := range []struct {
		name     string
		sddl     string
		ancestor bool
		ok       bool
	}{
		{"Windows 11 C:\\", "O:" + trustedInstaller + "D:PAI(A;;FA;;;BA)(A;OICIIO;GA;;;BA)(A;;FA;;;SY)" +
			"(A;OICIIO;GA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICIIO;SDGXGWGR;;;AU)(A;;LC;;;AU)", true, true},
		// Users:(CI)(WD,AD,WEA,WA) is 0x116, as stock Windows grants.
		{"C:\\ProgramData", "O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;GA;;;CO)(A;OICI;0x1200a9;;;BU)" +
			"(A;CI;0x116;;;BU)", true, true},
		{"ProgramData letting users delete children and take ownership", "O:SYD:PAI(A;OICI;FA;;;SY)" +
			"(A;CI;LCSWWPRCDTWO;;;BU)", true, false},
		{"MeshTransit as the log code makes it", "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", false, true},
		{"kube as meshd makes it", publicSDDL, false, true},
		{"ProgramData with Users:M", "O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)", true,
			false},
		{"a conditional allow on an ancestor", "O:SYD:PAI(A;OICI;FA;;;SY)(XA;;FA;;;WD;(Member_of {SID(BA)}))",
			true, false},
		{"MeshTransit owned by a user", "O:S-1-5-21-1-2-3-1001D:P(A;OICI;FA;;;SY)", false, false},
		{"kube users may write to", "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;BU)", false, false},
	} {
		descriptor, err := windows.SecurityDescriptorFromString(test.sddl)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		forbidden := uint32(strictWrite)
		if test.ancestor {
			forbidden = ancestorWrite
		}
		err = checkDescriptor(test.name, descriptor, forbidden, test.ancestor)
		if test.ok && err != nil || !test.ok && !errors.Is(err, ErrNotPublicDir) {
			t.Errorf("%s: %v", test.name, err)
		}
	}
}
