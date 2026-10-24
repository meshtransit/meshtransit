package dnsname

import "testing"

// A public suffix is no mesh suffix; a registered domain or a private
// name is (TD-SEC-48).
func TestParseSuffixRefusesPublicSuffixes(t *testing.T) {
	t.Parallel()
	for _, refused := range []string{"co.uk", "com.au", "github.io"} {
		if _, err := ParseSuffix(refused); err == nil {
			t.Errorf("%s accepted", refused)
		}
	}
	for _, accepted := range []string{DefaultSuffix, "mesh.example-corp.co.uk", "corp.internal", "mesh.company.com"} {
		if _, err := ParseSuffix(accepted); err != nil {
			t.Errorf("%s refused: %v", accepted, err)
		}
	}
}
