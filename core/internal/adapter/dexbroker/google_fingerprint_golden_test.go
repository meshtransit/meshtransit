//go:build dexbroker

package dexbroker

import "testing"

// TestGoogleConfigurationFingerprintIsUnchanged pins the fingerprint of a
// Google-only configuration: V1-22 options add material only when set, so a
// running Google Core keeps its broker fingerprint across the upgrade.
func TestGoogleConfigurationFingerprintIsUnchanged(t *testing.T) {
	fingerprint, err := CalculateConfigurationFingerprint(validServiceTestOptions(t))
	if err != nil {
		t.Fatalf("CalculateConfigurationFingerprint() error = %v", err)
	}
	const golden = "sha256-v2:e258cdf4350e28c1ca9ca56c8ba217fa7ae0f9cfa5963691682aa8f88919eab7"
	if fingerprint != golden {
		t.Fatalf("fingerprint = %q, want %q", fingerprint, golden)
	}
}
