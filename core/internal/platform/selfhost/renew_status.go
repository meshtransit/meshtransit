package selfhost

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"
)

// StatusFile is the file in RenewDir that records the last TLS renewal run for whoever
// watches renewal (auto-renewal-design.md §5): a timer that keeps failing
// would otherwise only show in the journal until a certificate expires.
const StatusFile = "status.json"

// RenewStatus is the last renewal run. It names files and services, never
// key material.
type RenewStatus struct {
	LastRun     time.Time   `json:"last_run"`
	Result      string      `json:"result"` // "ok" or "error"
	Error       string      `json:"error,omitempty"`
	LastSuccess time.Time   `json:"last_success,omitzero"`
	Report      RenewReport `json:"report"`
	// The earliest leaf expiry and the signing CA's, when readable.
	EarliestLeafNotAfter time.Time `json:"earliest_leaf_not_after,omitzero"`
	CANotAfter           time.Time `json:"ca_not_after,omitzero"`
}

// WriteRenewStatus records a run's outcome beside secretsDir, keeping the
// last success of earlier runs.
func WriteRenewStatus(secretsDir string, now time.Time, report RenewReport, runErr error) error {
	dir := restartDir(secretsDir)
	status := RenewStatus{LastRun: now.UTC(), Result: "ok", Report: report}
	if previous, err := readRenewStatus(dir); err == nil {
		status.LastSuccess = previous.LastSuccess
	}
	if runErr != nil {
		status.Result, status.Error = "error", runErr.Error()
	} else {
		status.LastSuccess = status.LastRun
	}
	if current, err := readTrust(secretsDir); err == nil {
		status.CANotAfter = current.signing.NotAfter.UTC()
	}
	for _, leaf := range tlsLeaves {
		certificates, err := readCertificates(filepath.Join(secretsDir, leaf.name+".crt"))
		if err != nil {
			continue
		}
		if notAfter := certificates[0].NotAfter.UTC(); status.EarliestLeafNotAfter.IsZero() ||
			notAfter.Before(status.EarliestLeafNotAfter) {
			status.EarliestLeafNotAfter = notAfter
		}
	}
	contents, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSecrets, StatusFile, err)
	}
	if err := PrepareRenewDir(secretsDir); err != nil {
		return err
	}
	return replaceSecretFile(dir, StatusFile, contents, 0o600, nil)
}

func readRenewStatus(dir string) (RenewStatus, error) {
	contents, err := readRegularFile(filepath.Join(dir, StatusFile), 64*1024)
	if errors.Is(err, fs.ErrNotExist) {
		return RenewStatus{}, err
	}
	if err != nil {
		return RenewStatus{}, fmt.Errorf("%w: read %s: %w", ErrSecrets, StatusFile, err)
	}
	var status RenewStatus
	if err := json.Unmarshal(contents, &status); err != nil {
		return RenewStatus{}, fmt.Errorf("%w: %s does not parse", ErrSecrets, StatusFile)
	}
	return status, nil
}
