package main

import (
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// evidenceLogins maps each serving login to the manifest role whose code
// runs as it (role isolation design §3.4–§3.5).
var evidenceLogins = map[string]string{"mesh_runtime": "api", "mesh_control": "control", "mesh_worker": "worker"}

// EvidenceReport compares statements a database ran per login
// (pg_stat_statements snapshots, S2.0) with the manifest: Unexplained is
// what ran but the static analysis misses, an analysis error; Covered and
// Total count how much of each role's manifest the evidence exercised.
type EvidenceReport struct {
	Snapshots   int                            `json:"snapshots"`
	Statements  int                            `json:"statements"`
	Unexplained map[string]map[string][]string `json:"unexplained"`
	Covered     map[string]map[string]int      `json:"covered"`
	Total       map[string]map[string]int      `json:"total"`
	Unseen      map[string]map[string][]string `json:"unseen"`
}

// Evidence reads snapshot files (CSV, gzip allowed: login, toplevel,
// queryid, calls, query) and compares their top-level statements with
// roles. Statements inside functions are the database's own needs, not the
// code's, and are left out.
func Evidence(paths []string, roles map[string]Usage) (EvidenceReport, error) {
	seen := map[string]map[string]map[string]bool{}
	report := EvidenceReport{Unexplained: map[string]map[string][]string{}, Covered: map[string]map[string]int{},
		Total: map[string]map[string]int{}, Unseen: map[string]map[string][]string{}}
	queries := map[string]bool{}
	for _, path := range paths {
		rows, err := readSnapshot(path)
		if err != nil {
			return EvidenceReport{}, err
		}
		report.Snapshots++
		for _, row := range rows {
			if len(row) != 5 {
				return EvidenceReport{}, fmt.Errorf("%s: row with %d fields", path, len(row))
			}
			role, known := evidenceLogins[row[0]]
			if !known || row[1] != "t" {
				continue
			}
			queries[row[0]+"\x00"+row[4]] = true
			if seen[role] == nil {
				seen[role] = newUsageSets()
			}
			recordSQL(row[4], seen[role])
		}
	}
	report.Statements = len(queries)
	for role, names := range seen {
		manifest := usageSets(roles[role])
		for kind, set := range names {
			for name := range set {
				if !manifest[kind][name] {
					addReported(report.Unexplained, role, kind, name)
				}
			}
		}
	}
	for role, usage := range roles {
		manifest := usageSets(usage)
		report.Covered[role], report.Total[role] = map[string]int{}, map[string]int{}
		for kind, set := range manifest {
			report.Total[role][kind] = len(set)
			for name := range set {
				if seen[role] != nil && seen[role][kind][name] {
					report.Covered[role][kind]++
				} else {
					addReported(report.Unseen, role, kind, name)
				}
			}
		}
	}
	return report, nil
}

func addReported(target map[string]map[string][]string, role, kind, name string) {
	if target[role] == nil {
		target[role] = map[string][]string{}
	}
	list := append(target[role][kind], name)
	slices.Sort(list)
	target[role][kind] = list
}

func newUsageSets() map[string]map[string]bool {
	return map[string]map[string]bool{"functions": {}, "inserts": {}, "updates": {}, "deletes": {}, "locks": {},
		"reads": {}}
}

func usageSets(usage Usage) map[string]map[string]bool {
	sets := newUsageSets()
	for kind, names := range map[string][]string{"functions": usage.Functions, "inserts": usage.Inserts,
		"updates": usage.Updates, "deletes": usage.Deletes, "locks": usage.Locks, "reads": usage.Reads} {
		for _, name := range names {
			sets[kind][name] = true
		}
	}
	return sets
}

func readSnapshot(path string) ([][]string, error) {
	file, err := os.Open(path) // #nosec G304 -- a snapshot the operator names.
	if err != nil {
		return nil, fmt.Errorf("open snapshot: %w", err)
	}
	defer func() { _ = file.Close() }()
	var reader io.Reader = file
	if strings.HasSuffix(path, ".gz") {
		unzipped, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		defer func() { _ = unzipped.Close() }()
		reader = unzipped
	}
	csvReader := csv.NewReader(reader)
	csvReader.FieldsPerRecord = -1
	rows, err := csvReader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rows, nil
}

// runEvidence prints the report for the snapshot files and fails when the
// manifest misses anything that ran.
func runEvidence(paths []string, manifestPath string, output io.Writer) error {
	contents, err := os.ReadFile(manifestPath) // #nosec G304 -- the repository's manifest.
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	roles := map[string]Usage{}
	if err := json.Unmarshal(contents, &roles); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	report, err := Evidence(paths, roles)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	if len(report.Unexplained) != 0 {
		return errors.New("statements ran that the manifest does not list: fix the analysis")
	}
	return nil
}
