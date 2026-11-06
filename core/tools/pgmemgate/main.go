// Command pgmemgate guards how much memory one PostgreSQL backend costs.
//
// Statement mode reads a server log written with log_statement_stats=on and
// fails when one statement grew a backend's maximum resident size by more
// than -max-mb. A backend keeps the memory it once needed until it closes, so
// one statement that plans or builds too much costs every pooled connection
// that runs it; the gate keeps such statements out of the authority
// functions.
//
//	pgmemgate -max-mb 64 postgres.log
//
// Backend mode reads samples of every backend's private memory taken while
// the integration suite ran (core/scripts/ci/pg-backend-sampler.sh) and fails
// when one client backend of a runtime role grew past -max-backend-mb. That
// total is what the database's memory budget multiplies by the pool sizes
// (docs: database-capacity.md); no single statement shows it.
//
//	pgmemgate -backend-samples samples.txt -max-backend-mb 200 [-roles mesh_runtime,mesh_worker]
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	entryStart = regexp.MustCompile(`^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+ \S+ \[(\d+)\] (?:LOG|ERROR|FATAL|WARNING|DETAIL|STATEMENT|CONTEXT):`)
	residentKB = regexp.MustCompile(`(\d+) kB max resident size`)
	statement  = regexp.MustCompile(`(?s)STATEMENT:\s+(.*)`)
	function   = regexp.MustCompile(`(?:mesh_ops|mesh_audit|mesh)\.([a-z0-9_]+)\(`)
	// Schema changes, migrations and maintenance are not request work.
	maintenance = regexp.MustCompile(`(?i)^\s*(CREATE|ALTER|DROP|COMMENT|GRANT|REVOKE|DO\s|ANALYZE|VACUUM|TRUNCATE|COPY|SET\s+ROLE|RESET)`)
)

// growth is the largest resident-size step one statement caused.
type growth struct {
	kb        int
	statement string
}

func main() {
	maxMB := flag.Int("max-mb", 64, "largest allowed growth of a backend's resident size from one statement")
	samples := flag.String("backend-samples", "", "backend mode: pg-backend-sampler.sh output to check")
	maxBackendMB := flag.Int("max-backend-mb", 200, "backend mode: largest allowed private memory of one client backend")
	roles := flag.String("roles", "mesh_runtime,mesh_worker", "backend mode: the database roles the budget applies to")
	flag.Parse()
	if *samples != "" {
		os.Exit(runBackendMode(os.Stdout, os.Stderr, *samples, *maxBackendMB, splitRoles(*roles)))
	}
	if flag.NArg() != 1 || *maxMB <= 0 {
		fmt.Fprintln(os.Stderr, "usage: pgmemgate -max-mb N postgres.log | pgmemgate -backend-samples FILE -max-backend-mb N")
		os.Exit(2)
	}
	file, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer func() { _ = file.Close() }() // read-only
	worst, err := scan(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(worst) == 0 {
		fmt.Fprintln(os.Stderr, "pgmemgate: no statement statistics in the log (log_statement_stats=on?)")
		os.Exit(2)
	}
	failed := false
	for index, g := range worst {
		over := g.kb > *maxMB*1024
		failed = failed || over
		if index < 10 || over {
			mark := " "
			if over {
				mark = "!"
			}
			fmt.Printf("%s %7.1f MB  %s\n", mark, float64(g.kb)/1024, g.statement)
		}
	}
	if failed {
		fmt.Fprintf(os.Stderr, "pgmemgate: statements above grew a backend by more than %d MB\n", *maxMB)
		os.Exit(1)
	}
}

// splitRoles reads -roles: comma separated, spaces trimmed, empty entries dropped.
func splitRoles(value string) []string {
	var roles []string
	for _, role := range strings.Split(value, ",") {
		if role = strings.TrimSpace(role); role != "" {
			roles = append(roles, role)
		}
	}
	return roles
}

// runBackendMode returns the exit code: 0 within budget, 1 over it, 2 when
// the samples cannot be read or hold no client backend (fails closed).
func runBackendMode(stdout, stderr io.Writer, path string, maxMB int, roles []string) int {
	if maxMB <= 0 || len(roles) == 0 {
		_, _ = fmt.Fprintln(stderr, "pgmemgate: -max-backend-mb and -roles are required in backend mode")
		return 2
	}
	file, err := os.Open(path) // #nosec G304 -- the CI script names its own sample file.
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	defer func() { _ = file.Close() }() // read-only
	peaks, err := scanBackends(file)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	if len(peaks) == 0 {
		_, _ = fmt.Fprintln(stderr, "pgmemgate: no client backend in the samples (did the sampler run?)")
		return 2
	}
	if !reportBackends(stdout, peaks, maxMB, roles) {
		_, _ = fmt.Fprintf(stderr, "pgmemgate: backends above cost more than %d MiB each; see database-capacity.md\n", maxMB)
		return 1
	}
	return 0
}

// scan returns, per statement (function name when it calls one), the largest
// growth of its backend's maximum resident size, largest first.
func scan(r io.Reader) ([]growth, error) {
	reader := bufio.NewReaderSize(r, 1<<20)
	peak := map[string]int{}
	worst := map[string]int{}
	var pid string
	var entry strings.Builder
	flush := func() {
		text := entry.String()
		entry.Reset()
		resident := residentKB.FindStringSubmatch(text)
		if pid == "" || resident == nil {
			return
		}
		kb, _ := strconv.Atoi(resident[1])
		key := ""
		if found := statement.FindStringSubmatch(text); found != nil {
			key = strings.Join(strings.Fields(found[1]), " ")
		}
		previous := peak[pid]
		if kb > previous {
			peak[pid] = kb
		}
		if key == "" || maintenance.MatchString(key) {
			return
		}
		if name := function.FindStringSubmatch(key); name != nil {
			key = name[1]
		} else if len(key) > 80 {
			key = key[:80]
		}
		if step := kb - previous; step > worst[key] {
			worst[key] = step
		}
	}
	for {
		line, err := reader.ReadString('\n')
		if match := entryStart.FindStringSubmatch(line); match != nil && strings.Contains(line, "] LOG:") {
			flush()
			pid = match[1]
		}
		entry.WriteString(line)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	flush()
	result := make([]growth, 0, len(worst))
	for key, kb := range worst {
		result = append(result, growth{kb: kb, statement: key})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].kb != result[j].kb {
			return result[i].kb > result[j].kb
		}
		return result[i].statement < result[j].statement
	})
	return result, nil
}
