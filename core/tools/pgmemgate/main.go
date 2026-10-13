// Command pgmemgate reads a PostgreSQL server log written with
// log_statement_stats=on and fails when one statement grew a backend's
// maximum resident size by more than -max-mb. A backend keeps the memory it
// once needed until it closes, so one statement that plans or builds too much
// costs every pooled connection that runs it; the gate keeps such statements
// out of the authority functions.
//
//	pgmemgate -max-mb 64 postgres.log
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
	flag.Parse()
	if flag.NArg() != 1 || *maxMB <= 0 {
		fmt.Fprintln(os.Stderr, "usage: pgmemgate -max-mb N postgres.log")
		os.Exit(2)
	}
	file, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer file.Close()
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
