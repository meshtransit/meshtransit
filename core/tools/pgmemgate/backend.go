package main

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// A client backend's process title: "postgres: <role> <database> <host(port)
// or [local]> <state>". Background processes (checkpointer, autovacuum
// launcher, logical replication launcher…) never carry a host.
var clientTitle = regexp.MustCompile(`^postgres: (\S+) (\S+) (\[local\]|\S+\(\d+\))(?: |$)`)

// backendPeak is the largest private anonymous resident size one client
// backend reached while it was sampled.
type backendPeak struct {
	pid  string
	role string
	kb   int
}

// scanBackends reads pg-backend-sampler.sh output ("pid kB title" per line)
// and returns each client backend's peak, largest first. A backend keeps the
// caches it builds (compiled PL/pgSQL functions, plans, relcache) until it
// closes, so its peak is what one pooled connection costs the database.
func scanBackends(r io.Reader) ([]backendPeak, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	peaks := map[string]backendPeak{}
	for scanner.Scan() {
		fields := strings.SplitN(strings.TrimSpace(scanner.Text()), " ", 3)
		if len(fields) != 3 {
			continue
		}
		kb, err := strconv.Atoi(fields[1])
		if err != nil || kb < 0 {
			continue
		}
		title := clientTitle.FindStringSubmatch(fields[2])
		if title == nil {
			continue
		}
		// A pid can be reused by a later backend of another role; the role
		// is part of the key so one never hides the other.
		key := fields[0] + " " + title[1]
		if kb > peaks[key].kb {
			peaks[key] = backendPeak{pid: fields[0], role: title[1], kb: kb}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	result := make([]backendPeak, 0, len(peaks))
	for _, peak := range peaks {
		result = append(result, peak)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].kb != result[j].kb {
			return result[i].kb > result[j].kb
		}
		return result[i].pid < result[j].pid
	})
	return result, nil
}

// overBudget lists the backends of the gated roles whose peak exceeds maxMB.
func overBudget(peaks []backendPeak, maxMB int, roles []string) []backendPeak {
	var over []backendPeak
	for _, peak := range peaks {
		if slices.Contains(roles, peak.role) && peak.kb > maxMB*1024 {
			over = append(over, peak)
		}
	}
	return over
}

// reportBackends prints each role's largest backend and every backend over
// the budget, and returns whether the gate passes.
func reportBackends(out io.Writer, peaks []backendPeak, maxMB int, roles []string) bool {
	seen := map[string]bool{}
	for _, peak := range peaks {
		if seen[peak.role] {
			continue
		}
		seen[peak.role] = true
		_, _ = fmt.Fprintf(out, "  %-18s largest backend %6.1f MiB (pid %s)\n", peak.role, float64(peak.kb)/1024, peak.pid)
	}
	over := overBudget(peaks, maxMB, roles)
	for _, peak := range over {
		_, _ = fmt.Fprintf(out, "! %-18s pid %s reached %.1f MiB, over %d MiB\n", peak.role, peak.pid, float64(peak.kb)/1024, maxMB)
	}
	return len(over) == 0
}
