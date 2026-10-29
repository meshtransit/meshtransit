package cli

import (
	"flag"
	"fmt"
	"io"
	"os"

	"meshtransit.net/client/internal/kubeauditcheck"
)

// Exit codes of meshctl kube audit-check (K1e design §5, Q128).
const (
	auditCheckClean      = 0
	auditCheckMismatch   = 1
	auditCheckUsage      = 2
	auditCheckError      = 3
	auditCheckIncomplete = 4
)

// runKubeAuditCheck reconciles an API server audit log with Core's
// records, offline: it needs no meshd and sends nothing anywhere.
func runKubeAuditCheck(args []string, stdout, stderr io.Writer, isJSON bool) int {
	flags := flag.NewFlagSet("kube audit-check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	recordsFile := flags.String("records", "", "Core's records of the cluster's operations (runbook k8s-operation-records)")
	logFile, rest := splitFirst(args)
	err := flags.Parse(rest)
	if err == nil && logFile == "" && flags.NArg() == 1 {
		logFile = flags.Arg(0) // the flags came first
	} else if flags.NArg() != 0 {
		logFile = ""
	}
	if err != nil || logFile == "" || *recordsFile == "" {
		writeKubeUsage(stderr)
		return auditCheckUsage
	}
	recordsReader, err := os.Open(*recordsFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)
		return auditCheckError
	}
	defer func() { _ = recordsReader.Close() }()
	records, options, err := kubeauditcheck.ReadRecords(recordsReader)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)
		return auditCheckError
	}
	log, err := os.Open(logFile) //nolint:gosec // The file the operator names.
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)
		return auditCheckError
	}
	defer func() { _ = log.Close() }()
	result, err := kubeauditcheck.Check(log, records, options)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)
		return auditCheckError
	}
	if isJSON {
		if code := writeJSON(stdout, stderr, result); code != 0 {
			return auditCheckError
		}
	} else {
		writeAuditCheck(stdout, result)
	}
	switch {
	case len(result.Mismatches) > 0:
		return auditCheckMismatch
	case result.Incomplete():
		// Lines the check could not read, or records the log lacks, are
		// requests it could not check (review e4 H3, re-review M2).
		return auditCheckIncomplete
	}
	return auditCheckClean
}

func writeAuditCheck(stdout io.Writer, result kubeauditcheck.Result) {
	_, _ = fmt.Fprintf(stdout, "Read %d audit events. Checked %d requests of the gateway's ServiceAccounts that "+
		"Core must record: %d recorded, %d not.\n", result.Events, result.Checked, result.Matched,
		len(result.Mismatches))
	if result.OutOfRange > 0 {
		_, _ = fmt.Fprintf(stdout, "%d such requests were logged outside from..to and are not checked here.\n",
			result.OutOfRange)
	}
	if result.NotForwarded > 0 {
		_, _ = fmt.Fprintf(stdout, "%d of Core's records are of requests the gateway could not send to the API "+
			"server (502).\n", result.NotForwarded)
	}
	if result.Unseen > 0 {
		_, _ = fmt.Fprintf(stdout, "INCOMPLETE %d of Core's records are not in the log (one: %s): a kube-apiserver "+
			"replica's log or an audit policy rule for the mt-* ServiceAccounts is missing, or a request failed "+
			"before reaching the API server. Requests that path served are not checked.\n", result.Unseen,
			result.FirstUnseen)
	}
	if result.Unreadable > 0 {
		_, _ = fmt.Fprintf(stdout, "INCOMPLETE %d lines are not audit events (the first: line %d); their requests "+
			"are not checked.\n", result.Unreadable, result.FirstUnreadable)
	}
	for _, finding := range result.Mismatches {
		_, _ = fmt.Fprintf(stdout, "MISMATCH %s %s %s %s %s: %s\n", finding.Received.UTC().Format("2006-01-02T15:04:05Z"),
			finding.AuditID, finding.User, finding.Verb, finding.URI, finding.Reason)
	}
}
