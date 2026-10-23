package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"meshtransit.net/client/internal/cli/localapi"
)

// dnsPathText says where meshd's resolver sends a name (DNS design D5f).
var dnsPathText = map[string]string{
	"mesh":           "MeshTransit answers it: a name in this Network's map",
	"zone_local":     "MeshTransit answers it: a name of zone %s",
	"zone":           "DNS zone %s",
	"root_zone":      "the root DNS zone",
	"infrastructure": "MeshTransit's own service: the network's DNS, beside the root zone",
	"exit":           "the exit node's DNS",
	"network":        "the Network's or this network's DNS",
	"host":           "this machine's own DNS: MeshTransit does not take this name",
	"none":           "nothing: the exit node is chosen but not in use yet",
}

func runDNS(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	if len(args) < 2 || len(args) > 3 || args[0] != "query" {
		_, _ = fmt.Fprintln(stderr, "usage: meshctl dns query NAME [TYPE]")

		return 2
	}
	recordType := "A"
	if len(args) == 3 {
		recordType = args[2]
	}
	result, err := client.QueryDNS(ctx, args[1], recordType)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	if isJSON {
		return writeJSON(stdout, stderr, result)
	}
	writeDNSQuery(stdout, result)

	return 0
}

func writeDNSQuery(stdout io.Writer, result localapi.DNSQuery) {
	_, _ = fmt.Fprintf(stdout, "Name: %s %s\n", result.Name, result.Type)
	path, known := dnsPathText[result.Path]
	switch {
	case !known:
		path = result.Path
	case strings.Contains(path, "%s"):
		path = fmt.Sprintf(path, result.Zone)
	}
	_, _ = fmt.Fprintf(stdout, "Asked: %s\n", path)
	if result.Path == "zone" || result.Path == "root_zone" {
		mode := "fails closed: no other DNS answers"
		if result.FailOpen {
			mode = "fails open: the machine's own DNS answers"
		}
		_, _ = fmt.Fprintf(stdout, "When its resolvers do not answer: %s\n", mode)
	}
	for _, resolver := range result.Resolvers {
		notes := ""
		if resolver.ViaExit {
			notes += " (through the exit node)"
		}
		if resolver.Skipped {
			notes += " (skipped: it stopped answering, tried again in 30 s)"
		}
		_, _ = fmt.Fprintf(stdout, "Resolver: %s%s\n", resolver.Address, notes)
	}
	if result.RCode == "" {
		_, _ = fmt.Fprintf(stdout, "Answer: none (%d ms)\n", result.ElapsedMillis)
		if result.Error != "" {
			_, _ = fmt.Fprintf(stdout, "  %s\n", result.Error)
		}

		return
	}
	_, _ = fmt.Fprintf(stdout, "Answer: %s (%d ms)\n", result.RCode, result.ElapsedMillis)
	for _, answer := range result.Answers {
		_, _ = fmt.Fprintf(stdout, "  %s\n", answer)
	}
}
