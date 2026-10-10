package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"meshtransit.net/client/internal/cli/localapi"
)

func runNetcheck(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, "usage: meshctl netcheck")

		return 2
	}
	result, err := client.RefreshNAT(ctx)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	if isJSON {
		return writeJSON(stdout, stderr, result)
	}
	writeNetcheck(stdout, result.NAT)
	if result.PortMapping != nil {
		_, _ = fmt.Fprintf(stdout, "Port mapping: %s\n", formatPortMapping(result.PortMapping))
		if result.PortMapping.External != "" {
			_, _ = fmt.Fprintf(stdout, "Mapped endpoint: %s\n", result.PortMapping.External)
		}
	}
	if result.Cloud != nil {
		_, _ = fmt.Fprintf(stdout, "Cloud: %s\n", formatCloud(result.Cloud))
		if len(result.Cloud.Addresses) != 0 {
			_, _ = fmt.Fprintf(stdout, "Cloud public addresses: %s\n", strings.Join(result.Cloud.Addresses, ", "))
		}
	}
	if result.NAT.State != "ready" {
		return 1
	}

	return 0
}

func writeNetcheck(stdout io.Writer, nat localapi.NATStatus) {
	if nat.State != "ready" && nat.State != "stale" {
		_, _ = fmt.Fprintf(stdout, "NAT: %s\n", formatNATSummary(&nat))

		return
	}
	_, _ = fmt.Fprintf(stdout, "NAT type: %s\n", nat.Difficulty)
	_, _ = fmt.Fprintf(stdout, "Mapping: %s\n", nat.Mapping)
	_, _ = fmt.Fprintf(stdout, "Filtering: %s\n", nat.Filtering)
	allocation := nat.Allocation
	if nat.SequentialStep != 0 {
		allocation = fmt.Sprintf("%s (step %d)", allocation, nat.SequentialStep)
	}
	_, _ = fmt.Fprintf(stdout, "Port allocation: %s\n", allocation)
	_, _ = fmt.Fprintf(stdout, "Public endpoint: %s\n", valueOrNone(nat.PublicEndpoint))
	_, _ = fmt.Fprintf(stdout, "STUN servers answered: %d\n", nat.ServersAnswered)
	_, _ = fmt.Fprintf(stdout, "Observed: %s\n", valueOrNone(nat.ObservedAt))
	for _, note := range netcheckNotes(nat) {
		_, _ = fmt.Fprintf(stdout, "Note: %s\n", note)
	}
}

func netcheckNotes(nat localapi.NATStatus) []string {
	var notes []string
	switch nat.Difficulty {
	case "easy":
		notes = append(notes, "direct connections are expected with most peers")
	case "hard":
		notes = append(notes, "this network changes ports per destination; direct connections depend on the peer's network, some peers will use a relay")
	default:
		notes = append(notes, "too few STUN servers answered to classify the mapping")
	}
	if nat.Filtering == "unknown" {
		notes = append(notes, "filtering needs a STUN server with an alternate address (RFC 5780); the current relays do not offer one")
	}
	if nat.State == "stale" {
		notes = append(notes, "this result is older than 10 minutes")
	}

	return notes
}

// formatNATSummary renders the one-line NAT field of meshctl status.
func formatNATSummary(nat *localapi.NATStatus) string {
	if nat == nil {
		return "unavailable"
	}
	switch nat.State {
	case "ready", "stale":
		parts := []string{nat.Mapping + " mapping", nat.Filtering + " filtering", nat.Allocation}
		summary := fmt.Sprintf("%s (%s)", nat.Difficulty, strings.Join(parts, ", "))
		if nat.State == "stale" {
			summary += ", stale"
		}

		return summary
	case "failed":
		return "failed (" + valueOrNone(nat.Error) + ")"
	default:
		return valueOrNone(nat.State)
	}
}

func valueOrNone(value string) string {
	if value == "" {
		return "none"
	}

	return value
}

// formatPortMapping renders the one-line port mapping field.
func formatPortMapping(mapping *localapi.PortMappingStatus) string {
	if mapping == nil {
		return "unavailable"
	}
	switch mapping.State {
	case "mapped", "double_nat":
		summary := mapping.Protocol
		if mapping.State == "double_nat" {
			summary += ", behind another NAT (not offered to peers)"
		}
		if mapping.ExpiresAt != "" {
			summary += ", expires " + mapping.ExpiresAt
		}

		return summary
	case "unavailable", "failed":
		return mapping.State + " (" + valueOrNone(mapping.Error) + ")"
	default:
		return valueOrNone(mapping.State)
	}
}

// formatCloud renders the one-line cloud field.
func formatCloud(cloud *localapi.CloudStatus) string {
	if cloud == nil {
		return "unavailable"
	}
	switch cloud.State {
	case "ready":
		noun := "addresses"
		if cloud.AddressCount == 1 {
			noun = "address"
		}

		return fmt.Sprintf("%s (%d public %s)", cloud.Platform, cloud.AddressCount, noun)
	case "pending":
		return cloud.Platform + " (looking up)"
	case "failed":
		return cloud.Platform + " (failed: " + valueOrNone(cloud.Error) + ")"
	case "none":
		return "not a cloud instance"
	default:
		return valueOrNone(cloud.State)
	}
}
