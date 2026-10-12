package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"

	"meshtransit.net/client/internal/cli/localapi"
)

// MeshTransit Cloud defaults. Packages built for Cloud carry the control key
// fingerprint, so `meshctl up` never asks a person to compare one; a key
// rotation ships a new package. Release builds may override both with
//
//	-ldflags "-X meshtransit.net/client/internal/cli.DefaultControlURL=...
//	          -X meshtransit.net/client/internal/cli.DefaultControlKeyFingerprint=..."
var (
	DefaultControlURL            = "https://control.meshtransit.net"
	DefaultControlKeyFingerprint = "sha256:9af0dbfdffaca2f5e428a33b9dfdd57e46aafd0b41010bfbb08daaf508f18f3a"
)

const cloudProfileName = "MeshTransit"

var errUnsafeServer = errors.New("server must be an https:// URL with only a host, for example https://mesh.example.com")

// upResult is the --json summary of one `meshctl up`.
type upResult struct {
	APIVersion     string `json:"api_version"`
	ProfileID      string `json:"profile_id"`
	Server         string `json:"server"`
	ProfileCreated bool   `json:"profile_created"`
	State          string `json:"state"`
	AuthURL        string `json:"auth_url,omitempty"`
	NetworkName    string `json:"network_name,omitempty"`
}

// runUp connects this machine in one command: it finds or creates the profile
// for the server, makes it active, pins (or re-verifies) the control key and
// registers, waiting for browser approval. Running it again on a connected
// machine changes nothing.
func runUp(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	flags := flag.NewFlagSet("meshctl up", flag.ContinueOnError)
	flags.SetOutput(stderr)
	serverFlag := flags.String("server", "", "control server URL (default: MeshTransit Cloud)")
	fingerprintFlag := flags.String("fingerprint", "", "expected control key fingerprint: sha256:… or the 32-character ck value of an enrollment link")
	nameFlag := flags.String("name", "", "profile name when a new profile is created")
	noWait := flags.Bool("no-wait", false, "return after printing the browser authorization URL")
	waitTimeout := flags.Duration("wait-timeout", defaultLoginWaitTimeout, "maximum time to wait for browser approval")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *waitTimeout <= 0 {
		writeUpUsage(stderr)

		return 2
	}
	server, err := canonicalServer(*serverFlag)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)

		return 2
	}
	cloudServer, _ := canonicalServer(DefaultControlURL)
	fingerprint := strings.TrimSpace(*fingerprintFlag)
	if fingerprint == "" && server == cloudServer {
		fingerprint = DefaultControlKeyFingerprint
	}
	if fingerprint == "" {
		_, _ = fmt.Fprintln(stderr,
			"meshctl: pass --fingerprint with the control key fingerprint your administrator gave you")

		return 2
	}
	name := strings.TrimSpace(*nameFlag)
	if name == "" {
		name = cloudProfileName
		if server != cloudServer {
			name = strings.TrimPrefix(server, "https://")
		}
	}

	result := upResult{APIVersion: "v1", Server: server}
	profile, created, err := ensureActiveProfile(ctx, client, server, name)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	result.ProfileID, result.ProfileCreated = profile.ID, created
	if !isJSON {
		verb := "Using"
		if created {
			verb = "Created"
		}
		_, _ = fmt.Fprintf(stdout, "%s profile %s for %s.\n", verb, profile.Name, server)
	}
	if _, err := client.TrustControl(ctx, fingerprint); err != nil {
		return writeRuntimeError(stderr, err)
	}
	// Undo a meshctl down; meshd then connects a registered profile again.
	connection, err := client.Up(ctx)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}

	status, err := client.Status(ctx)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	if status.ActiveProfileID == profile.ID && status.Registration == "registered" {
		result.State, result.NetworkName = "registered", status.NetworkName

		message := "Already connected"
		if connection.Changed {
			message = "Connected again"
		}

		return writeUpDone(stdout, stderr, isJSON, result, message)
	}

	login, err := client.StartLogin(ctx, "")
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	switch login.State {
	case "registered":
		result.State = "registered"

		return writeUpConnected(ctx, stdout, stderr, isJSON, client, result)
	case "authorization_required":
	default:
		return writeRuntimeError(stderr, fmt.Errorf("daemon returned unsupported login state %q", login.State))
	}
	result.State, result.AuthURL = login.State, login.AuthURL
	if *noWait {
		if isJSON {
			return writeJSON(stdout, stderr, result)
		}
		_, _ = fmt.Fprintf(stdout, "Approve this machine in your browser:\n  %s\nThen run meshctl up again.\n",
			login.AuthURL)

		return 0
	}
	if !isJSON {
		_, _ = fmt.Fprintf(stdout, "Approve this machine in your browser:\n  %s\nWaiting up to %s...\n",
			login.AuthURL, *waitTimeout)
	}
	waitCtx, cancel := context.WithTimeoutCause(ctx, *waitTimeout, errLoginWaitTimeout)
	defer cancel()
	if code := waitForLogin(waitCtx, io.Discard, stderr, true, *waitTimeout, client); code != 0 {
		return code
	}
	result.State, result.AuthURL = "registered", ""

	return writeUpConnected(ctx, stdout, stderr, isJSON, client, result)
}

// ensureActiveProfile reuses the profile already pointing at server, or
// creates one, and makes it the active profile.
func ensureActiveProfile(
	ctx context.Context,
	client DaemonClient,
	server string,
	name string,
) (localapi.Profile, bool, error) {
	profiles, err := client.ListProfiles(ctx)
	if err != nil {
		return localapi.Profile{}, false, err
	}
	for _, existing := range profiles.Profiles {
		existingServer, parseErr := canonicalServer(existing.ControlURL)
		if parseErr != nil || existingServer != server {
			continue
		}
		if existing.IsActive {
			return existing, false, nil
		}
		activated, err := client.ActivateProfile(ctx, existing.ID)

		return activated, false, err
	}
	created, err := client.CreateProfile(ctx, localapi.CreateProfile{Name: name, ControlURL: server})
	if err != nil {
		return localapi.Profile{}, false, err
	}
	activated, err := client.ActivateProfile(ctx, created.ID)

	return activated, true, err
}

// canonicalServer accepts only an https origin; an empty value means Cloud.
func canonicalServer(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		value = DefaultControlURL
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return "", errUnsafeServer
	}

	return "https://" + strings.ToLower(parsed.Host), nil
}

func writeUpConnected(
	ctx context.Context,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
	result upResult,
) int {
	if status, err := client.Status(ctx); err == nil {
		result.NetworkName = status.NetworkName
	}

	return writeUpDone(stdout, stderr, isJSON, result, "Connected")
}

func writeUpDone(stdout, stderr io.Writer, isJSON bool, result upResult, verb string) int {
	if isJSON {
		return writeJSON(stdout, stderr, result)
	}
	if result.NetworkName != "" {
		_, _ = fmt.Fprintf(stdout, "%s to %s. Check details with meshctl status.\n", verb, result.NetworkName)
	} else {
		_, _ = fmt.Fprintf(stdout, "%s. Check details with meshctl status.\n", verb)
	}

	return 0
}

func writeUpUsage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer,
		"usage: meshctl up [--server HTTPS_URL --fingerprint SHA256] [--name NAME] [--no-wait] [--wait-timeout DURATION]")
}
