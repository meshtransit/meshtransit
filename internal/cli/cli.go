// Package cli implements meshctl command parsing, output, and exit codes.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/meshtransit/meshctl/internal/localapi"
	"github.com/meshtransit/meshctl/internal/version"
)

const (
	defaultSocketPath = "/run/meshd/meshd.sock"
	defaultTimeout    = 5 * time.Second
	maxAuthKeyBytes   = 4096
)

// DaemonClient is the narrow local API surface consumed by the CLI.
type DaemonClient interface {
	Status(context.Context) (localapi.Status, error)
	ListProfiles(context.Context) (localapi.Profiles, error)
	CreateProfile(context.Context, localapi.CreateProfile) (localapi.Profile, error)
	ActivateProfile(context.Context, string) (localapi.Profile, error)
	ProbeControl(context.Context) (localapi.ControlProbe, error)
	TrustControl(context.Context, string) (localapi.ControlTrust, error)
	StartLogin(context.Context, string) (localapi.Login, error)
	CompleteLogin(context.Context) (localapi.Login, error)
}

// ClientFactory constructs the local daemon client after global flags are parsed.
type ClientFactory func(string, time.Duration) (DaemonClient, error)

// Options supplies build metadata, environment access, and the daemon boundary.
type Options struct {
	Build     version.Info
	Getenv    func(string) string
	NewClient ClientFactory
	Stdin     io.Reader
}

// Run executes one meshctl command and returns a process exit code.
func Run(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	options Options,
) int {
	if options.Getenv == nil {
		options.Getenv = os.Getenv
	}
	if options.Stdin == nil {
		options.Stdin = os.Stdin
	}
	if options.NewClient == nil {
		_, _ = fmt.Fprintln(stderr, "meshctl: local api client factory is not configured")

		return 1
	}

	global, commandArgs, err := parseGlobal(args, stderr, options.Getenv)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)
		}

		return 2
	}
	if global.showVersion {
		return writeVersion(stdout, global.isJSON, options.Build)
	}
	if len(commandArgs) == 0 {
		writeUsage(stderr)

		return 2
	}
	if commandArgs[0] == "help" {
		writeUsage(stdout)

		return 0
	}
	if commandArgs[0] == "version" {
		if len(commandArgs) != 1 {
			_, _ = fmt.Fprintln(stderr, "meshctl: version does not accept arguments")

			return 2
		}

		return writeVersion(stdout, global.isJSON, options.Build)
	}

	client, err := options.NewClient(global.socketPath, global.timeout)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)

		return 1
	}

	switch commandArgs[0] {
	case "status":
		return runStatus(ctx, commandArgs[1:], stdout, stderr, global.isJSON, client)
	case "profile":
		return runProfile(ctx, commandArgs[1:], stdout, stderr, global.isJSON, client)
	case "doctor":
		return runDoctor(ctx, commandArgs[1:], stdout, stderr, global.isJSON, client)
	case "login":
		return runLogin(
			ctx,
			commandArgs[1:],
			options.Stdin,
			stdout,
			stderr,
			global.isJSON,
			client,
		)
	default:
		_, _ = fmt.Fprintf(stderr, "meshctl: unknown command %q\n", commandArgs[0])
		writeUsage(stderr)

		return 2
	}
}

func runLogin(
	ctx context.Context,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	if len(args) > 0 && args[0] == "complete" {
		if len(args) != 1 {
			_, _ = fmt.Fprintln(stderr, "usage: meshctl login complete")

			return 2
		}
		result, err := client.CompleteLogin(ctx)
		if err != nil {
			return writeRuntimeError(stderr, err)
		}

		return writeLoginResult(stdout, stderr, isJSON, result)
	}

	flags := flag.NewFlagSet("meshctl login", flag.ContinueOnError)
	flags.SetOutput(stderr)
	authKeyStdin := flags.Bool("auth-key-stdin", false, "read an auth key from stdin")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "usage: meshctl login [--auth-key-stdin]")

		return 2
	}

	var authKey string
	if *authKeyStdin {
		var err error
		authKey, err = readAuthKey(stdin)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)

			return 2
		}
	}
	result, err := client.StartLogin(ctx, authKey)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}

	return writeLoginResult(stdout, stderr, isJSON, result)
}

func writeLoginResult(
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	result localapi.Login,
) int {
	if isJSON {
		return writeJSON(stdout, stderr, result)
	}
	if result.State == "authorization_required" {
		_, _ = fmt.Fprintf(
			stdout,
			"Browser authorization required.\nOpen: %s\nAfter approval, run: meshctl login complete\n",
			result.AuthURL,
		)

		return 0
	}
	if result.State == "registered" {
		_, _ = fmt.Fprintf(stdout, "Registered active profile %s.\n", result.ProfileID)

		return 0
	}

	return writeRuntimeError(stderr, fmt.Errorf("daemon returned unsupported login state %q", result.State))
}

func readAuthKey(stdin io.Reader) (string, error) {
	if stdin == nil {
		return "", errors.New("stdin is unavailable")
	}
	encoded, err := io.ReadAll(io.LimitReader(stdin, maxAuthKeyBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading auth key from stdin: %w", err)
	}
	defer clear(encoded)
	if len(encoded) > maxAuthKeyBytes {
		return "", fmt.Errorf("auth key exceeds %d bytes", maxAuthKeyBytes)
	}
	authKey := strings.TrimSpace(string(encoded))
	if authKey == "" {
		return "", errors.New("auth key from stdin is empty")
	}
	if !utf8.ValidString(authKey) {
		return "", errors.New("auth key from stdin is not valid UTF-8")
	}
	for _, character := range authKey {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return "", errors.New("auth key from stdin contains whitespace or control characters")
		}
	}

	return authKey, nil
}

func runDoctor(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	if len(args) != 1 || args[0] != "control" {
		_, _ = fmt.Fprintln(stderr, "usage: meshctl doctor control")

		return 2
	}

	result, err := client.ProbeControl(ctx)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	if isJSON {
		return writeJSON(stdout, stderr, result)
	}

	_, _ = fmt.Fprintf(
		stdout,
		"Control: reachable\nProtocol: %s\nCapability: %d\nNoise: %t (version %d)\nProfile: %s\nURL: %s\nKey fingerprint: %s\n",
		result.Protocol,
		result.Capability,
		result.NoiseEstablished,
		result.NoiseVersion,
		result.ProfileID,
		result.ControlURL,
		result.KeyFingerprint,
	)

	return 0
}

type globalOptions struct {
	socketPath  string
	timeout     time.Duration
	isJSON      bool
	showVersion bool
}

func parseGlobal(
	args []string,
	stderr io.Writer,
	getenv func(string) string,
) (globalOptions, []string, error) {
	options := globalOptions{
		socketPath: defaultSocketPath,
		timeout:    defaultTimeout,
	}
	if value := getenv("MESHCTL_SOCKET"); value != "" {
		options.socketPath = value
	}
	if value := getenv("MESHCTL_TIMEOUT"); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return globalOptions{}, nil, fmt.Errorf("invalid MESHCTL_TIMEOUT: %w", err)
		}
		options.timeout = parsed
	}

	flags := flag.NewFlagSet("meshctl", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.socketPath, "socket", options.socketPath, "path to the meshd Unix socket")
	flags.DurationVar(&options.timeout, "timeout", options.timeout, "maximum duration for one daemon call")
	flags.BoolVar(&options.isJSON, "json", false, "write machine-readable JSON")
	flags.BoolVar(&options.showVersion, "version", false, "print version and exit")
	flags.Usage = func() {
		writeUsage(stderr)
	}
	if err := flags.Parse(args); err != nil {
		return globalOptions{}, nil, err
	}
	if options.timeout <= 0 {
		return globalOptions{}, nil, errors.New("timeout must be positive")
	}

	return options, flags.Args(), nil
}

func runStatus(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, "meshctl: status does not accept arguments")

		return 2
	}

	status, err := client.Status(ctx)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	if isJSON {
		return writeJSON(stdout, stderr, status)
	}

	activeProfile := status.ActiveProfileID
	if activeProfile == "" {
		activeProfile = "none"
	}
	controlFingerprint := status.ControlFingerprint
	if controlFingerprint == "" {
		controlFingerprint = "none"
	}
	networkName := status.NetworkName
	if networkName == "" {
		networkName = "none"
	}
	selfAddresses := "none"
	if len(status.SelfAddresses) > 0 {
		selfAddresses = strings.Join(status.SelfAddresses, ", ")
	}
	_, _ = fmt.Fprintf(
		stdout,
		"Daemon: %s\nState: %s\nData plane: %s\nDNS: %s\nActive profile: %s\nProfiles: %d\nControl trust: %s\nRegistration: %s\nControl session: %s\nNetmap revision: %d\nNetwork: %s\nSelf addresses: %s\nPeers: %d\nPeer paths: %s\nRelay: %s\nPolicy rules: %d\nControl key: %s\nNote: %s\n",
		status.Daemon.Version,
		status.State,
		status.DataPlane,
		status.DNS,
		activeProfile,
		status.ProfileCount,
		status.ControlTrust,
		status.Registration,
		status.ControlSession,
		status.NetmapRevision,
		networkName,
		selfAddresses,
		status.PeerCount,
		formatPathStatus(status.PeerPaths),
		formatRelayStatus(status.Relay),
		status.PolicyRuleCount,
		controlFingerprint,
		status.CompatibilityNote,
	)

	return 0
}

func formatPathStatus(status localapi.PathStatus) string {
	if !status.Available {
		return "unavailable"
	}

	return fmt.Sprintf(
		"%d total (%d direct, %d relay, %d pending)",
		status.PeerCount,
		status.DirectCount,
		status.RelayCount,
		status.PendingCount,
	)
}

func formatRelayStatus(status localapi.RelayStatus) string {
	if !status.Available {
		return "unavailable"
	}

	homeRegion := "none"
	if status.HomeRegion > 0 {
		homeRegion = fmt.Sprint(status.HomeRegion)
	}

	return fmt.Sprintf(
		"%d/%d regions connected (home %s)",
		status.ConnectedRegions,
		status.ActiveRegions,
		homeRegion,
	)
}

func runProfile(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	if len(args) == 0 {
		writeProfileUsage(stderr)

		return 2
	}

	switch args[0] {
	case "list":
		return runProfileList(ctx, args[1:], stdout, stderr, isJSON, client)
	case "create":
		return runProfileCreate(ctx, args[1:], stdout, stderr, isJSON, client)
	case "use":
		return runProfileUse(ctx, args[1:], stdout, stderr, isJSON, client)
	case "trust":
		return runProfileTrust(ctx, args[1:], stdout, stderr, isJSON, client)
	default:
		_, _ = fmt.Fprintf(stderr, "meshctl: unknown profile command %q\n", args[0])
		writeProfileUsage(stderr)

		return 2
	}
}

func runProfileTrust(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	flags := flag.NewFlagSet("meshctl profile trust", flag.ContinueOnError)
	flags.SetOutput(stderr)
	fingerprint := flags.String("fingerprint", "", "expected SHA-256 control key fingerprint")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || strings.TrimSpace(*fingerprint) == "" {
		_, _ = fmt.Fprintln(stderr, "usage: meshctl profile trust --fingerprint SHA256_FINGERPRINT")

		return 2
	}

	trusted, err := client.TrustControl(ctx, *fingerprint)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	if isJSON {
		return writeJSON(stdout, stderr, trusted)
	}
	verb := "Pinned"
	if trusted.AlreadyPinned {
		verb = "Verified"
	}
	_, _ = fmt.Fprintf(
		stdout,
		"%s control key %s for active profile %s.\n",
		verb,
		trusted.Fingerprint,
		trusted.ProfileID,
	)

	return 0
}

func runProfileList(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, "meshctl: profile list does not accept arguments")

		return 2
	}

	response, err := client.ListProfiles(ctx)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	if isJSON {
		return writeJSON(stdout, stderr, response)
	}
	if len(response.Profiles) == 0 {
		_, _ = fmt.Fprintln(stdout, "No profiles configured.")

		return 0
	}

	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(table, "ACTIVE\tNAME\tID\tCONTROL URL")
	for _, item := range response.Profiles {
		marker := ""
		if item.IsActive {
			marker = "*"
		}
		_, _ = fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", marker, item.Name, item.ID, item.ControlURL)
	}
	if err := table.Flush(); err != nil {
		return writeRuntimeError(stderr, fmt.Errorf("writing profile table: %w", err))
	}

	return 0
}

func runProfileCreate(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	flags := flag.NewFlagSet("meshctl profile create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("name", "", "profile display name")
	controlURL := flags.String("control-url", "", "HTTPS control-plane base URL")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *name == "" || *controlURL == "" {
		_, _ = fmt.Fprintln(stderr, "usage: meshctl profile create --name NAME --control-url HTTPS_URL")

		return 2
	}

	created, err := client.CreateProfile(ctx, localapi.CreateProfile{
		Name:       *name,
		ControlURL: *controlURL,
	})
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	if isJSON {
		return writeJSON(stdout, stderr, created)
	}

	state := "inactive"
	if created.IsActive {
		state = "active"
	}
	_, _ = fmt.Fprintf(stdout, "Created profile %s (%s, %s).\n", created.Name, created.ID, state)

	return 0
}

func runProfileUse(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		_, _ = fmt.Fprintln(stderr, "usage: meshctl profile use PROFILE_ID")

		return 2
	}

	selected, err := client.ActivateProfile(ctx, args[0])
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	if isJSON {
		return writeJSON(stdout, stderr, selected)
	}

	_, _ = fmt.Fprintf(stdout, "Active profile: %s (%s).\n", selected.Name, selected.ID)

	return 0
}

func writeVersion(stdout io.Writer, isJSON bool, build version.Info) int {
	if isJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(build); err != nil {
			return 1
		}

		return 0
	}
	_, _ = fmt.Fprintf(stdout, "%s (commit %s, built %s)\n", build.Version, build.Commit, build.Date)

	return 0
}

func writeJSON(
	stdout io.Writer,
	stderr io.Writer,
	value any,
) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return writeRuntimeError(stderr, fmt.Errorf("writing json output: %w", err))
	}

	return 0
}

func writeRuntimeError(stderr io.Writer, err error) int {
	_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)

	return 1
}

func writeUsage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, `Usage:
  meshctl [--socket PATH] [--timeout DURATION] [--json] COMMAND

Commands:
  status                                  Show daemon and data-plane status
  profile list                            List configured profiles
  profile create --name N --control-url U Create an isolated profile
  profile use PROFILE_ID                  Select the only active profile
  profile trust --fingerprint SHA256      Verify and pin the active control key
  login [--auth-key-stdin]                Register the active profile
  login complete                          Complete browser authorization
  doctor control                          Probe active control compatibility
  version                                 Show meshctl build information
  help                                    Show this help

Environment:
  MESHCTL_SOCKET   Default Unix socket path
  MESHCTL_TIMEOUT  Default request timeout`)
}

func writeProfileUsage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, `Usage:
  meshctl profile list
  meshctl profile create --name NAME --control-url HTTPS_URL
  meshctl profile use PROFILE_ID
  meshctl profile trust --fingerprint SHA256_FINGERPRINT`)
}
