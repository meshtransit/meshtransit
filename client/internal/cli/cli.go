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

	"meshtransit.net/client/internal/cli/localapi"
	"meshtransit.net/client/internal/version"
)

const (
	defaultTimeout          = 5 * time.Second
	defaultLoginWaitTimeout = 5 * time.Minute
	loginRetryDelay         = 100 * time.Millisecond
	maxAuthKeyBytes         = 4096
	netcheckTimeout         = 15 * time.Second
	connectionTimeout       = 45 * time.Second
)

var errLoginWaitTimeout = errors.New("browser authorization wait timed out")

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
	RotateNodeKey(context.Context) (localapi.NodeKeyRotation, error)
	Down(context.Context) (localapi.Connection, error)
	Up(context.Context) (localapi.Connection, error)
	Logout(context.Context) (localapi.Logout, error)
	RefreshNAT(context.Context) (localapi.Netcheck, error)
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

	timeout := global.timeout
	switch commandArgs[0] {
	case "netcheck":
		// A classification waits for STUN answers; never cut it short.
		timeout = max(timeout, netcheckTimeout)
	case "logout", "down":
		// meshd first stops the control session; logout then waits for Core.
		timeout = max(timeout, connectionTimeout)
	}
	client, err := options.NewClient(global.socketPath, timeout)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)

		return 1
	}

	switch commandArgs[0] {
	case "up":
		return runUp(ctx, commandArgs[1:], stdout, stderr, global.isJSON, client)
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
	case "identity":
		return runIdentity(ctx, commandArgs[1:], stdout, stderr, global.isJSON, client)
	case "netcheck":
		return runNetcheck(ctx, commandArgs[1:], stdout, stderr, global.isJSON, client)
	case "down":
		return runDown(ctx, commandArgs[1:], stdout, stderr, global.isJSON, client)
	case "logout":
		return runLogout(ctx, commandArgs[1:], stdout, stderr, global.isJSON, client)
	default:
		_, _ = fmt.Fprintf(stderr, "meshctl: unknown command %q\n", commandArgs[0])
		writeUsage(stderr)

		return 2
	}
}

func runIdentity(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	if len(args) != 1 || args[0] != "rotate-node-key" {
		_, _ = fmt.Fprintln(stderr, "usage: meshctl identity rotate-node-key")

		return 2
	}

	result, err := client.RotateNodeKey(ctx)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	if result.State != "rotated" {
		return writeRuntimeError(
			stderr,
			fmt.Errorf("daemon returned unsupported Node-key rotation state %q", result.State),
		)
	}
	if isJSON {
		return writeJSON(stdout, stderr, result)
	}
	_, _ = fmt.Fprintf(stdout, "Rotated Node key for active profile %s.\n", result.ProfileID)

	return 0
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
	noWait := flags.Bool("no-wait", false, "return after printing the browser authorization URL")
	waitTimeout := flags.Duration(
		"wait-timeout",
		defaultLoginWaitTimeout,
		"maximum time to wait for browser authorization",
	)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(
			stderr,
			"usage: meshctl login [--auth-key-stdin] [--no-wait] [--wait-timeout DURATION]",
		)

		return 2
	}
	if *waitTimeout <= 0 {
		_, _ = fmt.Fprintln(stderr, "meshctl: login wait timeout must be positive")

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
	if result.State != "authorization_required" {
		return writeLoginResult(stdout, stderr, isJSON, result)
	}
	if exitCode := writeLoginResult(stdout, stderr, isJSON, result); exitCode != 0 {
		return exitCode
	}
	if *noWait {
		return 0
	}
	if !isJSON {
		_, _ = fmt.Fprintf(stdout, "Waiting up to %s for browser approval...\n", *waitTimeout)
	}

	waitCtx, cancel := context.WithTimeoutCause(ctx, *waitTimeout, errLoginWaitTimeout)
	defer cancel()

	return waitForLogin(waitCtx, stdout, stderr, isJSON, *waitTimeout, client)
}

func waitForLogin(
	ctx context.Context,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	waitTimeout time.Duration,
	client DaemonClient,
) int {
	for {
		result, err := client.CompleteLogin(ctx)
		switch {
		case err == nil && result.State == "registered":
			return writeLoginResult(stdout, stderr, isJSON, result)
		case err == nil && result.State == "authorization_required":
		case err == nil:
			return writeRuntimeError(
				stderr,
				fmt.Errorf("daemon returned unsupported login state %q", result.State),
			)
		case isAuthorizationPending(err):
		case ctx.Err() != nil:
			return writeLoginWaitError(ctx, stderr, waitTimeout)
		default:
			return writeRuntimeError(stderr, err)
		}

		timer := time.NewTimer(loginRetryDelay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()

			return writeLoginWaitError(ctx, stderr, waitTimeout)
		}
	}
}

func isAuthorizationPending(err error) bool {
	apiErr := &localapi.APIError{}

	return errors.As(err, &apiErr) && apiErr.Code == "authorization_pending"
}

func writeLoginWaitError(ctx context.Context, stderr io.Writer, waitTimeout time.Duration) int {
	if errors.Is(context.Cause(ctx), errLoginWaitTimeout) {
		return writeRuntimeError(
			stderr,
			fmt.Errorf(
				"browser authorization timed out after %s; run meshctl login to continue waiting",
				waitTimeout,
			),
		)
	}

	return writeRuntimeError(stderr, context.Cause(ctx))
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
			"Browser authorization required.\nOpen: %s\n",
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
	deviceExpiry := formatDeviceExpiry(status.DeviceExpiry, status.DeviceExpiresAt, time.Now())
	_, _ = fmt.Fprintf(
		stdout,
		"Daemon: %s\nState: %s\nData plane: %s\nDNS: %s\nNetwork changes: %s\nRuntime recovery: %s\nRuntime: %s\nActive profile: %s\nProfiles: %d\nControl trust: %s\nRegistration: %s\nControl session: %s\nNetmap revision: %d\nNetwork: %s\nSelf addresses: %s\nDevice expiry: %s\nPeers: %d\nPeer paths: %s\nSubnet routes: %s\nSubnet router: %s\nPath transitions: %s\nPath probes: %s\nRelay: %s\nNAT: %s\nPort mapping: %s\nCloud: %s\nPolicy rules: %d\nControl key: %s\nNote: %s\n",
		status.Daemon.Version,
		status.State,
		status.DataPlane,
		status.DNS,
		formatNetworkChangeStatus(status.NetworkChanges),
		formatRuntimeRecoveryStatus(status.RuntimeRecovery),
		formatRuntimeStatus(status.Runtime),
		activeProfile,
		status.ProfileCount,
		status.ControlTrust,
		status.Registration,
		status.ControlSession,
		status.NetmapRevision,
		networkName,
		selfAddresses,
		deviceExpiry,
		status.PeerCount,
		formatPathStatus(status.PeerPaths),
		formatSubnetRouteStatus(status.SubnetRoutes),
		formatSubnetRouterStatus(status.SubnetRouter),
		formatPathTransitionStatus(status.PeerPaths),
		formatPathProbeStatus(status.PathProbes),
		formatRelayStatus(status.Relay),
		formatNATSummary(status.NAT),
		formatPortMapping(status.PortMapping),
		formatCloud(status.Cloud),
		status.PolicyRuleCount,
		controlFingerprint,
		status.CompatibilityNote,
	)

	return 0
}

func formatPathProbeStatus(status *localapi.PathProbeStatus) string {
	if status == nil || !status.Available {
		return "unavailable"
	}

	return fmt.Sprintf(
		"maps %d (%d preserved, %d retired; authority peer/node/discovery/endpoint %d/%d/%d/%d; socket changes %d; %d pending invalidated), rounds %d/%d completed, sends %d/%d attempts (%d start, %d send failures), completions %d/%d authenticated replies (%d rejected), observations %d/%d accepted (%d rejected, %d dropped), expirations %d, receive drops %d",
		status.MapActivations,
		status.ActivationPreserved,
		status.ActivationRetired,
		status.AuthorityPeerChanges,
		status.AuthorityNodeKeyChanges,
		status.AuthorityDiscoveryKeyChanges,
		status.AuthorityEndpointChanges,
		status.SocketChanges,
		status.PendingInvalidated,
		status.RoundsCompleted,
		status.RoundsStarted,
		status.ProbesSent,
		status.ProbeAttempts,
		status.ProbeStartFailures,
		status.ProbeSendFailures,
		status.ProbeCompletions,
		status.AuthenticatedPongs,
		status.CompletionRejections,
		status.ObservationsAccepted,
		status.ObservationsQueued,
		status.ObservationRejected,
		status.ObservationDrops,
		status.DirectExpirations,
		status.DatagramDrops,
	)
}

func formatRuntimeRecoveryStatus(status *localapi.RuntimeRecoveryStatus) string {
	if status == nil {
		return "unavailable"
	}

	state := "idle"
	if status.Pending {
		state = "pending"
	}

	return fmt.Sprintf(
		"%s (failures: %d, recoveries: %d)",
		state,
		status.Failures,
		status.Recoveries,
	)
}

// maximumListedRefusals bounds the refused routes status prints.
const maximumListedRefusals = 5

func formatSubnetRouteStatus(status *localapi.SubnetRouteStatus) string {
	if status == nil || status.Requested == 0 {
		return "none"
	}
	summary := fmt.Sprintf("%d of %d installed", status.Installed, status.Requested)
	if status.Health != "" && status.Health != "ok" {
		summary += " [" + status.Health + "]"
	}
	if status.Error != "" {
		summary += "; error: " + status.Error
	}
	summary += formatRefusals(status.RefusedTotal, status.Refused)
	if status.UnreachableAnswered > 0 || status.UnreachableLimited > 0 {
		summary += fmt.Sprintf("; %d unreachable answered, %d limited", status.UnreachableAnswered,
			status.UnreachableLimited)
	}
	return summary
}

func formatSubnetRouterStatus(status *localapi.SubnetRouterStatus) string {
	if status == nil || (status.Sites == 0 && status.Error == "") {
		return "none"
	}
	summary := fmt.Sprintf("%d of %d prefixes in %d Sites served", status.Served, status.Requested, status.Sites)
	if status.Health != "" && status.Health != "ok" {
		summary += " [" + status.Health + "]"
	}
	if status.Error != "" {
		summary += "; error: " + status.Error
	}
	summary += formatRefusals(status.RefusedTotal, status.Refused)
	return summary
}

// formatRefusals lists the first refused routes and counts them all.
func formatRefusals(total int, refusals []localapi.SubnetRouteRefusal) string {
	if total == 0 {
		return ""
	}
	listed := make([]string, 0, maximumListedRefusals)
	for _, refusal := range refusals[:min(len(refusals), maximumListedRefusals)] {
		listed = append(listed, refusal.Prefix+" "+refusal.Reason)
	}
	text := fmt.Sprintf("; %d refused", total)
	if len(listed) > 0 {
		text += " (" + strings.Join(listed, ", ")
		if total > len(listed) {
			text += ", ..."
		}
		text += ")"
	}
	return text
}

func formatNetworkChangeStatus(status localapi.NetworkChangeStatus) string {
	if !status.Available {
		return "unavailable"
	}

	return fmt.Sprintf(
		"%d observed (%d endpoint refreshes)",
		status.Observed,
		status.EndpointRefreshes,
	)
}

func formatRuntimeStatus(status *localapi.RuntimeStatus) string {
	if status == nil {
		return "unavailable"
	}

	const bytesPerMiB = 1 << 20

	return fmt.Sprintf(
		"%d goroutines, %.1f MiB heap allocated, %.1f MiB system, %d GC cycles",
		status.Goroutines,
		float64(status.HeapAllocBytes)/bytesPerMiB,
		float64(status.SysBytes)/bytesPerMiB,
		status.GCCycles,
	)
}

func formatPathStatus(status localapi.PathStatus) string {
	if !status.Available {
		return "unavailable"
	}

	summary := fmt.Sprintf(
		"%d total (%d direct, %d relay, %d pending)",
		status.PeerCount,
		status.DirectCount,
		status.RelayCount,
		status.PendingCount,
	)
	if status.InactiveCount > 0 || status.LazyActivationCount > 0 {
		summary += fmt.Sprintf(
			"; lazy: %d inactive, %d activations, %d evictions, %d dropped",
			status.InactiveCount,
			status.LazyActivationCount,
			status.LazyEvictionCount,
			status.LazyDroppedCount,
		)
	}

	return summary
}

func formatPathTransitionStatus(status localapi.PathStatus) string {
	if !status.Available {
		return "unavailable"
	}
	promotionTiming := "unavailable"
	if status.DirectPromotionCount > 0 {
		promotionTiming = fmt.Sprintf(
			"%d/%d ms",
			status.LastDirectPromotionMillis,
			status.MaxDirectPromotionMillis,
		)
	}

	return fmt.Sprintf(
		"relay bootstraps %d, direct promotions %d, relay fallbacks %d, last/max promotion %s",
		status.RelayBootstrapCount,
		status.DirectPromotionCount,
		status.RelayFallbackCount,
		promotionTiming,
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
	fingerprint := flags.String("fingerprint", "", "expected control key fingerprint: sha256:… or the 32-character ck value of an enrollment link")
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
  up [--server U --fingerprint SHA256]    Connect this machine (MeshTransit Cloud by default)
  down                                    Disconnect this machine and stay off until up
  logout                                  Remove this machine from its Network; up enrolls it again
  status                                  Show daemon and data-plane status
  profile list                            List configured profiles
  profile create --name N --control-url U Create an isolated profile
  profile use PROFILE_ID                  Select the only active profile
  profile trust --fingerprint SHA256      Verify and pin the active control key
  login [--auth-key-stdin] [--no-wait] [--wait-timeout DURATION]
                                          Register the active profile and wait for browser approval
  login complete                          Recover a pending browser authorization
  identity rotate-node-key                Rotate the active profile Node key
  netcheck                                Classify the NAT in front of this machine now
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
