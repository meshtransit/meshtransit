// Package cli implements meshctl command parsing, output, and exit codes.
package cli

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
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
	connectPollDelay        = 250 * time.Millisecond
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
	RemoveProfile(context.Context, string, bool) (localapi.ProfileRemoval, error)
	AddAccount(context.Context, string) (localapi.AccountAdded, error)
	ProbeControl(context.Context) (localapi.ControlProbe, error)
	TrustControl(context.Context, string) (localapi.ControlTrust, error)
	StartLogin(context.Context, string) (localapi.Login, error)
	CompleteLogin(context.Context) (localapi.Login, error)
	RotateNodeKey(context.Context) (localapi.NodeKeyRotation, error)
	Down(context.Context) (localapi.Connection, error)
	Up(context.Context) (localapi.Connection, error)
	Logout(context.Context) (localapi.Logout, error)
	SignOut(context.Context) (localapi.Logout, error)
	RefreshNAT(context.Context) (localapi.Netcheck, error)
	ApproveExitNodes(context.Context, []string) (localapi.ExitApproval, error)
	CheckCaptiveWindow(context.Context) error
	QueryDNS(context.Context, string, string) (localapi.DNSQuery, error)
}

// ClientFactory constructs the local daemon client after global flags are parsed.
type ClientFactory func(string, time.Duration) (DaemonClient, error)

// Options supplies build metadata, environment access, and the daemon boundary.
type Options struct {
	Build     version.Info
	Getenv    func(string) string
	NewClient ClientFactory
	Stdin     io.Reader
	// Routes shows or changes the host's route settings as meshnetd routes
	// does (args after "routes"), asking for the privileges a change needs;
	// nil where meshctl cannot change them. quiet leaves out the settings
	// printed after a change. delegated reports the command ran again
	// elsewhere (meshctl through sudo), which said all there was to say.
	Routes func(args []string, quiet bool, stdout, stderr io.Writer) (code int, delegated bool)
	// Captive opens or closes a captive portal window, asking for the
	// privileges it needs (exit node design §17.4); nil where meshctl
	// cannot. delegated is as for Routes.
	Captive func(request CaptiveRequest, stdout, stderr io.Writer) (code int, delegated bool)
	// ExitWait bounds how long exit use waits for meshd to apply the
	// choice; zero waits 15 s.
	ExitWait time.Duration
	// ConnectWait bounds how long login waits, once registered, for the
	// first map to print this machine's addresses; zero waits 10 s, and a
	// negative value does not wait.
	ConnectWait time.Duration
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

	// A captive portal window is root's to open: it goes through Captive,
	// never the daemon, which can only be told to look.
	if len(commandArgs) >= 2 && commandArgs[0] == "exit" && commandArgs[1] == "captive" {
		return runCaptive(ctx, commandArgs[2:], stdout, stderr, options, global)
	}

	// The host's route settings are root's: they go through Routes, not the
	// daemon, which can never change them.
	if routes, handled := hostRouteArgs(commandArgs); handled {
		if global.isJSON {
			_, _ = fmt.Fprintf(stderr, "meshctl: %s has no JSON output\n", strings.Join(commandArgs[:min(2, len(commandArgs))], " "))
			return 2
		}
		quiet := commandArgs[0] == "exit"
		code, delegated := runHostRoutes(commandArgs[0], routes, quiet, stdout, stderr, options.Routes)
		if code != 0 || delegated || !quiet {
			return code
		}
		if routes[0] == "exit-mode" {
			_, _ = fmt.Fprintf(stdout, "Exit node: %s\n", exitServeText[routes[1]])
			return 0
		}
		return waitForExit(ctx, routes[1], stdout, options, global)
	}

	timeout := global.timeout
	switch commandArgs[0] {
	case "netcheck":
		// A classification waits for STUN answers; never cut it short.
		timeout = max(timeout, netcheckTimeout)
	case "logout", "deregister", "down":
		// meshd first stops the control session; logout then waits for Core.
		timeout = max(timeout, connectionTimeout)
	case "dns":
		// A zone whose resolvers do not answer takes its whole budget.
		timeout = max(timeout, dnsQueryTimeout)
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
			cmp.Or(options.ConnectWait, connectWaitDefault),
		)
	case "identity":
		return runIdentity(ctx, commandArgs[1:], stdout, stderr, global.isJSON, client)
	case "netcheck":
		return runNetcheck(ctx, commandArgs[1:], stdout, stderr, global.isJSON, client)
	case "dns":
		return runDNS(ctx, commandArgs[1:], stdout, stderr, global.isJSON, client)
	case "down":
		return runDown(ctx, commandArgs[1:], stdout, stderr, global.isJSON, client)
	case "logout":
		return runLogout(ctx, commandArgs[1:], stdout, stderr, global.isJSON, client)
	case "deregister":
		// The same as logout --remove (NetBird's name for it).
		if len(commandArgs) != 1 {
			_, _ = fmt.Fprintln(stderr, "usage: meshctl deregister")

			return 2
		}
		return runLogout(ctx, []string{"--remove"}, stdout, stderr, global.isJSON, client)
	case "kube":
		return runKube(ctx, commandArgs[1:], stdout, stderr, global.isJSON, client)
	case "exit":
		if len(commandArgs) == 2 && commandArgs[1] == "status" {
			if global.isJSON {
				_, _ = fmt.Fprintln(stderr, "meshctl: exit status has no JSON output; meshctl --json status carries the exit in use")
				return 2
			}
			return runExitStatus(ctx, stdout, stderr, client, options.Routes)
		}
		return runExit(ctx, commandArgs[1:], stdout, stderr, global.isJSON, client)
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

// addAccountProfile has meshd add an account on the active profile's server
// (design §7): a profile pinned with the same key before it becomes active,
// so the next login signs another account in as a new Device while the
// previous profile keeps its own. Profiles are switched, never logged out.
func addAccountProfile(ctx context.Context, client DaemonClient, name string) (localapi.Profile,
	localapi.Profile, error,
) {
	added, err := client.AddAccount(ctx, name)
	if errors.Is(err, localapi.ErrEndpointMissing) {
		// An older meshd has no account endpoint; a JSON 404 is its own answer.
		return localapi.Profile{}, localapi.Profile{}, errors.New("this meshd cannot add accounts; update it first")
	}
	if err != nil {
		return localapi.Profile{}, localapi.Profile{}, err
	}
	return added.Profile, added.Previous, nil
}

func runLogin(
	ctx context.Context,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
	connectWait time.Duration,
) int {
	// A registered login waits for the first map, so the addresses it
	// prints are the ones the machine uses (TD-CLI-102).
	finish := func(result localapi.Login) int {
		code := writeLoginResult(stdout, stderr, isJSON, result)
		if code == 0 && !isJSON && result.State == "registered" && connectWait > 0 {
			writeConnectedAddresses(ctx, stdout, client, result.ProfileID, connectWait)
		}
		return code
	}
	if len(args) > 0 && args[0] == "complete" {
		if len(args) != 1 {
			_, _ = fmt.Fprintln(stderr, "usage: meshctl login complete")

			return 2
		}
		result, err := client.CompleteLogin(ctx)
		if err != nil {
			return writeRuntimeError(stderr, err)
		}

		return finish(result)
	}

	flags := flag.NewFlagSet("meshctl login", flag.ContinueOnError)
	flags.SetOutput(stderr)
	authKeyStdin := flags.Bool("auth-key-stdin", false, "read an auth key from stdin")
	newAccount := flags.Bool("new-account", false,
		"sign in with another account in a new profile for the same server; the current one keeps its device")
	accountName := flags.String("name", "", "the new profile's name with --new-account")
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
			"usage: meshctl login [--new-account [--name NAME]] [--auth-key-stdin] [--no-wait] [--wait-timeout DURATION]",
		)

		return 2
	}
	if *waitTimeout <= 0 {
		_, _ = fmt.Fprintln(stderr, "meshctl: login wait timeout must be positive")

		return 2
	}
	if *accountName != "" && !*newAccount {
		_, _ = fmt.Fprintln(stderr, "meshctl: --name goes with --new-account")

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
	if *newAccount {
		created, previous, err := addAccountProfile(ctx, client, *accountName)
		if err != nil {
			return writeRuntimeError(stderr, err)
		}
		// On stderr in --json mode, so the login result stays the output.
		notice := stdout
		if isJSON {
			notice = stderr
		}
		_, _ = fmt.Fprintf(notice, "Created profile %q (%s) for this server and made it active. %q keeps its "+
			"device: meshctl profile use %s switches back.\n", created.Name, created.ID, previous.Name, previous.ID)
	}
	result, err := client.StartLogin(ctx, authKey)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	if result.State != "authorization_required" {
		return finish(result)
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

	return waitForLogin(waitCtx, stderr, *waitTimeout, client, finish)
}

func waitForLogin(
	ctx context.Context,
	stderr io.Writer,
	waitTimeout time.Duration,
	client DaemonClient,
	finish func(localapi.Login) int,
) int {
	for {
		result, err := client.CompleteLogin(ctx)
		switch {
		case err == nil && result.State == "registered":
			return finish(result)
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

// connectWaitDefault bounds how long login waits for the first map.
const connectWaitDefault = 10 * time.Second

// writeConnectedAddresses waits, within wait, for the control session to
// deliver the first map, then prints the machine's addresses; it never
// fails the login.
func writeConnectedAddresses(ctx context.Context, stdout io.Writer, client DaemonClient, profileID string,
	wait time.Duration,
) {
	_, _ = fmt.Fprintln(stdout, "Connecting...")
	waitCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	// A blocked or suspended state seen first may be the one before this
	// login: the session loop wakes to it in the background.
	moved := false
	for {
		status, err := client.Status(waitCtx)
		if err == nil && status.ActiveProfileID == profileID {
			if line, done := connectionOutcome(status, moved); done {
				_, _ = fmt.Fprintln(stdout, line)
				return
			}
			moved = moved || !stoppedSession(status.ControlSession)
		}
		timer := time.NewTimer(connectPollDelay)
		select {
		case <-timer.C:
		case <-waitCtx.Done():
			timer.Stop()
			if ctx.Err() != nil {
				// Cancelled (Ctrl-C): the login itself succeeded.
				return
			}
			_, _ = fmt.Fprintln(stdout, "Still connecting; meshctl status shows the addresses once connected.")
			return
		}
	}
}

// connectionOutcome is the line login prints for status, and whether the
// wait is over: connected, kept down, or stopped for a reason status shows
// (only once the session has moved since the login).
func connectionOutcome(status localapi.Status, moved bool) (string, bool) {
	switch {
	// An older meshd reports down only as the control session state.
	case status.Disconnected || status.ControlSession == "down":
		return "meshd stays off the network (meshctl down): meshctl up connects.", true
	case status.ControlSession == "synchronized" && len(status.SelfAddresses) > 0:
		return "Connected. Addresses: " + strings.Join(status.SelfAddresses, ", ") + ".", true
	case moved && stoppedSession(status.ControlSession):
		return "Not connected (" + status.ControlSession + "): meshctl status says why.", true
	}
	return "", false
}

// stoppedSession reports a control session that stays stopped until
// something changes.
func stoppedSession(state string) bool {
	return state == "blocked" || state == "suspended"
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
	// The account and its Network, as the active profile's map last named
	// them (self.identity1, S4b §4.2); nothing from an older meshd or Core.
	networkLine := activeAccountLines(ctx, client, status.ActiveProfileID)
	if networkLine == "" && status.NetworkName != "" {
		networkLine = "Network: " + status.NetworkName + "\n"
	}
	selfAddresses := "none"
	if len(status.SelfAddresses) > 0 {
		selfAddresses = strings.Join(status.SelfAddresses, ", ")
	}
	deviceExpiry := formatDeviceExpiry(status.DeviceExpiry, status.DeviceExpiresAt, time.Now())
	if status.Registration == "signed_out" {
		// Offline, so nothing is known here; the Network keeps them.
		selfAddresses = "kept in the Network while signed out"
		deviceExpiry = "not applicable while signed out (the server may remove it after 30 days signed out)"
	}
	_, _ = fmt.Fprintf(
		stdout,
		"Daemon: %s\nState: %s\nData plane: %s\nDNS: %s\nNetwork changes: %s\nRuntime recovery: %s\nRuntime: %s\nActive profile: %s\nProfiles: %d\nControl trust: %s\nRegistration: %s\nControl session: %s\nNetmap revision: %d\n%sSelf addresses: %s\nDevice expiry: %s\nPeers: %d\nPeer paths: %s\nSubnet routes: %s\nSubnet router: %s\nExit node: %s\nExit: %s\nKubernetes clusters: %s\nConnection logging: %s\nPath transitions: %s\nPath probes: %s\nRelay: %s\nNAT: %s\nPort mapping: %s\nCloud: %s\nPolicy rules: %d\nControl key: %s\nNote: %s\n",
		status.Daemon.Version,
		status.State,
		status.DataPlane,
		formatDNSStatus(status.DNS, status.DNSError),
		formatNetworkChangeStatus(status.NetworkChanges),
		formatRuntimeRecoveryStatus(status.RuntimeRecovery),
		formatRuntimeStatus(status.Runtime),
		activeProfile,
		status.ProfileCount,
		status.ControlTrust,
		status.Registration,
		status.ControlSession,
		status.NetmapRevision,
		networkLine,
		selfAddresses,
		deviceExpiry,
		status.PeerCount,
		formatPathStatus(status.PeerPaths),
		formatSubnetRouteStatus(status.SubnetRoutes),
		formatSubnetRouterStatus(status.SubnetRouter),
		formatExitNodeStatus(status.ExitNode),
		formatExitStatus(status.Exit)+formatCaptive(status.Captive),
		formatKubernetesClusters(status.KubernetesClusters),
		formatConnectionLogs(status.ConnectionLogs),
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

// formatConnectionLogs says whether this machine's connections are logged
// for its Network, as people on it should know.
func formatConnectionLogs(status *localapi.ConnectionLogStatus) string {
	if status == nil || !status.On {
		return "off"
	}
	text := fmt.Sprintf("on (%d batches pending", status.Pending)
	if status.LastSent != "" {
		text += ", last sent " + status.LastSent
	}
	if status.LastError != "" {
		text += ", last error: " + status.LastError
	}
	return text + ")"
}

// formatKubernetesClusters names each cluster this machine may reach with
// how far it trusts the cluster's gateways.
func formatKubernetesClusters(clusters []localapi.KubernetesClusterStatus) string {
	if len(clusters) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(clusters))
	for _, cluster := range clusters {
		parts = append(parts, cluster.Name+" "+cluster.State)
	}
	return strings.Join(parts, ", ")
}

// formatDNSStatus is the DNS state, with the host's refusal when it failed.
func formatDNSStatus(state, failure string) string {
	if failure == "" {
		return state
	}
	return state + " (" + failure + ")"
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
	for _, site := range status.Sites {
		// The name when Core sent one, with the prefixes the rules grant.
		name := site.Site
		if len(site.Prefixes) > 0 {
			name = strings.Join(site.Prefixes, ", ")
			if site.Name != "" {
				name = site.Name + " (" + name + ")"
			}
		} else if site.Name != "" {
			name = site.Name
		}
		summary += "; Site " + name + " " + formatRouteSite(site)
	}
	return summary
}

// formatRouteSite says which router a Site's traffic goes to and why.
func formatRouteSite(site localapi.SubnetRouteSite) string {
	// The Device's own name, without its Network's DNS suffix.
	router, _, _ := strings.Cut(site.RouterName, ".")
	if router == "" {
		router = site.Router
	}
	switch site.Via {
	case "primary":
		return "via " + router
	case "local_failover":
		return "via " + router + " (chosen here: the primary does not answer)"
	default:
		return "not served"
	}
}

// formatExitStatus says which exit node the Internet goes through, and
// that it is dropped while none carries it.
func formatExitStatus(status *localapi.ExitStatus) string {
	if status == nil {
		return "none"
	}
	pool := cmp.Or(status.PoolName, status.Pool)
	var summary string
	switch {
	case status.Pool == "":
		summary = fmt.Sprintf("%s: pool not granted; Internet traffic is dropped", status.Use)
	case status.ExitNode == "":
		summary = fmt.Sprintf("pool %s: no exit node available; Internet traffic is dropped", pool)
	default:
		summary = fmt.Sprintf("via %s in pool %s", cmp.Or(status.ExitNodeName, status.ExitNode), pool)
		switch status.Via {
		case "local_failover":
			summary += " (chosen here: the primary does not answer)"
		case "primary_unapproved":
			summary += " (chosen here: the primary waits for approval)"
		case "sticky":
			summary += " (kept: Core elected another primary)"
		}
		if !status.IPv6 {
			summary += "; IPv6 blocked"
		}
	}
	if len(status.Pending) != 0 {
		waiting := make([]string, len(status.Pending))
		for index, id := range status.Pending {
			waiting[index] = id
			if index < len(status.PendingNames) && status.PendingNames[index] != id {
				waiting[index] = status.PendingNames[index] + " (" + id + ")"
			}
		}
		summary += "; new exit nodes wait for meshctl exit approve ID: " + strings.Join(waiting, ", ")
	}
	if status.PendingPool != "" {
		summary += "; another pool now has this name: meshctl exit approve " + status.PendingPool
	}
	if status.Tampered {
		summary += "; another program changed the exit routes, installed again"
	}
	switch {
	case status.Error != "":
		summary += "; error: " + status.Error
	case !status.Routing && status.Refused != "":
		summary += " [helper: " + status.Refused + "]"
	case !status.Routing:
		summary += " [not routed yet]"
	}
	return summary
}

func formatExitNodeStatus(status *localapi.ExitNodeStatus) string {
	if status == nil || (status.Pool == "" && status.Error == "") {
		return "none"
	}
	var summary string
	switch {
	case status.Serving:
		summary = fmt.Sprintf("serving pool %s, %d connections per consumer, %d consumers", status.Pool,
			status.ConntrackPerConsumer, status.MaxConsumers)
		if status.SMTPAllowed {
			summary += ", SMTP allowed"
		}
	case status.Refused != "":
		summary = fmt.Sprintf("not serving pool %s [%s]", status.Pool, status.Refused)
	default:
		summary = fmt.Sprintf("not serving pool %s", status.Pool)
	}
	if status.State != "" && status.State != "ok" {
		summary += " [" + status.State + " " + status.Code + "]"
	}
	if status.Families != "" {
		summary += "; Internet over " + status.Families
	}
	if status.Error != "" {
		summary += "; error: " + status.Error
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
	var unhealthy []string
	for _, site := range status.SiteHealth {
		if site.State != "ok" {
			unhealthy = append(unhealthy, site.Site+" "+site.State+" "+site.Code)
		}
	}
	if len(unhealthy) > 0 {
		summary += "; " + strings.Join(unhealthy[:min(len(unhealthy), maximumListedRefusals)], ", ")
		if len(unhealthy) > maximumListedRefusals {
			summary += ", ..."
		}
	}
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
	case "remove":
		return runProfileRemove(ctx, args[1:], stdout, stderr, isJSON, client)
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
	_, _ = fmt.Fprintln(table, "ACTIVE\tNAME\tACCOUNT\tNETWORK\tSTATE\tID\tCONTROL URL")
	for _, item := range response.Profiles {
		marker := ""
		if item.IsActive {
			marker = "*"
		}
		state := item.State
		if state == "" {
			state = "-"
		}
		if item.Removed && state == "unregistered" {
			state = "removed"
		}
		account, network := profileAccountColumns(item.Identity)
		_, _ = fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", marker, item.Name, account, network, state, item.ID,
			item.ControlURL)
	}
	if err := table.Flush(); err != nil {
		return writeRuntimeError(stderr, fmt.Errorf("writing profile table: %w", err))
	}

	return 0
}

// activeAccountLines are the status lines naming the active profile's
// account and Network; empty when unknown. Best effort: a failed list only
// leaves them out.
func activeAccountLines(ctx context.Context, client DaemonClient, activeID string) string {
	if activeID == "" {
		return ""
	}
	profiles, err := client.ListProfiles(ctx)
	if err != nil {
		return ""
	}
	for _, item := range profiles.Profiles {
		if item.ID != activeID || item.Identity == nil {
			continue
		}
		account, network := profileAccountColumns(item.Identity)
		return "Account: " + account + "\nNetwork: " + network + "\n"
	}
	return ""
}

// profileAccountColumns is who an account is and its Network, as its map
// last named them: the owner's name, or Workspace for a Workspace's Device;
// "-" until a map named them.
func profileAccountColumns(identity *localapi.ProfileIdentity) (string, string) {
	if identity == nil {
		return "-", "-"
	}
	account := identity.Owner
	if identity.Ownership == "workspace" {
		account = "Workspace " + identity.Workspace
	} else if account == "" {
		account = "-"
	}
	return account, identity.Network
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

// runProfileRemove deletes an inactive profile by id or name. Core removes
// its Device first; --local only drops the keys here (design §7, §2.2).
func runProfileRemove(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	flags := flag.NewFlagSet("meshctl profile remove", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	local := flags.Bool("local", false, "drop the profile's keys here without asking Core")
	// The profile comes first or last: `remove NAME --local` reads naturally.
	// After "--" nothing is a flag.
	positional := []string{}
	rest := args
	for len(rest) > 0 {
		before := len(rest)
		if err := flags.Parse(rest); err != nil {
			_, _ = fmt.Fprintln(stderr, "usage: meshctl profile remove PROFILE_ID|NAME [--local]")

			return 2
		}
		rest = flags.Args()
		consumed := before - len(rest)
		if consumed > 0 && args[len(args)-before+consumed-1] == "--" {
			positional = append(positional, rest...)
			break
		}
		if len(rest) > 0 {
			positional = append(positional, rest[0])
			rest = rest[1:]
		}
	}
	if len(positional) != 1 || strings.TrimSpace(positional[0]) == "" {
		_, _ = fmt.Fprintln(stderr, "usage: meshctl profile remove PROFILE_ID|NAME [--local]")

		return 2
	}
	target, err := resolveProfile(ctx, client, positional[0])
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	removal, err := client.RemoveProfile(ctx, target.ID, *local)
	if err != nil {
		apiErr := &localapi.APIError{}
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusMethodNotAllowed {
			// An older meshd has no profile removal.
			return writeRuntimeError(stderr, errors.New("this meshd cannot remove profiles; update it first"))
		}
		return writeRuntimeError(stderr, err)
	}
	if isJSON {
		return writeJSON(stdout, stderr, removal)
	}
	_, _ = fmt.Fprintln(stdout, profileRemovalMessage(removal))

	return 0
}

// resolveProfile finds a profile by id, else by name (case folded, as the
// store compares names).
func resolveProfile(ctx context.Context, client DaemonClient, reference string) (localapi.Profile, error) {
	profiles, err := client.ListProfiles(ctx)
	if err != nil {
		return localapi.Profile{}, err
	}
	reference = strings.TrimSpace(reference)
	for _, item := range profiles.Profiles {
		if item.ID == reference {
			return item, nil
		}
	}
	for _, item := range profiles.Profiles {
		if strings.EqualFold(item.Name, reference) {
			return item, nil
		}
	}

	return localapi.Profile{}, fmt.Errorf("no profile %q (meshctl profile list shows them)", reference)
}

func profileRemovalMessage(removal localapi.ProfileRemoval) string {
	name := removal.Profile.Name
	switch removal.Device {
	case "removed":
		return fmt.Sprintf("Removed profile %q and its device from the Network.", name)
	case "already_removed":
		return fmt.Sprintf("Removed profile %q; its device had already been removed from the Network.", name)
	case "pending":
		return fmt.Sprintf("Removed profile %q. Its browser sign-in was never approved: do not approve that link "+
			"now, or remove the device it makes in the Console.", name)
	case "left":
		return fmt.Sprintf("Removed profile %q from this machine only. If its device is still in the Network, "+
			"an administrator removes it in the Console.", name)
	default:
		return fmt.Sprintf("Removed profile %q; it had no device.", name)
	}
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

// dnsQueryTimeout outlasts a zone's budget (5 s) and the resolver's own
// failure, within the local API's write timeout.
const dnsQueryTimeout = 9 * time.Second

func writeUsage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, `Usage:
  meshctl [--socket PATH] [--timeout DURATION] [--json] COMMAND

Commands:
  up [--server U --fingerprint SHA256]    Connect this machine (MeshTransit Cloud by default)
  down                                    Disconnect this machine and stay off until up
  logout [--remove]                       Sign out and keep this machine's device; login brings it back
                                          (--remove, or deregister: remove it; up enrolls a new one)
  status                                  Show daemon and data-plane status
  profile list                            List configured profiles
  profile create --name N --control-url U Create an isolated profile
  profile use PROFILE_ID                  Select the only active profile
  profile remove PROFILE [--local]        Remove an inactive profile and its device (--local: only here)
  profile trust --fingerprint SHA256      Verify and pin the active control key
  login [--auth-key-stdin] [--no-wait] [--wait-timeout DURATION]
                                          Register the active profile and wait for browser approval
  login complete                          Recover a pending browser authorization
  identity rotate-node-key                Rotate the active profile Node key
  netcheck                                Classify the NAT in front of this machine now
  dns query NAME [TYPE]                   Ask MeshTransit DNS for a name and show where it went
  exit use POOL|auto|off                  Send this machine's Internet traffic through an Exit Pool (needs root or administrator)
  exit serve on|off                       Offer to be an exit node for other Devices (needs root or administrator)
  exit status                             Show this machine's exit choice and the exit node in use
  exit approve ID...                      Use the exit nodes (or pool) status lists as waiting
  routes COMMAND                          Show or change subnet and exit route settings (meshctl routes show)
  kube list                               List the Kubernetes clusters this Device may reach
  kube login CLUSTER [--group G] [--use]  Add a kubectl context for a cluster (no credential is written)
  kube logout CLUSTER|--all               Remove the kubectl contexts meshctl added
  kube doctor [CLUSTER]                   Check, step by step, why kubectl cannot reach a cluster
  kube audit-check LOG --records FILE     Find writes in an API server audit log that Core never recorded
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
  meshctl profile remove PROFILE_ID|NAME [--local]
  meshctl profile trust --fingerprint SHA256_FINGERPRINT`)
}

// formatCaptive says that a captive portal holds the host, and how to sign
// in; empty when none does.
func formatCaptive(status *localapi.CaptiveStatus) string {
	if status == nil {
		return ""
	}
	where := ""
	if status.URL != "" {
		where = ", sign in at " + status.URL + " (reported by the network)"
	}
	if status.State == "open" {
		window := "captive portal window open"
		if until, err := time.Parse(time.RFC3339, status.Until); err == nil {
			window += " until " + until.Local().Format(time.TimeOnly)
		}
		if status.Interface != "" {
			window += " on " + status.Interface
		}
		return "; " + window + ": HTTP and HTTPS go straight to the network" + where
	}
	what := "a captive portal holds this network"
	if status.State == "suspected" {
		what = "this network looks like a captive portal"
	}
	command := "sudo meshctl exit captive"
	if runtime.GOOS == "windows" {
		command = "meshctl exit captive (as administrator)"
	}
	return "; " + what + where + ": " + command + " opens it for 2 minutes"
}
