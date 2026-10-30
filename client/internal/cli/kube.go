package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"meshtransit.net/client/internal/cli/localapi"
	"meshtransit.net/client/internal/kubeconfig"
)

// kubeWhoamiTimeout bounds one whoami call to a cluster's gateway.
const kubeWhoamiTimeout = 5 * time.Second

// caMarkerPrefix starts a CA file meshd withheld (K1e design §3.2).
const caMarkerPrefix = "# MeshTransit: CA withheld ("

func runKube(ctx context.Context, args []string, stdout, stderr io.Writer, isJSON bool, client DaemonClient) int {
	if len(args) == 0 {
		writeKubeUsage(stderr)
		return 2
	}
	switch args[0] {
	case "list":
		return runKubeList(ctx, args[1:], stdout, stderr, isJSON, client)
	case "login":
		return runKubeLogin(ctx, args[1:], stdout, stderr, isJSON, client)
	case "logout":
		return runKubeLogout(ctx, args[1:], stdout, stderr, isJSON, client)
	case "doctor":
		return runKubeDoctor(ctx, args[1:], stdout, stderr, isJSON, client)
	case "audit-check":
		return runKubeAuditCheck(args[1:], stdout, stderr, isJSON)
	default:
		writeKubeUsage(stderr)
		return 2
	}
}

func writeKubeUsage(stderr io.Writer) {
	_, _ = fmt.Fprintln(stderr, "usage: meshctl kube list [--groups]\n"+
		"       meshctl kube doctor [<cluster>] [--kubeconfig <file>]   (the cluster comes first)\n"+
		"       meshctl kube audit-check <audit.log> --records <records.json>\n"+
		"       meshctl kube login <cluster> [--group <group>] [--use] [--kubeconfig <file>] [--force]\n"+
		"       meshctl kube logout <cluster> | --all [--any-profile] [--kubeconfig <file>]")
}

// kubeListEntry is a cluster as meshctl kube list --json shows it.
type kubeListEntry struct {
	localapi.KubernetesClusterStatus
	Groups      []string `json:"groups,omitempty"`
	GroupsError string   `json:"groups_error,omitempty"`
}

func runKubeList(ctx context.Context, args []string, stdout, stderr io.Writer, isJSON bool, client DaemonClient) int {
	flags := flag.NewFlagSet("kube list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	withGroups := flags.Bool("groups", false, "ask each cluster's gateway which groups this Device holds")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		writeKubeUsage(stderr)
		return 2
	}
	status, err := client.Status(ctx)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	entries := make([]kubeListEntry, len(kubeClusters(status)))
	for index, cluster := range kubeClusters(status) {
		entries[index].KubernetesClusterStatus = cluster
	}
	if *withGroups {
		kubeGroups(ctx, entries, kubeMeshPrefixes(status))
	}
	if isJSON {
		return writeJSON(stdout, stderr, entries)
	}
	if len(entries) == 0 {
		_, _ = fmt.Fprintln(stdout, "No Kubernetes clusters in this Network's map.")
		return 0
	}
	for _, entry := range entries {
		line := fmt.Sprintf("%-24s %-40s %-11s %s", entry.Name, valueOr(entry.DNSName, "-"), entry.State,
			valueOr(entry.CAFileState, "-"))
		switch {
		case len(entry.Groups) > 0:
			line += "  groups: " + strings.Join(entry.Groups, ", ")
		case entry.GroupsError != "":
			line += "  groups: (" + entry.GroupsError + ")"
		}
		_, _ = fmt.Fprintln(stdout, line)
	}
	return 0
}

// kubeGroups asks the gateways of usable clusters, four at a time.
func kubeGroups(ctx context.Context, entries []kubeListEntry, prefixes []netip.Prefix) {
	slots := make(chan struct{}, 4)
	done := make(chan struct{})
	pending := 0
	for index := range entries {
		if err := usableKubeCluster(entries[index].KubernetesClusterStatus); err != nil {
			entries[index].GroupsError = err.Error() // review e3 L10
			continue
		}
		pending++
		go func() {
			slots <- struct{}{}
			defer func() { <-slots; done <- struct{}{} }()
			answer, err := kubeWhoami(ctx, entries[index].KubernetesClusterStatus, prefixes)
			if err != nil {
				entries[index].GroupsError = err.Error()
				return
			}
			entries[index].Groups = answer.Groups
		}()
	}
	for range pending {
		<-done
	}
}

func kubeClusters(status localapi.Status) []localapi.KubernetesClusterStatus {
	if status.KubernetesClusters == nil {
		return []localapi.KubernetesClusterStatus{}
	}
	return status.KubernetesClusters
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// kubeLoginResult is meshctl --json kube login's answer.
type kubeLoginResult struct {
	Context  string   `json:"context"`
	File     string   `json:"file"`
	Group    string   `json:"group,omitempty"`
	Groups   []string `json:"groups"`
	Shadowed []string `json:"shadowed_by,omitempty"`
}

func runKubeLogin(ctx context.Context, args []string, stdout, stderr io.Writer, isJSON bool, client DaemonClient) int {
	flags := flag.NewFlagSet("kube login", flag.ContinueOnError)
	flags.SetOutput(stderr)
	group := flags.String("group", "", "Kubernetes group to act as (default: the cluster's default group)")
	use := flags.Bool("use", false, "make it the current context")
	file := flags.String("kubeconfig", "", "kubeconfig file to write (default: as kubectl chooses)")
	force := flags.Bool("force", false, "replace an entry of the same name that meshctl did not write")
	name, rest := splitFirst(args)
	if err := flags.Parse(rest); err != nil || name == "" || flags.NArg() != 0 {
		writeKubeUsage(stderr)
		return 2
	}
	status, err := client.Status(ctx)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	cluster, ok := findKubeCluster(status, name)
	if !ok {
		_, _ = fmt.Fprintf(stderr, "meshctl: no Kubernetes cluster %q in this Network's map (meshctl kube list)\n", name)
		return 1
	}
	if err := usableKubeCluster(cluster); err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %s: %v\n", cluster.Name, err)
		return 1
	}
	answer, err := kubeWhoami(ctx, cluster, kubeMeshPrefixes(status))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %s: %v (meshctl kube doctor %s)\n", cluster.Name, err, cluster.Name)
		return 1
	}
	if *group != "" && !slices.Contains(answer.Groups, *group) {
		_, _ = fmt.Fprintf(stderr, "meshctl: %s: you do not hold group %q; you hold %s\n", cluster.Name, *group,
			strings.Join(answer.Groups, ", "))
		return 1
	}
	entry := kubeconfig.Entry{
		Name: kubeContextName(status.NetworkName, cluster.Name, *group), Server: "https://" + cluster.DNSName,
		TLSServerName: cluster.TLSServerName, CAFile: cluster.CAFile,
		Marker: kubeconfig.Marker{ProfileID: status.ActiveProfileID, ClusterID: cluster.ID, Group: *group},
	}
	if *group != "" {
		entry.Server += "/mt/g/" + url.PathEscape(*group)
	}
	files, err := kubeFiles(*file)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)
		return 1
	}
	result, err := kubeconfig.Login(files, entry, *use, *force)
	if errors.Is(err, kubeconfig.ErrNameTaken) {
		// Another cluster, group or profile has the name: this one takes
		// its cluster ID too (review e2 H1).
		entry.Name = withSuffix(entry.Name, entry.Marker)
		result, err = kubeconfig.Login(files, entry, *use, *force)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)
		return 1
	}
	if isJSON {
		return writeJSON(stdout, stderr, kubeLoginResult{Context: entry.Name, File: result.File, Group: *group,
			Groups: answer.Groups, Shadowed: result.Shadowed})
	}
	_, _ = fmt.Fprintf(stdout, "Context %s written to %s.\n", entry.Name, result.File)
	_, _ = fmt.Fprintf(stdout, "Groups you hold: %s.\n", strings.Join(answer.Groups, ", "))
	for _, shadow := range result.Shadowed {
		_, _ = fmt.Fprintf(stdout, "Warning: %s comes first in KUBECONFIG and has an entry named %s; kubectl uses it.\n",
			shadow, entry.Name)
	}
	if *use {
		_, _ = fmt.Fprintln(stdout, "Try: kubectl get pods")
	} else {
		_, _ = fmt.Fprintf(stdout, "Try: kubectl --context %s get pods\n", entry.Name)
	}
	return 0
}

func runKubeLogout(ctx context.Context, args []string, stdout, stderr io.Writer, isJSON bool, client DaemonClient) int {
	flags := flag.NewFlagSet("kube logout", flag.ContinueOnError)
	flags.SetOutput(stderr)
	all := flags.Bool("all", false, "remove every context meshctl wrote for this profile")
	anyProfile := flags.Bool("any-profile", false, "with --all: of any profile, including ones removed")
	file := flags.String("kubeconfig", "", "kubeconfig file (default: as kubectl chooses)")
	name, rest := splitFirst(args)
	if err := flags.Parse(rest); err != nil || flags.NArg() != 0 || (name == "") == !*all || *anyProfile && !*all {
		writeKubeUsage(stderr)
		return 2
	}
	status, err := client.Status(ctx)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	files, err := kubeFiles(*file)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)
		return 1
	}
	match := func(marker kubeconfig.Marker) bool {
		return *anyProfile || marker.ProfileID == status.ActiveProfileID
	}
	if name != "" {
		clusters, err := kubeLogoutClusters(status, name, files)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)
			return 1
		}
		if len(clusters) == 0 {
			_, _ = fmt.Fprintf(stderr, "meshctl: no Kubernetes cluster %q in this Network's map, and no context "+
				"meshctl wrote for it (meshctl kube logout --all)\n", name)
			return 1
		}
		match = func(marker kubeconfig.Marker) bool {
			return marker.ProfileID == status.ActiveProfileID && clusters[marker.ClusterID]
		}
	}
	removed, err := kubeconfig.Logout(files, match)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)
		return 1
	}
	if isJSON {
		return writeJSON(stdout, stderr, map[string]int{"removed": removed})
	}
	_, _ = fmt.Fprintf(stdout, "Removed %d context(s).\n", removed)
	return 0
}

// kubeLogoutClusters are the IDs of the cluster named name (or of that
// ID): from the map, or, once the cluster left it (its rule removed, the
// cluster deleted), from this profile's contexts of clusters no longer in
// the map that bear the names login gave them, suffixed or not, or that
// cluster's ID (TD-CLI-92). Names two clusters share are ambiguous: logout
// refuses rather than guess.
func kubeLogoutClusters(status localapi.Status, name string, files []string) (map[string]bool, error) {
	if cluster, ok := findKubeCluster(status, name); ok {
		return map[string]bool{cluster.ID: true}, nil
	}
	managed, err := kubeconfig.Managed(files)
	if err != nil {
		return nil, err
	}
	inMap := map[string]bool{}
	for _, cluster := range status.KubernetesClusters {
		inMap[cluster.ID] = true
	}
	clusters := map[string]bool{}
	var names []string
	for _, context := range managed {
		marker := context.Marker
		if marker.ProfileID != status.ActiveProfileID || inMap[marker.ClusterID] {
			continue
		}
		base := kubeContextName(status.NetworkName, name, marker.Group)
		if marker.ClusterID == name || context.Name == base || context.Name == withSuffix(base, marker) {
			clusters[marker.ClusterID] = true
			names = append(names, context.Name)
		}
	}
	if len(clusters) > 1 {
		return nil, fmt.Errorf("contexts %s belong to %d clusters: log out by cluster ID", strings.Join(names, ", "),
			len(clusters))
	}
	return clusters, nil
}

// kubeFiles are the kubeconfig files kubectl would use.
func kubeFiles(explicit string) ([]string, error) {
	env := os.Getenv("KUBECONFIG")
	if explicit != "" || env != "" {
		return kubeconfig.Files(explicit, env, ""), nil
	}
	home := kubeHome()
	if home == "" {
		return nil, errors.New("no home directory; pass --kubeconfig")
	}
	return kubeconfig.Files("", "", home), nil
}

// kubeHome is the home directory kubectl uses.
func kubeHome() string {
	if runtime.GOOS != "windows" {
		home, _ := os.UserHomeDir()
		return home
	}
	return windowsKubeHome(os.Getenv, os.Stat)
}

// windowsKubeHome is client-go's homedir.HomeDir on Windows (review e2
// M3): the first of HOME, HOMEDRIVE+HOMEPATH and USERPROFILE that holds
// .kube\config; else, in the order HOME, USERPROFILE, HOMEDRIVE+HOMEPATH,
// the first writable directory, then the first that exists, then the first
// set.
func windowsKubeHome(getenv func(string) string, stat func(string) (os.FileInfo, error)) string {
	home, profile := getenv("HOME"), getenv("USERPROFILE")
	drivePath := ""
	if drive, path := getenv("HOMEDRIVE"), getenv("HOMEPATH"); drive != "" && path != "" {
		drivePath = drive + path
	}
	for _, candidate := range []string{home, drivePath, profile} {
		if candidate == "" {
			continue
		}
		if _, err := stat(filepath.Join(candidate, ".kube", "config")); err == nil {
			return candidate
		}
	}
	firstSet, firstExisting := "", ""
	for _, candidate := range []string{home, profile, drivePath} {
		if candidate == "" {
			continue
		}
		if firstSet == "" {
			firstSet = candidate
		}
		info, err := stat(candidate)
		if err != nil {
			continue
		}
		if firstExisting == "" {
			firstExisting = candidate
		}
		if info.IsDir() && info.Mode().Perm()&0o200 != 0 {
			return candidate
		}
	}
	if firstExisting != "" {
		return firstExisting
	}
	return firstSet
}

// withSuffix adds 8 hex characters of what tells the entry apart, within
// 63: a UUIDv7's first characters are shared by clusters made together
// (re-review e2 L1).
func withSuffix(name string, marker kubeconfig.Marker) string {
	sum := sha256.Sum256([]byte(marker.ProfileID + "|" + marker.ClusterID + "|" + marker.Group))
	suffix := "-" + hex.EncodeToString(sum[:4])
	if len(name)+len(suffix) > 63 {
		name = strings.TrimRight(name[:63-len(suffix)], "-")
	}
	return name + suffix
}

// splitFirst separates a leading positional argument from flags after it.
func splitFirst(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func findKubeCluster(status localapi.Status, name string) (localapi.KubernetesClusterStatus, bool) {
	for _, cluster := range status.KubernetesClusters {
		if cluster.Name == name || cluster.ID == name {
			return cluster, true
		}
	}
	return localapi.KubernetesClusterStatus{}, false
}

// usableKubeCluster says why a cluster cannot be logged in to yet.
func usableKubeCluster(cluster localapi.KubernetesClusterStatus) error {
	switch {
	case cluster.State != "trusted" && cluster.State != "incomplete":
		return fmt.Errorf("the cluster is %s, not trusted yet", cluster.State)
	case cluster.DNSName == "":
		return errors.New("the cluster has no mesh name yet")
	case cluster.CAFile == "":
		return errors.New("meshd keeps no CA file for it (a meshd older than K1e?)")
	case cluster.CAFileState != "current":
		return fmt.Errorf("its CA file is %s %s", cluster.CAFileState, cluster.CAFileReason)
	}
	return nil
}

// kubeContextName is mt-<network>-<cluster>[-<group>], in kubectl's safe
// characters, at most 63 long.
func kubeContextName(network, cluster, group string) string {
	parts := []string{"mt", network, cluster}
	if group != "" {
		parts = append(parts, group)
	}
	var builder strings.Builder
	for _, part := range parts {
		if part == "" {
			continue
		}
		if builder.Len() > 0 {
			builder.WriteByte('-')
		}
		for _, character := range strings.ToLower(part) {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				builder.WriteRune(character)
			} else {
				builder.WriteByte('-')
			}
		}
	}
	name := builder.String()
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	if len(name) > 63 {
		name = name[:63]
	}
	return strings.Trim(name, "-")
}

// kubeResolve and kubeMeshPrefixes are the resolver and the Network's
// address space; tests replace them to reach a gateway on loopback. No
// test that does calls t.Parallel.
var (
	kubeResolve      = net.DefaultResolver.LookupNetIP
	kubeMeshPrefixes = meshPrefixes
)

// meshPrefixes are where a cluster's gateway can be (review e3 H1): the
// CGNAT overlay and the Workspace's IPv6 /48 this Device's own address is
// in — never the alias range a cluster is not reached through, nor any ULA
// a LAN hands out.
func meshPrefixes(status localapi.Status) []netip.Prefix {
	prefixes := []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
	for _, self := range status.SelfAddresses {
		prefix, err := netip.ParsePrefix(self)
		if err != nil || !prefix.Addr().Is6() {
			continue
		}
		if workspace, err := prefix.Addr().Prefix(48); err == nil {
			prefixes = append(prefixes, workspace)
		}
	}
	return prefixes
}

func inPrefixes(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address.Unmap()) {
			return true
		}
	}
	return false
}

// kubeMeshAddress resolves a cluster's mesh name (host[:port], port 443 by
// default) and returns the first address inside the mesh, with every
// address the name resolved to: one outside means the name did not come
// from meshd (its DNS off, or a resolver answering for mesh.internal), and
// nothing is dialed.
func kubeMeshAddress(ctx context.Context, dnsName string, prefixes []netip.Prefix) (string, []netip.Addr, error) {
	host, port, err := net.SplitHostPort(dnsName)
	if err != nil {
		host, port = dnsName, "443"
	}
	if host == "" {
		return "", nil, errors.New("the cluster has no mesh name yet")
	}
	ctx, cancel := context.WithTimeout(ctx, kubeWhoamiTimeout)
	defer cancel()
	addresses, err := kubeResolve(ctx, "ip", host)
	if err != nil {
		return "", nil, fmt.Errorf("resolving %s: %w (is meshd's DNS on?)", host, err)
	}
	for _, address := range addresses {
		if inPrefixes(address, prefixes) {
			return net.JoinHostPort(address.Unmap().String(), port), addresses, nil
		}
	}
	return "", addresses, fmt.Errorf("%s resolves outside the mesh, to %s (is meshd's DNS on?)", host,
		joinAddresses(addresses))
}

func joinAddresses(addresses []netip.Addr) string {
	texts := make([]string, len(addresses))
	for index, address := range addresses {
		texts[index] = address.String()
	}
	return strings.Join(texts, ", ")
}

// kubeWhoamiAnswer is the gateway's /mt/v1/whoami.
type kubeWhoamiAnswer struct {
	Person       string   `json:"person,omitempty"`
	Device       string   `json:"device"`
	Groups       []string `json:"groups"`
	DefaultGroup string   `json:"default_group,omitempty"`
	Cluster      string   `json:"cluster"`
	Username     string   `json:"username,omitempty"`
}

// kubeRoots reads the cluster's CA file and checks that it holds exactly
// roots the map names (K1e design §4): meshctl trusts nothing else.
func kubeRoots(cluster localapi.KubernetesClusterStatus) (*x509.CertPool, error) {
	raw, err := os.ReadFile(cluster.CAFile)
	if err != nil {
		return nil, fmt.Errorf("reading its CA file: %w", err)
	}
	if bytes.HasPrefix(raw, []byte(caMarkerPrefix)) {
		return nil, errors.New("meshd withheld its CA file")
	}
	pool := x509.NewCertPool()
	count := 0
	for rest := raw; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			if len(bytes.TrimSpace(rest)) != 0 {
				return nil, errors.New("its CA file holds something that is not a certificate")
			}
			break
		}
		sum := sha256.Sum256(block.Bytes)
		if block.Type != "CERTIFICATE" || !slices.Contains(cluster.Roots, hex.EncodeToString(sum[:])) {
			return nil, errors.New("its CA file holds a certificate the map does not name")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("its CA file: %w", err)
		}
		pool.AddCert(certificate)
		count++
	}
	if count == 0 {
		return nil, errors.New("its CA file holds no certificate")
	}
	return pool, nil
}

// kubeWhoami asks the cluster's gateway who this Device is, over TLS that
// trusts the cluster's roots only, straight to its mesh address: never a
// proxy (review v1 M3).
func kubeWhoami(ctx context.Context, cluster localapi.KubernetesClusterStatus, prefixes []netip.Prefix,
) (kubeWhoamiAnswer, error) {
	roots, err := kubeRoots(cluster)
	if err != nil {
		return kubeWhoamiAnswer{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, kubeWhoamiTimeout)
	defer cancel()
	address, _, err := kubeMeshAddress(ctx, cluster.DNSName, prefixes)
	if err != nil {
		return kubeWhoamiAnswer{}, err
	}
	dialer := &net.Dialer{Timeout: kubeWhoamiTimeout}
	transport := &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: cluster.TLSServerName,
			MinVersion: tls.VersionTLS13},
		// Straight to the mesh address checked above, whatever the URL's host
		// resolves to later (K1e design §4).
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+cluster.DNSName+"/mt/v1/whoami", nil)
	if err != nil {
		return kubeWhoamiAnswer{}, err
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // a gateway never redirects whoami (review e2 L6)
	}}
	response, err := client.Do(request)
	if err != nil {
		return kubeWhoamiAnswer{}, fmt.Errorf("reaching its gateway: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return kubeWhoamiAnswer{}, fmt.Errorf("its gateway answered %s", response.Status)
	}
	var answer kubeWhoamiAnswer
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&answer); err != nil {
		return kubeWhoamiAnswer{}, fmt.Errorf("reading its gateway's answer: %w", err)
	}
	if len(answer.Groups) == 0 {
		return answer, errors.New("its gateway grants this Device no Kubernetes group")
	}
	return answer, nil
}
