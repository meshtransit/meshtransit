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
	default:
		writeKubeUsage(stderr)
		return 2
	}
}

func writeKubeUsage(stderr io.Writer) {
	_, _ = fmt.Fprintln(stderr, "usage: meshctl kube list\n"+
		"       meshctl kube login <cluster> [--group <group>] [--use] [--kubeconfig <file>] [--force]\n"+
		"       meshctl kube logout <cluster> | --all [--any-profile] [--kubeconfig <file>]")
}

func runKubeList(ctx context.Context, args []string, stdout, stderr io.Writer, isJSON bool, client DaemonClient) int {
	if len(args) != 0 {
		writeKubeUsage(stderr)
		return 2
	}
	status, err := client.Status(ctx)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	if isJSON {
		return writeJSON(stdout, stderr, kubeClusters(status))
	}
	if len(status.KubernetesClusters) == 0 {
		_, _ = fmt.Fprintln(stdout, "No Kubernetes clusters in this Network's map.")
		return 0
	}
	for _, cluster := range status.KubernetesClusters {
		_, _ = fmt.Fprintf(stdout, "%-24s %-40s %-11s %s\n", cluster.Name, valueOr(cluster.DNSName, "-"), cluster.State,
			valueOr(cluster.CAFileState, "-"))
	}
	return 0
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
	answer, err := kubeWhoami(ctx, cluster)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %s: %v (meshctl doctor, meshctl status)\n", cluster.Name, err)
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
	match := func(marker kubeconfig.Marker) bool {
		return *anyProfile || marker.ProfileID == status.ActiveProfileID
	}
	if name != "" {
		cluster, ok := findKubeCluster(status, name)
		if !ok {
			_, _ = fmt.Fprintf(stderr, "meshctl: no Kubernetes cluster %q in this Network's map\n", name)
			return 1
		}
		match = func(marker kubeconfig.Marker) bool {
			return marker.ProfileID == status.ActiveProfileID && marker.ClusterID == cluster.ID
		}
	}
	files, err := kubeFiles(*file)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)
		return 1
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
func kubeWhoami(ctx context.Context, cluster localapi.KubernetesClusterStatus) (kubeWhoamiAnswer, error) {
	roots, err := kubeRoots(cluster)
	if err != nil {
		return kubeWhoamiAnswer{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, kubeWhoamiTimeout)
	defer cancel()
	transport := &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: cluster.TLSServerName,
			MinVersion: tls.VersionTLS13},
		DialContext: (&net.Dialer{Timeout: kubeWhoamiTimeout}).DialContext,
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
