package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"meshtransit.net/client/internal/cli/localapi"
	"meshtransit.net/client/internal/kubeconfig"
)

// kubeCheck is one step of meshctl kube doctor (K1e design §4): what was
// checked, whether it holds, why not and how to fix it.
type kubeCheck struct {
	Step   string `json:"step"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

// kubeDiagnosis is a cluster's checks and warnings.
type kubeDiagnosis struct {
	Cluster  string      `json:"cluster"`
	Checks   []kubeCheck `json:"checks"`
	Warnings []string    `json:"warnings,omitempty"`
	OK       bool        `json:"ok"`
}

func runKubeDoctor(ctx context.Context, args []string, stdout, stderr io.Writer, isJSON bool, client DaemonClient) int {
	flags := flag.NewFlagSet("kube doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("kubeconfig", "", "kubeconfig file to check (default: as kubectl chooses)")
	name, rest := splitFirst(args)
	if err := flags.Parse(rest); err != nil || flags.NArg() != 0 {
		writeKubeUsage(stderr)
		return 2
	}
	status, err := client.Status(ctx)
	if err != nil {
		diagnosis := kubeDiagnosis{Cluster: name, Checks: []kubeCheck{{Step: "meshd", Detail: err.Error(),
			Fix: "start meshd (meshctl status)"}}}
		return writeKubeDiagnoses(stdout, stderr, isJSON, []kubeDiagnosis{diagnosis})
	}
	var clusters []localapi.KubernetesClusterStatus
	if name != "" {
		cluster, ok := findKubeCluster(status, name)
		if !ok {
			daemon, _ := kubeDaemonCheck(status)
			diagnosis := kubeDiagnosis{Cluster: name, Checks: []kubeCheck{daemon, {
				Step: "cluster in the map", Detail: "this Network's map has no cluster " + name,
				Fix: "meshctl kube list; ask an administrator for a rule to the cluster"}}}
			return writeKubeDiagnoses(stdout, stderr, isJSON, []kubeDiagnosis{diagnosis})
		}
		clusters = append(clusters, cluster)
	} else {
		clusters = status.KubernetesClusters
	}
	if len(clusters) == 0 {
		daemon, _ := kubeDaemonCheck(status)
		diagnosis := kubeDiagnosis{Checks: []kubeCheck{daemon, {Step: "clusters in the map",
			Detail: "this Network's map has no Kubernetes cluster", Fix: "ask an administrator for a rule to a cluster"}}}
		return writeKubeDiagnoses(stdout, stderr, isJSON, []kubeDiagnosis{diagnosis})
	}
	files, filesErr := kubeFiles(*file)
	diagnoses := make([]kubeDiagnosis, 0, len(clusters))
	for _, cluster := range clusters {
		diagnoses = append(diagnoses, diagnoseKubeCluster(ctx, status, cluster, files, filesErr))
	}
	return writeKubeDiagnoses(stdout, stderr, isJSON, diagnoses)
}

// kubeDaemonCheck is step 1, and a warning for a session reconnecting:
// its last map and tunnels still serve kubectl (review e3 M3).
func kubeDaemonCheck(status localapi.Status) (kubeCheck, string) {
	check := kubeCheck{Step: "meshd online", OK: true}
	switch status.ControlSession {
	case "synchronized":
	case "reconnecting":
		return check, "meshd is reconnecting to Core; kubectl keeps working on the last map"
	default:
		check.OK = false
		check.Detail = "control session " + valueOr(status.ControlSession, "unknown")
		check.Fix = map[string]string{
			"down":      "meshctl up",
			"inactive":  "meshctl login",
			"blocked":   "meshctl status: Core refused this Device; ask an administrator",
			"suspended": "an administrator suspended this Device",
		}[status.ControlSession]
		if check.Fix == "" {
			check.Fix = "wait a moment and run doctor again; meshctl status"
		}
	}
	return check, ""
}

// diagnoseKubeCluster runs the steps in order and stops at the first that
// fails: each later one needs it.
func diagnoseKubeCluster(ctx context.Context, status localapi.Status, cluster localapi.KubernetesClusterStatus,
	files []string, filesErr error,
) kubeDiagnosis {
	diagnosis := kubeDiagnosis{Cluster: cluster.Name}
	add := func(check kubeCheck) bool {
		diagnosis.Checks = append(diagnosis.Checks, check)
		return check.OK
	}
	warn := func(warning string) {
		if warning != "" {
			diagnosis.Warnings = append(diagnosis.Warnings, warning)
		}
	}
	daemon, warning := kubeDaemonCheck(status)
	warn(warning)
	if !add(daemon) {
		return diagnosis
	}
	if cluster.HeldUntil != "" {
		warn("Core cannot confirm the cluster list; meshd holds it until " + cluster.HeldUntil)
	}
	if !add(trustedCheck(cluster)) {
		return diagnosis
	}
	if !add(caFileCheck(cluster)) {
		return diagnosis
	}
	prefixes := kubeMeshPrefixes(status)
	if !add(dnsCheck(ctx, cluster, prefixes)) {
		return diagnosis
	}
	warn(kubeProxyWarning(cluster.DNSName))
	if !add(gatewayCheck(ctx, cluster, prefixes)) {
		return diagnosis
	}
	context, warnings := kubeconfigCheck(cluster, status, files, filesErr)
	for _, warning := range warnings {
		warn(warning)
	}
	add(context)
	return diagnosis
}

func trustedCheck(cluster localapi.KubernetesClusterStatus) kubeCheck {
	check := kubeCheck{Step: "cluster trusted", OK: cluster.State == "trusted" || cluster.State == "incomplete"}
	if !check.OK {
		check.Detail = "the cluster is " + cluster.State
		check.Fix = map[string]string{
			"pending":     "the cluster has no CA yet; an administrator finishes setting it up",
			"invalid":     "no root the cluster names can be trusted; report it to an administrator",
			"unavailable": "Core cannot say which clusters this Device may reach; wait, or check Core's status",
		}[cluster.State]
		if check.Fix == "" {
			check.Fix = "upgrade meshctl; report the state to an administrator"
		}
	}
	return check
}

// caFileCheck: meshd wrote only roots that pass the map's checks, a P-256
// key and NameConstraints equal to the cluster's TLS name (kubecafile);
// meshctl checks the file holds exactly the map's roots.
func caFileCheck(cluster localapi.KubernetesClusterStatus) kubeCheck {
	switch {
	case cluster.CAFile == "":
		return kubeCheck{Step: "CA file", Detail: "meshd reports no CA file",
			Fix: "upgrade meshd: one older than K1e leaves CA files as they were"}
	case cluster.CAFileState != "current":
		return kubeCheck{Step: "CA file", Detail: strings.TrimSpace(cluster.CAFileState + " " + cluster.CAFileReason),
			Fix: "meshctl up; if it stays, see meshd's log (kubernetes_ca_*)"}
	}
	if _, err := kubeRoots(cluster); err != nil {
		return kubeCheck{Step: "CA file", Detail: err.Error(),
			Fix: "restart meshd: it rewrites the file from the map; if it stays, report it"}
	}
	return kubeCheck{Step: "CA file", OK: true}
}

// dnsCheck fails unless every address the name resolves to is in the
// mesh: kubectl dials them in the system's order (review e3 M2).
func dnsCheck(ctx context.Context, cluster localapi.KubernetesClusterStatus, prefixes []netip.Prefix) kubeCheck {
	check := kubeCheck{Step: "mesh name resolves", OK: true}
	_, addresses, err := kubeMeshAddress(ctx, cluster.DNSName, prefixes)
	if err != nil {
		check.OK, check.Detail = false, err.Error()
		check.Fix = "meshctl status: DNS must be on; meshctl dns query " + valueOr(cluster.DNSName, "<name>")
		return check
	}
	var outside []netip.Addr
	for _, address := range addresses {
		if !inPrefixes(address, prefixes) {
			outside = append(outside, address)
		}
	}
	if len(outside) > 0 {
		check.OK = false
		check.Detail = "it also resolves outside the mesh, to " + joinAddresses(outside)
		check.Fix = "another resolver answers for the mesh's names; let meshd's DNS answer them alone"
	}
	return check
}

func gatewayCheck(ctx context.Context, cluster localapi.KubernetesClusterStatus, prefixes []netip.Prefix) kubeCheck {
	answer, err := kubeWhoami(ctx, cluster, prefixes)
	if err == nil {
		return kubeCheck{Step: "gateway answers", OK: true, Detail: "groups: " + strings.Join(answer.Groups, ", ")}
	}
	check := kubeCheck{Step: "gateway answers", Detail: err.Error()}
	text := err.Error()
	port := "443"
	if _, given, splitErr := net.SplitHostPort(cluster.DNSName); splitErr == nil {
		port = given
	}
	switch {
	case strings.Contains(text, "no Kubernetes group"):
		check.Fix = "ask an administrator for a rule granting a Kubernetes group of the cluster"
	case strings.Contains(text, "x509") || strings.Contains(text, "tls:"):
		check.Fix = "the gateway's certificate does not match the cluster's CA: after a CA rotation restart meshd; " +
			"otherwise report it"
	default:
		check.Fix = "a policy rule must let this Device reach the cluster (TCP " + port + "), and the gateway must run"
	}
	return check
}

// kubeconfigCheck finds the contexts meshctl wrote for the cluster and
// checks kubectl will use them as written.
func kubeconfigCheck(cluster localapi.KubernetesClusterStatus, status localapi.Status, files []string,
	filesErr error,
) (kubeCheck, []string) {
	check := kubeCheck{Step: "kubectl context"}
	if filesErr != nil {
		check.Detail, check.Fix = filesErr.Error(), "pass --kubeconfig"
		return check, nil
	}
	found, err := kubeconfig.Find(files, cluster.ID)
	if err != nil {
		check.Detail, check.Fix = err.Error(), "fix or move the kubeconfig file named"
		return check, nil
	}
	var names, warnings []string
	for _, context := range found {
		if context.Marker.ProfileID != status.ActiveProfileID {
			continue
		}
		server := "https://" + cluster.DNSName
		if context.Marker.Group != "" {
			server += "/mt/g/" + url.PathEscape(context.Marker.Group) // as login writes it
		}
		switch {
		case context.ClusterMissing:
			check.Detail = context.Name + " in " + context.File + " has no cluster entry"
		case context.ShadowedBy != "":
			check.Detail = context.Name + " is shadowed by an entry of the same name in " + context.ShadowedBy
		case context.CAFile != cluster.CAFile || context.Server != server:
			check.Detail = context.Name + " in " + context.File + " points elsewhere"
		}
		if check.Detail != "" {
			check.Fix = "meshctl kube login " + cluster.Name
			return check, warnings
		}
		if context.ProxyURL != "" {
			warnings = append(warnings, context.Name+" sets proxy-url: kubectl sends the cluster's traffic to it")
		}
		names = append(names, context.Name)
	}
	if len(names) == 0 {
		check.Detail, check.Fix = "none yet", "meshctl kube login "+cluster.Name
		return check, warnings
	}
	check.OK, check.Detail = true, strings.Join(names, ", ")
	return check, warnings
}

// kubeProxyWarning warns when kubectl would send the cluster's traffic to
// an HTTPS proxy, which cannot reach the mesh: NO_PROXY matched as Go's
// httpproxy matches it (review e3 L7).
func kubeProxyWarning(dnsName string) string {
	if firstEnv("HTTPS_PROXY", "https_proxy") == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(dnsName)
	if err != nil {
		host, port = dnsName, "443"
	}
	host = strings.ToLower(host)
	for _, entry := range strings.Split(firstEnv("NO_PROXY", "no_proxy"), ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "*" {
			return ""
		}
		if entryHost, entryPort, err := net.SplitHostPort(entry); err == nil {
			if entryPort != port {
				continue
			}
			entry = entryHost
		}
		entry = strings.TrimPrefix(entry, "*")
		switch {
		case entry == "":
		case strings.HasPrefix(entry, "."):
			if strings.HasSuffix(host, entry) {
				return ""
			}
		case host == entry || strings.HasSuffix(host, "."+entry):
			return ""
		}
	}
	return "HTTPS_PROXY is set and NO_PROXY does not cover " + host + ": kubectl will send the cluster's traffic " +
		"to the proxy; add " + host + " (or its zone) to NO_PROXY"
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}

func writeKubeDiagnoses(stdout, stderr io.Writer, isJSON bool, diagnoses []kubeDiagnosis) int {
	failed := false
	settled := make([]kubeDiagnosis, 0, len(diagnoses))
	for _, diagnosis := range diagnoses {
		diagnosis.OK = true
		for _, check := range diagnosis.Checks {
			diagnosis.OK = diagnosis.OK && check.OK
		}
		failed = failed || !diagnosis.OK
		settled = append(settled, diagnosis)
	}
	if isJSON {
		if code := writeJSON(stdout, stderr, settled); code != 0 {
			return code
		}
	} else {
		for _, diagnosis := range settled {
			if diagnosis.Cluster != "" {
				_, _ = fmt.Fprintf(stdout, "%s\n", diagnosis.Cluster)
			}
			for _, check := range diagnosis.Checks {
				mark := "ok  "
				if !check.OK {
					mark = "FAIL"
				}
				line := fmt.Sprintf("  %s %s", mark, check.Step)
				if check.Detail != "" {
					line += ": " + check.Detail
				}
				_, _ = fmt.Fprintln(stdout, line)
				if !check.OK && check.Fix != "" {
					_, _ = fmt.Fprintf(stdout, "       fix: %s\n", check.Fix)
				}
			}
			for _, warning := range diagnosis.Warnings {
				_, _ = fmt.Fprintf(stdout, "  warn %s\n", warning)
			}
		}
	}
	if failed {
		return 1
	}
	return 0
}
