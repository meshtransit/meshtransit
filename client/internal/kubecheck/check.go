// Package kubecheck is `meshgw check`: what `helm test` and the preflight
// hook ask of a gateway install (K1c design §8). It reads, never changes,
// the cluster, except the one Event that carries its result.
package kubecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"meshtransit.net/client/internal/kubetoken"
)

// Level is how a finding counts: a failure fails the check, a warning is
// reported only.
type Level string

// Levels of a finding.
const (
	Fail Level = "fail"
	Warn Level = "warn"
)

// Finding is one thing the check found, safe to print: never a token.
type Finding struct {
	Level   Level  `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Report is what one check found.
type Report struct {
	Findings []Finding `json:"findings"`
}

// Failed reports any failure.
func (report Report) Failed() bool {
	return slices.ContainsFunc(report.Findings, func(finding Finding) bool { return finding.Level == Fail })
}

func (report *Report) add(level Level, code, format string, args ...any) {
	report.Findings = append(report.Findings, Finding{Level: level, Code: code, Message: fmt.Sprintf(format, args...)})
}

// Enforcement is what a policy's binding must do.
type Enforcement string

// Enforcements a policy may be expected to have.
const (
	// MustDeny fails the check unless the binding denies.
	MustDeny Enforcement = "deny"
	// ShouldDeny warns unless the binding denies.
	ShouldDeny Enforcement = "deny-or-warn"
	// AnyAction only needs the binding to exist.
	AnyAction Enforcement = "any"
)

// Policy is a ValidatingAdmissionPolicy the install must have.
type Policy struct {
	Name        string      `json:"name"`
	Binding     string      `json:"binding"`
	Enforcement Enforcement `json:"enforcement"`
	// PolicyHash and BindingHash are the chart's fingerprints of what it
	// rendered (policyHash, bindingHash).
	PolicyHash  string `json:"policyHash"`
	BindingHash string `json:"bindingHash"`
}

// Config is the check's configuration, rendered by the chart into one JSON
// value (MESHGW_CHECK_CONFIG); unknown fields are refused.
type Config struct {
	Namespace    string   `json:"namespace"`
	StatefulSet  string   `json:"statefulSet"`
	Replicas     int      `json:"replicas"`
	StatusPort   int      `json:"statusPort"`
	APIAudiences []string `json:"apiAudiences"`
	Policies     []Policy `json:"policies"`
	// ServiceAccount is the gateway's, CheckServiceAccount the check's:
	// the RBAC warnings leave them out.
	ServiceAccount      string          `json:"serviceAccount"`
	CheckServiceAccount string          `json:"checkServiceAccount"`
	Preflight           PreflightConfig `json:"preflight"`
}

// maximumConfig bounds MESHGW_CHECK_CONFIG.
const maximumConfig = 64 << 10

// ParseConfig reads MESHGW_CHECK_CONFIG strictly.
func ParseConfig(raw string) (Config, error) {
	if raw == "" || len(raw) > maximumConfig {
		return Config{}, errors.New("kubecheck: MESHGW_CHECK_CONFIG is missing or too long")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("kubecheck: MESHGW_CHECK_CONFIG: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("kubecheck: MESHGW_CHECK_CONFIG has more after its object")
	}
	if config.Namespace == "" || config.StatefulSet == "" || config.Replicas < 1 || config.Replicas > 10 ||
		config.StatusPort < 1 || config.StatusPort > 65535 || len(config.APIAudiences) == 0 ||
		config.ServiceAccount == "" || config.CheckServiceAccount == "" {
		return Config{}, errors.New("kubecheck: MESHGW_CHECK_CONFIG needs namespace, statefulSet, replicas, " +
			"statusPort, apiAudiences, serviceAccount and checkServiceAccount")
	}
	for _, policy := range config.Policies {
		if policy.Name == "" || policy.Binding == "" || policy.PolicyHash == "" || policy.BindingHash == "" ||
			!slices.Contains([]Enforcement{MustDeny, ShouldDeny, AnyAction}, policy.Enforcement) {
			return Config{}, fmt.Errorf("kubecheck: MESHGW_CHECK_CONFIG: policy %q is incomplete", policy.Name)
		}
	}
	return config, nil
}

// ReplicaStatus is the part of a replica's /status the check reads.
type ReplicaStatus struct {
	Ready  bool   `json:"ready"`
	Reason string `json:"reason"`
	Kube   struct {
		Listening bool   `json:"listening"`
		Closed    string `json:"closed_reason"`
		Groups    []struct {
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
			Reason  string `json:"reason"`
		} `json:"groups"`
	} `json:"kube"`
}

// Checker runs the gateway's checks.
type Checker struct {
	Config Config
	API    API
	// Status reads a replica's /status at host:port.
	Status func(ctx context.Context, host string, port int) (ReplicaStatus, error)
	// Audiences reads the API server's audiences from the check pod's own
	// token.
	Audiences func() ([]string, error)
}

// Run checks the install and reports what it found.
func (checker Checker) Run(ctx context.Context) Report {
	var report Report
	checker.replicas(ctx, &report)
	checker.policies(ctx, &report)
	checker.audiences(&report)
	checker.namespace(ctx, &report)
	checker.failedCreates(ctx, &report)
	checker.rbac(ctx, &report)
	return report
}

type pod struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		Phase      string `json:"phase"`
		PodIP      string `json:"podIP"`
		Conditions []struct {
			Type    string `json:"type"`
			Status  string `json:"status"`
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"conditions"`
	} `json:"status"`
}

func (checker Checker) path(format string, args ...string) string {
	escaped := make([]any, len(args))
	for index, arg := range args {
		escaped[index] = url.PathEscape(arg)
	}
	return fmt.Sprintf(format, escaped...)
}

// replicas checks every replica the StatefulSet should run: it has a pod,
// is scheduled, serves, and holds no group turned off; and they are not
// all on one node.
func (checker Checker) replicas(ctx context.Context, report *Report) {
	nodes, scheduled := map[string]bool{}, 0
	for ordinal := range checker.Config.Replicas {
		name := checker.Config.StatefulSet + "-" + strconv.Itoa(ordinal)
		var got pod
		err := checker.API.Get(ctx, checker.path("/api/v1/namespaces/%s/pods/%s", checker.Config.Namespace, name), &got)
		switch {
		case NotFound(err):
			report.add(Fail, "replica_missing", "replica %s has no pod", name)
			continue
		case err != nil:
			report.add(Fail, "replica_unreadable", "replica %s: %v", name, err)
			continue
		}
		if got.Spec.NodeName == "" {
			reason := "not scheduled"
			for _, condition := range got.Status.Conditions {
				if condition.Type == "PodScheduled" && condition.Status != "True" {
					reason = printable(condition.Reason + ": " + condition.Message)
				}
			}
			report.add(Fail, "replica_pending", "replica %s is not scheduled: %s", name, reason)
			continue
		}
		if got.Status.Phase == "Pending" {
			report.add(Fail, "replica_starting", "replica %s is starting on node %s", name,
				printable(got.Spec.NodeName))
			continue
		}
		nodes[got.Spec.NodeName] = true
		scheduled++
		if got.Status.PodIP == "" || checker.Status == nil {
			report.add(Fail, "replica_no_address", "replica %s has no pod address", name)
			continue
		}
		status, err := checker.Status(ctx, got.Status.PodIP, checker.Config.StatusPort)
		if err != nil {
			report.add(Fail, "replica_status_unreadable", "replica %s: /status: %v", name, err)
			continue
		}
		if !status.Ready {
			report.add(Fail, "replica_not_ready", "replica %s is not ready: %s", name, printable(status.Reason))
		}
		if !status.Kube.Listening {
			report.add(Fail, "replica_not_listening", "replica %s does not take kubectl: %s", name,
				printable(status.Kube.Closed))
		}
		for _, group := range status.Kube.Groups {
			if !group.Enabled {
				report.add(Fail, "group_disabled", "replica %s turned group %q off: %s", name, group.Name,
					printable(group.Reason))
			}
		}
	}
	if scheduled > 1 && len(nodes) == 1 {
		report.add(Warn, "replicas_one_node", "every replica runs on one node: losing it stops kubectl")
	}
}

type admissionObject struct {
	Spec   map[string]any `json:"spec"`
	Status struct {
		TypeChecking *struct {
			ExpressionWarnings []struct {
				FieldRef string `json:"fieldRef"`
				Warning  string `json:"warning"`
			} `json:"expressionWarnings"`
		} `json:"typeChecking"`
	} `json:"status"`
}

// policies checks the install's cluster-wide guards: present, failing
// closed, type-checked, as the chart rendered them, bound, and denying
// where they must (K1c §5.12).
func (checker Checker) policies(ctx context.Context, report *Report) {
	const base = "/apis/admissionregistration.k8s.io/v1/"
	read := func(kind, name string) (admissionObject, bool) {
		var object admissionObject
		err := checker.API.Get(ctx, checker.path(base+kind+"/%s", name), &object)
		switch {
		case NotFound(err):
			report.add(Fail, "policy_missing", "%s %s is missing", kind, name)
		case err != nil:
			// An unread guard is an unchecked one (review c2b M-b).
			if !forbidden(err) {
				report.add(Fail, "policy_unreadable", "%s %s: %v", kind, name, err)
			} else {
				checker.unreadable(report, kind+" "+name, err)
			}
		}
		return object, err == nil
	}
	for _, expected := range checker.Config.Policies {
		policy, ok := read("validatingadmissionpolicies", expected.Name)
		if ok {
			if failure, _ := policy.Spec["failurePolicy"].(string); failure != "Fail" {
				report.add(Fail, "policy_fails_open", "admission policy %s has failurePolicy %q, not Fail",
					expected.Name, printable(failure))
			}
			if checking := policy.Status.TypeChecking; checking != nil {
				for _, warning := range checking.ExpressionWarnings {
					report.add(Fail, "policy_type_warning", "admission policy %s: %s: %s", expected.Name,
						printable(warning.FieldRef), printable(warning.Warning))
				}
			}
			if hash, err := policyHash(policy.Spec); err != nil || hash != expected.PolicyHash {
				report.add(Fail, "policy_changed", "admission policy %s differs from what the chart installed", expected.Name)
			}
		}
		binding, ok := read("validatingadmissionpolicybindings", expected.Binding)
		if !ok {
			continue
		}
		if name, _ := binding.Spec["policyName"].(string); name != expected.Name {
			report.add(Fail, "binding_wrong_policy", "admission binding %s binds %q, not %s", expected.Binding,
				printable(name), expected.Name)
		}
		if hash, err := bindingHash(binding.Spec); err != nil || hash != expected.BindingHash {
			report.add(Fail, "binding_changed", "admission binding %s differs from what the chart installed",
				expected.Binding)
		}
		actions, _ := binding.Spec["validationActions"].([]any)
		if slices.Contains(actions, any("Deny")) {
			continue
		}
		switch expected.Enforcement {
		case MustDeny:
			report.add(Fail, "policy_not_enforced", "admission policy %s does not deny", expected.Name)
		case ShouldDeny:
			report.add(Warn, "policy_not_enforced", "admission policy %s only warns", expected.Name)
		}
	}
}

// audiences checks the chart's apiServerAudiences against the API
// server's own, which the token VAP admits; a mismatch turns every group
// off, so the finding names the value to set.
func (checker Checker) audiences(report *Report) {
	if checker.Audiences == nil {
		return
	}
	actual, err := checker.Audiences()
	if err != nil {
		report.add(Warn, "audiences_unknown", "the API server's audiences are unknown: %v", err)
		return
	}
	if !kubetoken.SameAudiences(actual, checker.Config.APIAudiences) {
		report.add(Fail, "audience_mismatch", "apiServerAudiences is %q; this cluster's API server uses %q",
			checker.Config.APIAudiences, actual)
	}
}

// namespace warns about a gateway namespace Pod Security does not hold to
// restricted.
func (checker Checker) namespace(ctx context.Context, report *Report) {
	var namespace struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := checker.API.Get(ctx, checker.path("/api/v1/namespaces/%s", checker.Config.Namespace),
		&namespace); err != nil {
		checker.unreadable(report, "namespace "+checker.Config.Namespace, err)
		return
	}
	if namespace.Metadata.Labels["pod-security.kubernetes.io/enforce"] != "restricted" {
		report.add(Warn, "namespace_not_restricted",
			"namespace %s lacks pod-security.kubernetes.io/enforce=restricted", checker.Config.Namespace)
	}
}

// failedCreates reports controllers in the namespace that could not create
// pods: an admission policy refusing them (a sidecar injector, an image
// rewriter, another controller name) shows here first (review v2 M2).
func (checker Checker) failedCreates(ctx context.Context, report *Report) {
	var events struct {
		Items []struct {
			InvolvedObject struct {
				Kind string `json:"kind"`
				Name string `json:"name"`
			} `json:"involvedObject"`
			Message string `json:"message"`
		} `json:"items"`
	}
	path := checker.path("/api/v1/namespaces/%s/events", checker.Config.Namespace) + "?fieldSelector=" +
		url.QueryEscape("reason=FailedCreate")
	if err := checker.API.Get(ctx, path, &events); err != nil {
		checker.unreadable(report, "events", err)
		return
	}
	seen := map[string]bool{}
	for _, event := range events.Items {
		key := event.InvolvedObject.Kind + "/" + event.InvolvedObject.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		report.add(Warn, "failed_create", "%s could not create a pod: %s", printable(key), printable(event.Message))
	}
}

// Summary is the report in a few lines, for a pod's termination message
// (4 KiB at most).
func (report Report) Summary() string {
	var buffer bytes.Buffer
	failed, warned := 0, 0
	for _, finding := range report.Findings {
		if finding.Level == Fail {
			failed++
		} else {
			warned++
		}
	}
	fmt.Fprintf(&buffer, "%d failed, %d warnings\n", failed, warned)
	for _, finding := range report.Findings {
		line := string(finding.Level) + " " + finding.Code + ": " + finding.Message + "\n"
		if buffer.Len()+len(line) > 4000 {
			buffer.WriteString("…\n")
			break
		}
		buffer.WriteString(line)
	}
	return buffer.String()
}
