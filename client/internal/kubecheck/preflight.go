package kubecheck

import (
	"context"
	"encoding/json"
	"slices"
)

// PreflightConfig is what the preflight is told (K1c §8): the namespaces
// whose pods may run on any node, and the schedulers trusted to bind.
type PreflightConfig struct {
	ExemptNamespaces      []string `json:"exemptNamespaces"`
	BindingEnforced       bool     `json:"bindingEnforced"`
	TrustedSchedulerNames []string `json:"trustedSchedulerNames"`
}

type toleration struct {
	Key      string `json:"key"`
	Operator string `json:"operator"`
}

type podSpec struct {
	NodeName      string       `json:"nodeName"`
	SchedulerName string       `json:"schedulerName"`
	Tolerations   []toleration `json:"tolerations"`
}

type owner struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// workload is any object the preflight lists: a controller with a pod
// template where the controllers keep it, or a pod.
type workload struct {
	Metadata struct {
		Name            string  `json:"name"`
		Namespace       string  `json:"namespace"`
		OwnerReferences []owner `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		podSpec
		Template struct {
			Spec podSpec `json:"spec"`
		} `json:"template"`
		JobTemplate struct {
			Spec struct {
				Template struct {
					Spec podSpec `json:"spec"`
				} `json:"template"`
			} `json:"spec"`
		} `json:"jobTemplate"`
	} `json:"spec"`
	Status struct {
		Phase      string      `json:"phase"`
		Conditions []condition `json:"conditions"`
	} `json:"status"`
}

type condition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

// finished reports a Job or pod that has run to its end: never created
// again, so nothing enforcement could refuse (review c2b L2).
func (object workload) finished(kind string) bool {
	switch kind {
	case "Pod":
		return object.Status.Phase == "Succeeded" || object.Status.Phase == "Failed"
	case "Job":
		return slices.ContainsFunc(object.Status.Conditions, func(each condition) bool {
			return (each.Type == "Complete" || each.Type == "Failed") && each.Status == "True"
		})
	}
	return false
}

// listed are the kinds the preflight reads, and the owners of each whose
// template it has already seen: an item owned by another kind (Argo
// Rollouts, KEDA, Tekton) is checked itself (review c2b H3).
var listed = []struct {
	kind, path string
	seenOwners []string
}{
	{"DaemonSet", "/apis/apps/v1/daemonsets", nil},
	{"Deployment", "/apis/apps/v1/deployments", nil},
	{"StatefulSet", "/apis/apps/v1/statefulsets", nil},
	{"ReplicaSet", "/apis/apps/v1/replicasets", []string{"Deployment"}},
	{"ReplicationController", "/api/v1/replicationcontrollers", nil},
	{"Job", "/apis/batch/v1/jobs", []string{"CronJob"}},
	{"CronJob", "/apis/batch/v1/cronjobs", nil},
	{"Pod", "/api/v1/pods", []string{"ReplicaSet", "StatefulSet", "DaemonSet", "Job", "ReplicationController", "Node"}},
}

// Preflight lists what the broad placement and the binding policies would
// deny once enforced: pod templates and pods that tolerate every taint or
// name a node outside placement's exempt namespaces, and, with binding
// enforced, those another scheduler binds outside binding's. Each fails
// the preflight: enforcing would stop it (review v1 C1). A custom
// controller with no pod at this moment cannot be seen.
func (checker Checker) Preflight(ctx context.Context) Report {
	var report Report
	// The same sets the chart renders into each policy (review c2b M5).
	placementExempt := append([]string{checker.Config.Namespace}, checker.Config.Preflight.ExemptNamespaces...)
	bindingExempt := checker.Config.Preflight.ExemptNamespaces
	reported := map[string]bool{}
	add := func(code, where, format string, args ...any) {
		if reported[code+" "+where] {
			return
		}
		reported[code+" "+where] = true
		report.add(Fail, code, format, args...)
	}
	for _, list := range listed {
		err := listAll(ctx, checker.API, list.path, func(raw json.RawMessage) error {
			var object workload
			if err := json.Unmarshal(raw, &object); err != nil {
				return err
			}
			meta := object.Metadata
			if slices.ContainsFunc(meta.OwnerReferences, func(each owner) bool {
				return slices.Contains(list.seenOwners, each.Kind)
			}) || object.finished(list.kind) {
				return nil
			}
			where := printable(list.kind + " " + meta.Namespace + "/" + meta.Name)
			// A custom controller's items report once, under it.
			for _, each := range meta.OwnerReferences {
				where = printable(list.kind + "s of " + each.Kind + " " + meta.Namespace + "/" + each.Name)
			}
			spec := object.Spec.Template.Spec
			switch list.kind {
			case "CronJob":
				spec = object.Spec.JobTemplate.Spec.Template.Spec
			case "Pod":
				// A bound pod's node is its scheduler's choice, not its ask.
				spec, spec.NodeName = object.Spec.podSpec, ""
			}
			if !slices.Contains(placementExempt, meta.Namespace) {
				if slices.ContainsFunc(spec.Tolerations, func(each toleration) bool {
					return each.Key == "" && each.Operator == "Exists"
				}) {
					add("tolerates_every_taint", where, "%s tolerates every taint: add its namespace to "+
						"nodeLevelNamespaces or change it before enforcing placement", where)
				}
				if spec.NodeName != "" {
					add("names_a_node", where, "%s names node %s: enforcing placement would refuse it", where,
						printable(spec.NodeName))
				}
			}
			if checker.Config.Preflight.BindingEnforced && !slices.Contains(bindingExempt, meta.Namespace) &&
				spec.SchedulerName != "" && spec.SchedulerName != "default-scheduler" &&
				!slices.Contains(checker.Config.Preflight.TrustedSchedulerNames, spec.SchedulerName) {
				add("other_scheduler", where, "%s uses scheduler %q: trust its binder before enforcing binding",
					where, printable(spec.SchedulerName))
			}
			return nil
		})
		if err != nil {
			report.add(Fail, "preflight_unreadable", "%s: %v", list.kind, err)
		}
	}
	return report
}
