package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/adapter/kubeapi"
)

const (
	newImage = "meshtransit/mesh-core@sha256:new"
	oldImage = "meshtransit/mesh-core@sha256:old"
)

func coreContainerOf(role, image string) kubeapi.Container {
	container := kubeapi.Container{Name: role, Image: image}
	container.Env = append(container.Env, struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}{Name: coreRoleVariable, Value: role})
	return container
}

func rolloutPod(name, component, image, phase string, deleting bool, extra ...kubeapi.Container) kubeapi.Pod {
	var pod kubeapi.Pod
	pod.Metadata.Name = name
	pod.Metadata.Labels = map[string]string{"app.kubernetes.io/component": component}
	if deleting {
		stamp := "2026-11-20T00:00:00Z"
		pod.Metadata.DeletionTimestamp = &stamp
	}
	pod.Spec.Containers = append([]kubeapi.Container{coreContainerOf(component, image)}, extra...)
	pod.Status.Phase = phase
	return pod
}

func TestRolloutBlockingPods(t *testing.T) {
	t.Parallel()
	images := map[string]string{"api": newImage, "worker": newImage}
	sidecar := kubeapi.Container{Name: "proxy", Image: "mesh/proxy:1"}
	identity := rolloutPod("identity-1", "identity", "id@sha256:x", "Running", false)
	identity.Spec.Containers[0].Env[0].Value = "identity"
	for _, test := range []struct {
		name    string
		pod     kubeapi.Pod
		blocked bool
	}{
		{"new image", rolloutPod("api-new", "api", newImage, "Running", false), false},
		{"new image with a sidecar", rolloutPod("api-side", "api", newImage, "Running", false, sidecar), false},
		{"rewritten registry, same digest", rolloutPod("api-mirror", "api", "mirror.example/core@sha256:new", "Running", false), false},
		{"old image", rolloutPod("api-old", "api", oldImage, "Running", false), true},
		{"draining", rolloutPod("api-drain", "api", newImage, "Running", true), true},
		{"pending new", rolloutPod("worker-pending", "worker", newImage, "Pending", false), false},
		{"finished old", rolloutPod("worker-done", "worker", oldImage, "Succeeded", false), false},
		{"removed component", rolloutPod("control-old", "control", newImage, "Running", false), true},
		{"identity pod", identity, false},
	} {
		blocking, _ := rolloutBlockingPods([]kubeapi.Pod{test.pod}, images)
		if (len(blocking) != 0) != test.blocked {
			t.Errorf("%s: blocking = %v", test.name, blocking)
		}
	}
}

func rolloutReplicaSet(name, component, image string, desired, actual int32) kubeapi.ReplicaSet {
	var replicaSet kubeapi.ReplicaSet
	replicaSet.Metadata.Name = name
	replicaSet.Spec.Replicas = &desired
	replicaSet.Spec.Template.Metadata.Labels = map[string]string{"app.kubernetes.io/component": component}
	replicaSet.Spec.Template.Spec.Containers = []kubeapi.Container{coreContainerOf(component, image)}
	replicaSet.Status.Replicas = actual
	return replicaSet
}

func TestRolloutBlockingReplicaSets(t *testing.T) {
	t.Parallel()
	images := map[string]string{"api": newImage}
	for _, test := range []struct {
		name       string
		replicaSet kubeapi.ReplicaSet
		blocked    bool
	}{
		{"current", rolloutReplicaSet("api-new", "api", newImage, 2, 2), false},
		{"old at zero", rolloutReplicaSet("api-old", "api", oldImage, 0, 0), false},
		{"old scaling down", rolloutReplicaSet("api-old", "api", oldImage, 0, 1), true},
		{"old still desired", rolloutReplicaSet("api-old", "api", oldImage, 1, 0), true},
		{"removed component", rolloutReplicaSet("control-old", "control", newImage, 1, 1), true},
	} {
		if blocking := rolloutBlockingReplicaSets([]kubeapi.ReplicaSet{test.replicaSet}, images); (len(blocking) != 0) != test.blocked {
			t.Errorf("%s: blocking = %v", test.name, blocking)
		}
	}
}

func rolloutLookup(environment map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) { value, ok := environment[name]; return value, ok }
}

func validRolloutEnvironment() map[string]string {
	return map[string]string{envRolloutInstance: "meshtransit-core", envRolloutChart: "meshtransit-core",
		envRolloutImages: "worker=core@sha256:a, api=core@sha256:a", envRolloutTimeout: "2m"}
}

func TestLoadRolloutSettings(t *testing.T) {
	t.Parallel()
	settings, err := loadRolloutSettings(rolloutLookup(validRolloutEnvironment()), rolloutPoll)
	if err != nil || settings.timeout != 2*time.Minute ||
		settings.selector() != "app.kubernetes.io/instance=meshtransit-core,app.kubernetes.io/name=meshtransit-core" {
		t.Fatalf("settings = %+v, %v", settings, err)
	}
	for _, test := range []struct {
		name, variable, value string
	}{
		{"no instance", envRolloutInstance, ""},
		{"bad chart", envRolloutChart, "Mesh_Core"},
		{"bad pair", envRolloutImages, "api"},
		{"duplicate", envRolloutImages, "api=a,api=b"},
		{"injection", envRolloutImages, "api=a,x) in (y=b"},
		{"long timeout", envRolloutTimeout, "2h"},
		{"short timeout", envRolloutTimeout, "1s"},
	} {
		environment := validRolloutEnvironment()
		environment[test.variable] = test.value
		_, err := loadRolloutSettings(rolloutLookup(environment), rolloutPoll)
		if !errors.Is(err, errRolloutSetting) || !strings.Contains(err.Error(), test.variable) {
			t.Errorf("%s: %v", test.name, err)
		}
	}
}

// steppingLister answers each list in turn; an error answer is returned
// once.
type steppingLister struct {
	pods     [][]kubeapi.Pod
	failures []error
}

func (lister *steppingLister) ListPods(context.Context, string) ([]kubeapi.Pod, error) {
	if len(lister.failures) > 0 {
		failure := lister.failures[0]
		lister.failures = lister.failures[1:]
		return nil, failure
	}
	answer := lister.pods[0]
	if len(lister.pods) > 1 {
		lister.pods = lister.pods[1:]
	}
	return answer, nil
}

func (*steppingLister) ListReplicaSets(context.Context, string) ([]kubeapi.ReplicaSet, error) {
	return nil, nil
}

func TestRunInstallWaitRollout(t *testing.T) {
	t.Parallel()
	const poll = time.Millisecond
	environment := map[string]string{envRolloutInstance: "rel", envRolloutChart: "meshtransit-core",
		envRolloutImages: "api=" + newImage, envRolloutTimeout: "200ms"}
	old := rolloutPod("api-old", "api", oldImage, "Running", false)
	fresh := rolloutPod("api-new", "api", newImage, "Running", false)
	for _, test := range []struct {
		name   string
		lister *steppingLister
		code   int
		text   string
	}{
		{"rolls out after a passing error", &steppingLister{pods: [][]kubeapi.Pod{{old, fresh}, {fresh}},
			failures: []error{errors.New("HTTP 503")}}, 0, `"pods":1`},
		{"denied fails at once", &steppingLister{failures: []error{kubeapi.ErrDenied}}, 1, "install_kubernetes_denied"},
		{"stuck times out", &steppingLister{pods: [][]kubeapi.Pod{{old}}}, 1, "rollout_timeout"},
	} {
		var output, errorOutput bytes.Buffer
		code := runInstallWaitRollout(context.Background(), rolloutLookup(environment), &output, &errorOutput,
			func() (rolloutLister, error) { return test.lister, nil }, poll)
		if code != test.code || !strings.Contains(output.String()+errorOutput.String(), test.text) {
			t.Errorf("%s: %d %s %s", test.name, code, output.String(), errorOutput.String())
		}
	}
}
