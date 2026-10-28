package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func kubernetesCAWorkerValues(changes map[string]string) map[string]string {
	values := map[string]string{
		envRole: "worker", envKubernetesCAWorkerEnabled: "true",
		envKubernetesCAWorkerDeployment: "01890f00-0000-7000-8000-000000000001",
		envKubernetesCAWrapKeyFile:      "/run/secrets/kube-ca/wrap-key",
		envDNSSuffix:                    "mesh.internal",
	}
	for key, value := range changes {
		values[key] = value
	}
	return validProcessValues(values)
}

func TestKubernetesCAWorkerConfigurationIsExplicitAndBounded(t *testing.T) {
	t.Parallel()
	defaults, err := Load(mapLookup(validProcessValues(nil)))
	if err != nil || defaults.KubernetesCAWorker != nil {
		t.Fatal("Kubernetes CA worker enabled by default", err)
	}
	got, err := Load(mapLookup(kubernetesCAWorkerValues(map[string]string{
		envKubernetesCAPreviousKeyFiles: "/run/secrets/kube-ca/old-1,/run/secrets/kube-ca/old-2",
	})))
	if err != nil || got.KubernetesCAWorker == nil {
		t.Fatal("explicit Kubernetes CA worker rejected", err)
	}
	worker := got.KubernetesCAWorker
	if worker.BatchSize != 16 || worker.PollInterval != 30*time.Second || worker.OperationTimeout != 20*time.Second ||
		worker.Custody != KubernetesCACustodyFile || len(worker.PreviousWrapKeyFiles) != 2 {
		t.Fatalf("unexpected defaults %+v", *worker)
	}
	formatted := fmt.Sprintf("%v %#v %s", worker, worker, worker.LogValue())
	if strings.Contains(formatted, worker.DeploymentID.String()) || strings.Contains(formatted, "wrap-key") {
		t.Fatal("assignment or key path exposed by formatting")
	}
}

func TestKubernetesCAWorkerRejectsInvalidAssignmentAndBounds(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, key, value string }{
		{"missing deployment", envKubernetesCAWorkerDeployment, ""},
		{"api role", envRole, "api"},
		{"ambiguous flag", envKubernetesCAWorkerEnabled, "yes"},
		{"excess batch", envKubernetesCAWorkerBatch, "65"},
		{"short poll", envKubernetesCAWorkerPoll, "500ms"},
		{"long timeout", envKubernetesCAWorkerTimeout, "61s"},
		{"KMS before it is wired", envKubernetesCACustody, "kms"},
		{"no wrap key", envKubernetesCAWrapKeyFile, ""},
		{"relative wrap key", envKubernetesCAWrapKeyFile, "wrap-key"},
		{"empty previous keys", envKubernetesCAPreviousKeyFiles, ""},
		{"relative previous key", envKubernetesCAPreviousKeyFiles, "/run/a,old"},
		{"nine previous keys", envKubernetesCAPreviousKeyFiles, strings.Repeat("/run/k,", 8) + "/run/k"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Load(mapLookup(kubernetesCAWorkerValues(map[string]string{test.key: test.value}))); !errors.Is(err,
				ErrInvalid) {
				t.Fatal("unsafe setting accepted", err)
			}
		})
	}
	missing := kubernetesCAWorkerValues(nil)
	delete(missing, envDNSSuffix)
	if _, err := Load(mapLookup(missing)); !errors.Is(err, ErrInvalid) {
		t.Fatal("a defaulted DNS suffix accepted", err)
	}
	values := validProcessValues(map[string]string{envKubernetesCAWrapKeyFile: "/run/secrets/kube-ca/wrap-key"})
	if _, err := Load(mapLookup(values)); !errors.Is(err, ErrInvalid) {
		t.Fatal("setting without the enabled flag accepted", err)
	}
}
