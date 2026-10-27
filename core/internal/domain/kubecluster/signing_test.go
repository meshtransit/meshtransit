package kubecluster_test

import (
	"testing"

	"meshtransit.net/core/internal/domain/kubecluster"
)

func TestRequestSigningState(t *testing.T) {
	t.Parallel()
	thumbprint := func(b byte) [32]byte { return [32]byte{b} }
	trust := &kubecluster.SigningTrust{Issuer: "https://kubernetes.default.svc.cluster.local",
		KeyThumbprints: [][32]byte{thumbprint(1), thumbprint(2)}, Namespace: "mt-kube-k1",
		ServiceAccount: "meshgw", StatefulSet: "meshgw", Version: 1, Source: kubecluster.TrustFromReplicaApproval}
	request := kubecluster.RequestSigning{CodeVersion: 2, Issuer: trust.Issuer, Namespace: "mt-kube-k1",
		ServiceAccount: "meshgw", StatefulSet: "meshgw", PodName: "meshgw-0", JoinKeyThumbprint: thumbprint(2)}
	differ := func(change func(*kubecluster.RequestSigning)) kubecluster.RequestSigning {
		changed := request
		change(&changed)
		return changed
	}
	for name, test := range map[string]struct {
		trust   *kubecluster.SigningTrust
		request kubecluster.RequestSigning
		want    kubecluster.RequestTrustState
	}{
		"first approval sets the trust": {nil, request, kubecluster.RequestSetsTrust},
		"same trust":                    {trust, request, kubecluster.RequestMatchesTrust},
		"other issuer": {trust, differ(func(r *kubecluster.RequestSigning) {
			r.Issuer = "https://other.example"
		}), kubecluster.RequestDiffersFromTrust},
		"other namespace": {trust, differ(func(r *kubecluster.RequestSigning) { r.Namespace = "other" }),
			kubecluster.RequestDiffersFromTrust},
		"other service account": {trust, differ(func(r *kubecluster.RequestSigning) { r.ServiceAccount = "x" }),
			kubecluster.RequestDiffersFromTrust},
		"other statefulset": {trust, differ(func(r *kubecluster.RequestSigning) { r.StatefulSet = "x" }),
			kubecluster.RequestDiffersFromTrust},
		"token signed by a key the trust lacks": {trust, differ(func(r *kubecluster.RequestSigning) {
			r.JoinKeyThumbprint = thumbprint(3)
		}), kubecluster.RequestDiffersFromTrust},
		"opened without signing material": {trust, kubecluster.RequestSigning{CodeVersion: 1},
			kubecluster.RequestMustJoinAgain},
		"without signing material and no trust": {nil, kubecluster.RequestSigning{CodeVersion: 1},
			kubecluster.RequestMustJoinAgain},
	} {
		if got := test.request.State(test.trust); got != test.want {
			t.Errorf("%s: State() = %q, want %q", name, got, test.want)
		}
	}
}

// A pod an active replica already holds cannot be approved, whatever its
// signing keys: approving checks the trust first, then the pod.
func TestSigningStateOfHeldPod(t *testing.T) {
	t.Parallel()
	trust := &kubecluster.SigningTrust{Issuer: "https://kubernetes.default.svc.cluster.local",
		KeyThumbprints: [][32]byte{{1}}, Namespace: "mt-kube-k1", ServiceAccount: "meshgw", StatefulSet: "meshgw",
		Version: 1, Source: kubecluster.TrustFromReplicaApproval}
	request := kubecluster.RequestSigning{CodeVersion: 2, Issuer: trust.Issuer, Namespace: "mt-kube-k1",
		ServiceAccount: "meshgw", StatefulSet: "meshgw", PodName: "meshgw-0", JoinKeyThumbprint: [32]byte{1}}
	held := kubecluster.Signing{Trust: trust, Replicas: []kubecluster.ReplicaSigning{{PodName: "meshgw-0"}}}
	if got := held.StateOf(request); got != kubecluster.RequestPodHeld {
		t.Fatalf("StateOf(held pod) = %q", got)
	}
	free := kubecluster.Signing{Trust: trust, Replicas: []kubecluster.ReplicaSigning{{PodName: "meshgw-1"}}}
	if got := free.StateOf(request); got != kubecluster.RequestMatchesTrust {
		t.Fatalf("StateOf(free pod) = %q", got)
	}
	// The trust is checked first: keys that differ stay refused for that.
	differs := request
	differs.Namespace = "other"
	if got := held.StateOf(differs); got != kubecluster.RequestDiffersFromTrust {
		t.Fatalf("StateOf(other namespace) = %q", got)
	}
	// Without a trust the pod is still checked.
	if got := (kubecluster.Signing{Replicas: held.Replicas}).StateOf(request); got != kubecluster.RequestPodHeld {
		t.Fatalf("StateOf(held pod, no trust) = %q", got)
	}
}
