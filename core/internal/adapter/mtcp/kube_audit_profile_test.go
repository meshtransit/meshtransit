package mtcp

import (
	"bytes"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
)

// Profile reasons come only from a gateway.kube.v2 session; a sample stays
// only with a profile reason and in form, else the window stays without it
// (§6.10, §7.12, review d4a M2).
func TestDecodeKubeAuditDenialProfiles(t *testing.T) {
	t.Parallel()
	now := time.Now().UnixMilli()
	sample := &mtcpv1.KubeAuditDenialSample{Verb: "delete", Resource: "pods", Namespace: "team-a",
		Scope: bytes.Repeat([]byte{1}, 32)}
	window := func(reason string, sample *mtcpv1.KubeAuditDenialSample) *mtcpv1.KubeAuditDenials {
		return &mtcpv1.KubeAuditDenials{PeerDeviceId: auditPeer, Reason: reason, Count: 2, FirstMs: now - 1000,
			LastMs: now, Sample: sample}
	}
	for name, test := range map[string]struct {
		denials        *mtcpv1.KubeAuditDenials
		profiles       bool
		valid, sampled bool
	}{
		"profile reason with sample": {window("profile_denied", sample), true, true, true},
		"would deny without sample":  {window("profile_would_deny", nil), true, true, false},
		"profile reason from v1":     {window("profile_denied", nil), false, false, false},
		"sample with another reason": {window("forbidden", sample), true, true, false},
		"sample from a v1 session":   {window("forbidden", sample), false, true, false},
		"sample without a verb": {window("profile_denied", &mtcpv1.KubeAuditDenialSample{Scope: sample.Scope}),
			true, true, false},
		"sample with a short scope": {window("profile_denied",
			&mtcpv1.KubeAuditDenialSample{Verb: "get", Scope: []byte{1}}), true, true, false},
	} {
		denials, valid := decodeKubeAuditDenials(test.denials, test.profiles)
		if valid != test.valid || (denials.Sample != nil) != test.sampled {
			t.Errorf("%s: valid = %t, sampled = %t", name, valid, denials.Sample != nil)
		}
	}
}
