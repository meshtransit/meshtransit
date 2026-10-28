package meshgw

import (
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/daemon"
)

func TestCertificateMetrics(t *testing.T) {
	t.Parallel()
	var none strings.Builder
	writeCertificateMetrics(&none, nil)
	if none.Len() != 0 {
		t.Fatal("a gateway without certificates wrote metrics")
	}
	now := time.Unix(1_800_000_000, 0)
	var out strings.Builder
	writeCertificateMetrics(&out, &daemon.GatewayCertificateStatus{
		HasCertificate: true, NotAfter: now.Add(24 * time.Hour), RenewAt: now.Add(8 * time.Hour), MapMismatch: true,
		WaitingSince: now.Add(-30 * time.Second), WaitingFor: 30 * time.Second,
		Requests: map[string]uint64{"issued/": 2, "refused/token_used": 1},
	})
	for _, want := range []string{
		"meshgw_certificate_not_after_seconds 1800086400\n", "meshgw_certificate_renew_at_seconds 1800028800\n",
		"meshgw_certificate_map_mismatch 1\n", "meshgw_certificate_request_waiting_seconds 30\n",
		`meshgw_certificate_requests_total{outcome="issued",reason=""} 2`,
		`meshgw_certificate_requests_total{outcome="refused",reason="token_used"} 1`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("metrics lack %q:\n%s", want, out.String())
		}
	}
}
