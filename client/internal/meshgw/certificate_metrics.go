package meshgw

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"meshtransit.net/client/internal/daemon"
)

// writeCertificateMetrics writes a K1 gateway's replica certificate
// metrics (K1a4a a4 §3.4); nothing when it keeps none. Alert on
// meshgw_certificate_not_after_seconds - time() < 10 * 3600 for 15 minutes.
func writeCertificateMetrics(w io.Writer, status *daemon.GatewayCertificateStatus) {
	if status == nil {
		return
	}
	seconds := func(at time.Time) int64 {
		if at.IsZero() {
			return 0
		}
		return at.Unix()
	}
	flag := func(value bool) int {
		if value {
			return 1
		}
		return 0
	}
	// Measured on Core's clock by the manager, never against this host's
	// (a4b2 review L2).
	waiting := int64(status.WaitingFor.Seconds())
	_, _ = fmt.Fprintf(w,
		"# HELP meshgw_certificate_not_after_seconds When the replica certificate expires (Unix seconds); 0: none.\n"+
			"# TYPE meshgw_certificate_not_after_seconds gauge\nmeshgw_certificate_not_after_seconds %d\n"+
			"# HELP meshgw_certificate_renew_at_seconds When Core asked the certificate renewed (Unix seconds).\n"+
			"# TYPE meshgw_certificate_renew_at_seconds gauge\nmeshgw_certificate_renew_at_seconds %d\n"+
			"# HELP meshgw_certificate_map_mismatch Whether the map names CAs other than the certificate's.\n"+
			"# TYPE meshgw_certificate_map_mismatch gauge\nmeshgw_certificate_map_mismatch %d\n"+
			"# HELP meshgw_certificate_request_waiting_seconds How long the waiting request has waited; 0: none.\n"+
			"# TYPE meshgw_certificate_request_waiting_seconds gauge\nmeshgw_certificate_request_waiting_seconds %d\n",
		seconds(status.NotAfter), seconds(status.RenewAt), flag(status.MapMismatch), waiting)
	keys := make([]string, 0, len(status.Requests))
	for key := range status.Requests {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	_, _ = fmt.Fprint(w, "# HELP meshgw_certificate_requests_total Core's answers to certificate requests.\n"+
		"# TYPE meshgw_certificate_requests_total counter\n")
	for _, key := range keys {
		outcome, reason, _ := strings.Cut(key, "/")
		_, _ = fmt.Fprintf(w, "meshgw_certificate_requests_total{outcome=%q,reason=%q} %d\n", outcome, reason,
			status.Requests[key])
	}
}
