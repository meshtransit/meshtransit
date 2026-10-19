package cli

import (
	"strings"
	"testing"

	"meshtransit.net/client/internal/cli/localapi"
)

func TestFormatSubnetRouteStatusNamesEachSitesRouter(t *testing.T) {
	t.Parallel()
	got := formatSubnetRouteStatus(&localapi.SubnetRouteStatus{
		Requested: 2, Installed: 2, Health: "ok",
		Sites: []localapi.SubnetRouteSite{
			{Site: "prod", Router: "01a15307-257a", RouterName: "router-2-prod", Via: "local_failover"},
			{Site: "uat", Router: "01a15307-484b", Via: "primary"},
			{Site: "lab", Via: "none"},
		},
	})
	for _, want := range []string{
		"2 of 2 installed",
		"Site prod via router-2-prod (chosen here: the primary does not answer)",
		"Site uat via 01a15307-484b",
		"Site lab not served",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("status %q lacks %q", got, want)
		}
	}
}
