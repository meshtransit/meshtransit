package daemon

import (
	"testing"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dataplane"
)

func TestExitHealthOf(t *testing.T) {
	t.Parallel()
	if health, measured := exitHealthOf(dataplane.ExitNodeStatus{}); !measured || health.Ref != "" {
		t.Fatalf("no pool = %+v, %t", health, measured)
	}
	if _, measured := exitHealthOf(dataplane.ExitNodeStatus{Pool: "p"}); measured {
		t.Fatal("an unmeasured pool was reported")
	}
	health, measured := exitHealthOf(dataplane.ExitNodeStatus{Pool: "p", Health: &dataplane.ExitHealth{
		State: dataplane.SiteHealthFailed, Code: "egress failed", IPv4: true, IPv6: true,
	}})
	if !measured || health.State != controlplane.RouteHealthFailed || health.Code != "unknown" ||
		health.Families != controlplane.ExitFamiliesBoth {
		t.Fatalf("failed pool = %+v", health)
	}
	if health, _ := exitHealthOf(dataplane.ExitNodeStatus{Pool: "p", Health: &dataplane.ExitHealth{
		State: dataplane.SiteHealthOK, Code: "ok", IPv6: true,
	}}); health.Families != controlplane.ExitFamiliesV6 ||
		health.State != controlplane.RouteHealthOK {
		t.Fatalf("v6 pool = %+v", health)
	}
}
