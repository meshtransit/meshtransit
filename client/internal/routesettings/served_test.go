package routesettings

import (
	"net/netip"
	"slices"
	"testing"
)

func TestAdmitServedIntersectsWithWhatTheHostOffers(t *testing.T) {
	t.Parallel()
	prefix := netip.MustParsePrefix
	settings := Settings{RouterMode: true, AdvertiseRoutes: []netip.Prefix{
		prefix("10.35.0.0/17"), prefix("10.40.1.0/24"), prefix("10.40.2.0/24"), prefix("10.40.2.128/25"),
	}}
	served := []ServedEntry{
		{SiteRef: "prod", Prefix: prefix("10.35.0.0/24"), Masquerade: true}, // inside an offer: served as is
		{SiteRef: "lab", Prefix: prefix("10.40.0.0/16")},                    // offers inside it: the offers
		{SiteRef: "uat", Prefix: prefix("10.35.128.0/17")},                  // not offered
		{SiteRef: "bad", Prefix: prefix("100.64.0.0/24")},                   // overlay frame
	}
	admitted, refused := AdmitServed(settings, served)
	want := []ServedEntry{
		{SiteRef: "prod", Prefix: prefix("10.35.0.0/24"), Masquerade: true},
		{SiteRef: "lab", Prefix: prefix("10.40.1.0/24")},
		{SiteRef: "lab", Prefix: prefix("10.40.2.0/24")},
	}
	if !slices.Equal(admitted, want) {
		t.Fatalf("admitted = %v, want %v", admitted, want)
	}
	reasons := map[netip.Prefix]string{}
	for _, refusal := range refused {
		reasons[refusal.Prefix] = refusal.Reason
	}
	if len(refused) != 2 || reasons[prefix("10.35.128.0/17")] != ReasonNotAdvertised ||
		reasons[prefix("100.64.0.0/24")] != ReasonReserved {
		t.Fatalf("refused = %v", refused)
	}
	settings.RouterMode = false
	if admitted, refused := AdmitServed(settings, served); len(admitted) != 0 || len(refused) != len(served) ||
		refused[0].Reason != ReasonRouterOff {
		t.Fatalf("router mode off: admitted %v, refused %v", admitted, refused)
	}
}

func TestAdmitServedKeepsNoOverlapFromAMalformedRequest(t *testing.T) {
	t.Parallel()
	prefix := netip.MustParsePrefix
	settings := Settings{RouterMode: true, AdvertiseRoutes: []netip.Prefix{prefix("10.0.0.0/8")}}
	admitted, _ := AdmitServed(settings, []ServedEntry{
		{SiteRef: "a", Prefix: prefix("10.0.0.0/8")},
		{SiteRef: "b", Prefix: prefix("10.1.0.0/16")},
		{SiteRef: "c", Prefix: prefix("10.2.0.0/16")},
	})
	if len(admitted) != 1 || admitted[0].Prefix != prefix("10.0.0.0/8") {
		t.Fatalf("admitted = %v", admitted)
	}
}
