package oidcauth

import (
	"reflect"
	"testing"
	"time"
)

func TestCallbackResultReleaseTimeAndOriginalRoute(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"issued", "provider error"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			fixture := newCallbackFixture(t)
			fixture.options.IdleLifetime = 2 * time.Minute
			var err error
			fixture.service, err = NewCallbackService(fixture.options, fixture.deps)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "provider error" {
				fixture.command.params.Kind, fixture.command.params.Code = CallbackProviderErrorReceived, Code{}
			}
			result, err := fixture.service.CompleteBrowser(t.Context(), fixture.command)
			if err != nil || !result.IsLiveAt(fixture.now) || !reflect.DeepEqual(result.Route(), fixture.command.params.Route) {
				t.Fatal("confirmed result lost fresh time or original exact route", err)
			}
			for _, test := range []struct {
				name string
				at   time.Time
			}{
				{name: "zero"},
				{name: "before decision", at: fixture.now.Add(-time.Microsecond)},
				{name: "claim expiry", at: fixture.snapshot.ExpiresAt()},
			} {
				t.Run(test.name, func(t *testing.T) {
					t.Parallel()
					if result.IsLiveAt(test.at) {
						t.Fatal("stale result released")
					}
				})
			}
			if kind == "issued" {
				if !result.Issued().Session().IsActiveAt(result.issued.issued.command.ProviderExpiresAt()) {
					t.Fatal("provider-expiry case also expired Session")
				}
				if result.IsLiveAt(result.Issued().Session().IdleExpiresAt()) ||
					result.IsLiveAt(result.Issued().Session().AbsoluteExpiresAt()) ||
					result.IsLiveAt(result.issued.issued.command.ProviderExpiresAt()) {
					t.Fatal("exclusive Session/provider expiry widened")
				}
			}
			scopes := result.Route().Scopes()
			scopes[0] = "untrusted"
			if reflect.DeepEqual(scopes, result.Route().Scopes()) {
				t.Fatal("route accessor leaked mutable slices")
			}
		})
	}
	if (CallbackResult{}).IsLiveAt(time.Now()) || (CallbackResult{}).Route().IsValid() {
		t.Fatal("zero result released route/evidence")
	}
}
