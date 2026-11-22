package oidc

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
)

func TestCallbackTelemetryBalancesConcurrentWorkAndBoundsLabels(t *testing.T) {
	t.Parallel()
	telemetry := NewCallbackTelemetry()
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(telemetry); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for _, outcome := range []oidcauth.CallbackOutcome{
		oidcauth.CallbackIssued, oidcauth.CallbackFailed, oidcauth.CallbackRejected, oidcauth.CallbackLimited,
		oidcauth.CallbackUnavailable, oidcauth.CallbackCommitUnknown, oidcauth.CallbackCleanupFailed, 200, 201,
	} {
		workers.Go(func() {
			telemetry.CallbackOpened()
			telemetry.CallbackClosed(outcome, -time.Millisecond)
		})
	}
	workers.Wait()
	families, err := registry.Gather()
	if err != nil || len(families) != 3 {
		t.Fatal("invalid callback application metric families")
	}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			if strings.HasSuffix(family.GetName(), "_active") {
				if metric.GetGauge().GetValue() != 0 || len(metric.GetLabel()) != 0 {
					t.Fatal("callback observation did not drain or exposed input")
				}
				continue
			}
			if len(metric.GetLabel()) != 1 || metric.GetLabel()[0].GetName() != "result" {
				t.Fatal("request/identity data escaped into labels")
			}
			label := metric.GetLabel()[0].GetValue()
			switch label {
			case "issued", "failed", "rejected", "limited", "unavailable", "commit_unknown", "cleanup_failed", "unknown":
			default:
				t.Fatal("unbounded callback result label")
			}
			if strings.HasSuffix(family.GetName(), "_total") && label == "unknown" && metric.GetCounter().GetValue() != 2 {
				t.Fatal("unknown outcomes did not fold into one closed value")
			}
			if metric.GetHistogram() != nil && metric.GetHistogram().GetSampleSum() != 0 {
				t.Fatal("negative duration entered histogram")
			}
		}
	}
}

// TD-SEC-37: refused invitation links count under one closed reason label.
func TestCallbackTelemetryCountsInvitationRefusalsByClosedReason(t *testing.T) {
	t.Parallel()
	telemetry := NewCallbackTelemetry()
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(telemetry); err != nil {
		t.Fatal(err)
	}
	for _, refusal := range []oidcauth.InvitationRefusal{
		oidcauth.InvitationRefusalInvalid, oidcauth.InvitationRefusalNoVerifiedEmail,
		oidcauth.InvitationRefusalEmailMismatch, oidcauth.InvitationRefusalNotPending,
		oidcauth.InvitationRefusalInviterAuthority, oidcauth.InvitationRefusalMemberConflict, 0, 200,
	} {
		telemetry.InvitationRefused(refusal)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"invalid": true, "no_verified_email": true, "email_mismatch": true,
		"not_pending": true, "inviter_authority": true, "member_conflict": true, "unknown": true}
	seen := map[string]float64{}
	for _, family := range families {
		if family.GetName() != "meshtransit_invitation_refused_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			labels := metric.GetLabel()
			if len(labels) != 1 || labels[0].GetName() != "reason" || !allowed[labels[0].GetValue()] {
				t.Fatalf("labels %v", labels)
			}
			seen[labels[0].GetValue()] = metric.GetCounter().GetValue()
		}
	}
	if len(seen) != 7 || seen["unknown"] != 2 || seen["email_mismatch"] != 1 {
		t.Fatalf("refusals %v", seen)
	}
}
