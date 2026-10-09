package main

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

func TestRenewalFixtureValidation(t *testing.T) {
	t.Parallel()
	evaluatedAt := time.Date(2026, time.September, 16, 1, 0, 0, 0, time.UTC)
	fixture := validRenewalFixture(t, evaluatedAt)
	if !fixture.isValid(validSeedScope(), evaluatedAt) {
		t.Fatal("exact expired qualification fixture was rejected")
	}

	tests := []struct {
		name   string
		mutate func(*renewalFixture)
	}{
		{
			name: "membership still live",
			mutate: func(value *renewalFixture) {
				value.membershipExpiresAt = evaluatedAt.Add(time.Second)
			},
		},
		{
			name: "binding generation mismatch",
			mutate: func(value *renewalFixture) {
				value.bindingAuthorityGeneration++
			},
		},
		{
			name: "wrong principal account",
			mutate: func(value *renewalFixture) {
				value.accountPrincipalInternalID++
			},
		},
		{
			name: "invalid subject public ID",
			mutate: func(value *renewalFixture) {
				value.subjectPublicID = publicid.ID{}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := fixture
			test.mutate(&candidate)
			if candidate.isValid(validSeedScope(), evaluatedAt) {
				t.Fatal("invalid renewal fixture was accepted")
			}
		})
	}
}

func TestRenewalFixtureAcceptsExpiryBoundaryAndRejectsUnsafeCounters(t *testing.T) {
	t.Parallel()
	evaluatedAt := time.Date(2026, time.September, 16, 1, 0, 0, 0, time.UTC)
	fixture := validRenewalFixture(t, evaluatedAt)
	fixture.membershipExpiresAt = evaluatedAt
	fixture.bindingExpiresAt = evaluatedAt
	if !fixture.isValid(validSeedScope(), evaluatedAt) {
		t.Fatal("fixture expiring at transaction time was rejected")
	}

	tests := []struct {
		name   string
		mutate func(*renewalFixture)
	}{
		{
			name: "membership counter overflow",
			mutate: func(value *renewalFixture) {
				value.membershipVersion = math.MaxInt64
				value.membershipAuthorityGeneration = math.MaxInt64
			},
		},
		{
			name: "binding counter overflow",
			mutate: func(value *renewalFixture) {
				value.bindingVersion = math.MaxInt64
				value.bindingAuthorityGeneration = math.MaxInt64
			},
		},
		{
			name: "different expiry",
			mutate: func(value *renewalFixture) {
				value.bindingExpiresAt = value.bindingExpiresAt.Add(-time.Second)
			},
		},
		{
			name: "future authentication",
			mutate: func(value *renewalFixture) {
				value.authenticationTime = evaluatedAt.Add(time.Second)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := fixture
			test.mutate(&candidate)
			if candidate.isValid(validSeedScope(), evaluatedAt) {
				t.Fatal("unsafe renewal fixture was accepted")
			}
		})
	}
}

func TestRenewalSQLCarriesFailClosedContracts(t *testing.T) {
	t.Parallel()
	requiredFixtureFragments := []string{
		"qualification.management_session.seeded",
		"qualification.management_session.renewed",
		"mutation.operation = 'update'",
		"session.absolute_expires_at > pg_catalog.transaction_timestamp()",
		"session.authentication_time IS DISTINCT FROM seeded_session.authentication_time",
		"FOR UPDATE OF account, provider, generation, client, subject",
	}
	for _, fragment := range requiredFixtureFragments {
		if !strings.Contains(loadRenewalFixtureSQL, fragment) {
			t.Fatalf("loadRenewalFixtureSQL lacks %q", fragment)
		}
	}
	if !strings.Contains(insertRenewalSessionSQL, "$11::TIMESTAMPTZ") {
		t.Fatal("renewal session does not preserve original authentication_time")
	}
	for _, query := range []string{renewMembershipSQL, renewRoleBindingSQL} {
		for _, fragment := range []string{
			"authority_generation = authority_generation + 1",
			"version = version + 1",
			"expires_at <= pg_catalog.transaction_timestamp()",
		} {
			if !strings.Contains(query, fragment) {
				t.Fatalf("renewal CAS query lacks %q", fragment)
			}
		}
	}
}

func validRenewalFixture(t *testing.T, evaluatedAt time.Time) renewalFixture {
	t.Helper()
	parseID := func(value string) publicid.ID {
		id, err := publicid.Parse(value)
		if err != nil {
			t.Fatalf("parse renewal fixture public ID: %v", err)
		}
		return id
	}
	return renewalFixture{
		accountInternalID:                 301,
		accountPrincipalInternalID:        11,
		accountSessionGeneration:          1,
		providerInternalID:                302,
		providerGeneration:                1,
		providerClientInternalID:          303,
		subjectInternalID:                 304,
		subjectPublicID:                   parseID("01995d00-0000-7000-8000-000000000304"),
		membershipInternalID:              305,
		membershipPublicID:                parseID("01995d00-0000-7000-8000-000000000305"),
		membershipVersion:                 2,
		membershipAuthorityGeneration:     2,
		membershipExpiresAt:               evaluatedAt.Add(-time.Minute),
		roleDefinitionInternalID:          306,
		roleDefinitionPublicID:            parseID("01995d00-0000-7000-8000-000000000306"),
		roleDefinitionVersion:             1,
		roleDefinitionAuthorityGeneration: 1,
		rolePermissionInternalID:          307,
		bindingInternalID:                 308,
		bindingPublicID:                   parseID("01995d00-0000-7000-8000-000000000308"),
		bindingVersion:                    2,
		bindingAuthorityGeneration:        2,
		bindingExpiresAt:                  evaluatedAt.Add(-time.Minute),
		authenticationTime:                evaluatedAt.Add(-2 * time.Minute),
	}
}
