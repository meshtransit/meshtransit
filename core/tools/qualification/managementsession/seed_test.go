package main

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"meshtransit.net/core/internal/domain/publicid"
)

func TestSeedScopeAndCountsValidation(t *testing.T) {
	t.Parallel()
	scope := validSeedScope()
	if !scope.isValid() {
		t.Fatal("valid seed scope was rejected")
	}
	scope.deploymentProfile = "saas"
	if scope.isValid() {
		t.Fatal("non-self-hosted seed scope was accepted")
	}
	if !(seedAuthorityCounts{}).isPristine() {
		t.Fatal("empty authority counts are not pristine")
	}
	if (seedAuthorityCounts{session: 1}).isPristine() {
		t.Fatal("existing Account Session was treated as pristine")
	}
	renewable := seedAuthorityCounts{
		account: 1, provider: 1, providerGeneration: 1, providerClient: 1,
		subject: 1, session: 1, membership: 1, roleDefinition: 1,
		rolePermission: 1, roleBinding: 1,
	}
	if !renewable.isRenewable() {
		t.Fatal("exact qualification authority was not renewable")
	}
	renewable.session = maximumFixtureSessions + 1
	if renewable.isRenewable() {
		t.Fatal("unbounded qualification session history was renewable")
	}
	renewable.session = 1
	renewable.roleBinding = 2
	if renewable.isRenewable() {
		t.Fatal("unexpected additional RoleBinding was renewable")
	}
}

func TestNewSeedIDsRequiresDistinctUUIDv7Values(t *testing.T) {
	t.Parallel()
	index := 0
	ids, err := newSeedIDs(func() (publicid.ID, error) {
		index++
		return publicid.Parse(fmt.Sprintf("01995d00-0000-7000-8000-%012d", index))
	})
	if err != nil {
		t.Fatalf("newSeedIDs() error = %v", err)
	}
	if ids.change == ids.event || ids.session == ids.roleBinding || !ids.roleBinding.IsValid() {
		t.Fatalf("newSeedIDs() returned invalid or duplicate values: %#v", ids)
	}
	one, err := publicid.Parse("01995d00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("parse duplicate ID: %v", err)
	}
	if _, err := newSeedIDs(func() (publicid.ID, error) { return one, nil }); !errors.Is(err, errInvalidInput) {
		t.Fatalf("newSeedIDs() duplicate error = %v, want invalid input", err)
	}
}

func TestNewSeedIdentityMaterialIsBoundAndRejectsZeroEntropy(t *testing.T) {
	t.Parallel()
	entropy := bytes.Repeat([]byte{0x51}, 32)
	first, err := newSeedIdentityMaterial(bytes.NewReader(entropy))
	if err != nil {
		t.Fatalf("newSeedIdentityMaterial() error = %v", err)
	}
	second, err := newSeedIdentityMaterial(bytes.NewReader(entropy))
	if err != nil {
		t.Fatalf("newSeedIdentityMaterial() second error = %v", err)
	}
	if !bytes.Equal(first.issuerDigest, second.issuerDigest) ||
		!bytes.Equal(first.subjectDigest, second.subjectDigest) ||
		bytes.Equal(first.issuerDigest, first.subjectDigest) ||
		first.trustHash != second.trustHash {
		t.Fatal("synthetic identity material is not deterministic and purpose-bound")
	}
	if _, err := newSeedIdentityMaterial(bytes.NewReader(make([]byte, 32))); !errors.Is(err, errInvalidInput) {
		t.Fatalf("zero entropy error = %v, want invalid input", err)
	}
}

func validSeedScope() seedScope {
	return seedScope{
		deploymentInternalID:         1,
		deploymentProfile:            "self_hosted",
		recoveryEpoch:                1,
		deploymentState:              "active",
		deploymentRecoveryState:      "verified",
		principalInternalID:          11,
		principalKind:                "account",
		principalState:               "active",
		principalAuthorityGeneration: 1,
		workspaceInternalID:          101,
		workspaceState:               "active",
		workspaceAuthorityGeneration: 1,
		networkInternalID:            201,
		networkState:                 "active",
		networkAuthorityGeneration:   1,
		networkRevision:              1,
	}
}
