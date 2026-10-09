package main

import "testing"

func TestAuthorityStateRequiresExactCurrentProviders(t *testing.T) {
	t.Parallel()
	manifest, err := parseManifest([]byte(validManifestJSON()))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := buildPlanSpec(
		manifest,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		testSubjectKey(t, "source-key-v1", 1),
		testSubjectKey(t, "target-key-v1", 2),
	)
	if err != nil {
		t.Fatal(err)
	}
	state := authorityState{
		deploymentInternalID: 1, deploymentProfile: "production",
		deploymentRecoveryState: "verified", deploymentState: "active",
		actorInternalID: 2, actorKind: "account", actorState: "active",
		source: providerStateFixture(manifest.Source),
		target: providerStateFixture(manifest.Target),
	}
	if !state.matches(spec) {
		t.Fatal("exact authority state rejected")
	}
	state.target.generationVersion++
	if state.matches(spec) {
		t.Fatal("stale target generation version accepted")
	}
}

func TestSubjectsMatchCompleteExactPlan(t *testing.T) {
	t.Parallel()
	manifest, err := parseManifest([]byte(validManifestJSON()))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := buildPlanSpec(
		manifest,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		testSubjectKey(t, "source-key-v1", 1),
		testSubjectKey(t, "target-key-v1", 2),
	)
	if err != nil {
		t.Fatal(err)
	}
	digest := spec.mappings[0].sourceDigest.Bytes()
	rows := []subjectRow{{
		internalID: 1, publicID: testSourceSubjectID,
		principalInternalID: 2, principalID: testPrincipalID,
		algorithm: spec.mappings[0].sourceDigest.Algorithm(), keyID: "source-key-v1",
		digest: digest[:], claimsRevision: 1, version: 1,
	}}
	if !subjectsMatchPlan(rows, spec) {
		t.Fatal("exact complete subject plan rejected")
	}
	rows[0].version++
	if subjectsMatchPlan(rows, spec) {
		t.Fatal("stale subject version accepted")
	}
	rows[0].version--
	rows = append(rows, rows[0])
	if subjectsMatchPlan(rows, spec) {
		t.Fatal("incomplete manifest coverage accepted")
	}
}

func providerStateFixture(reference providerReference) providerState {
	return providerState{
		internalID: 1, issuer: reference.Issuer, protocol: "oidc", authorityKind: "external_oidc",
		currentGeneration: reference.ExpectedGeneration, generation: reference.ExpectedGeneration,
		recoveryState: "verified", state: "active", version: reference.ExpectedProviderVersion,
		trustHash: make([]byte, 32), generationRecoveryMode: "continuous",
		generationState: "current", generationVersion: reference.ExpectedGenerationVersion,
	}
}
