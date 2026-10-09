package publication_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/policy"
	publication "github.com/meshtransit/meshtransit/core/internal/domain/policy/publication"
	"github.com/meshtransit/meshtransit/core/internal/domain/resource"
)

func TestCandidateHashIsDeterministicAndRevisionIndependent(t *testing.T) {
	t.Parallel()

	firstRule := publicationRuleFixture(t, "000000000801", "000000000701", "000000000702", 443)
	secondRule := publicationRuleFixture(t, "000000000802", "000000000702", "000000000703", 53)
	first := publicationCandidateFixture(t, 2, []policy.Rule{secondRule, firstRule})
	second := publicationCandidateFixture(t, 9, []policy.Rule{firstRule, secondRule})

	if first.SemanticHash() != second.SemanticHash() {
		t.Fatalf(
			"semantic hashes differ for equal rules: %x != %x",
			first.SemanticHash().Bytes(),
			second.SemanticHash().Bytes(),
		)
	}
	firstHash := first.SemanticHash().Bytes()
	if encoded := hex.EncodeToString(firstHash[:]); encoded != "af10c4cb27ca1a47360763896f1812657802e6e63dd5c33cae38f56ea8916ca7" {
		t.Fatalf("format-v1 semantic hash = %s, want compatibility fixture", encoded)
	}
	if !first.IsValid() || first.CompilerFormatVersion() != 1 ||
		first.Snapshot().Revision() != 2 {
		t.Fatalf("candidate = %+v, want valid compiler format 1 revision 2", first)
	}
}

func TestCandidateHashChangesWithTrafficOrCompilerFormat(t *testing.T) {
	t.Parallel()

	baseRule := publicationRuleFixture(t, "000000000801", "000000000701", "000000000702", 443)
	changedRule := publicationRuleFixture(t, "000000000801", "000000000701", "000000000702", 8443)
	base := publicationCandidateFixture(t, 2, []policy.Rule{baseRule})
	changedTraffic := publicationCandidateFixture(t, 2, []policy.Rule{changedRule})
	changedCompiler, err := publication.NewCandidate(base.Snapshot(), 2)
	if err != nil {
		t.Fatalf("publication.NewCandidate() error = %v", err)
	}

	if base.SemanticHash() == changedTraffic.SemanticHash() ||
		base.SemanticHash() == changedCompiler.SemanticHash() {
		t.Fatal("semantic hash did not bind traffic semantics and compiler format")
	}
}

func TestCandidateRejectsUnsafeInput(t *testing.T) {
	t.Parallel()

	if _, err := publication.NewCandidate(policy.Snapshot{}, 1); err == nil {
		t.Fatal("NewCandidate() accepted invalid snapshot")
	}
	valid := publicationCandidateFixture(t, 2, nil)
	if _, err := publication.NewCandidate(valid.Snapshot(), 0); err == nil {
		t.Fatal("NewCandidate() accepted zero compiler format")
	}
	if _, err := publication.NewCandidate(
		valid.Snapshot(),
		publication.MaximumCompilerFormatVersion+1,
	); err == nil {
		t.Fatal("NewCandidate() accepted excessive compiler format")
	}
}

func TestCandidateHashBindsResourceResolutionProvenance(t *testing.T) {
	t.Parallel()

	rule := publicationRuleFixture(t, "000000000801", "000000000701", "000000000702", 443)
	base := publicationCandidateFixture(t, 2, []policy.Rule{rule})
	resourceID, err := resource.ParseID("01890f00-0000-7000-8000-000000000901")
	if err != nil {
		t.Fatal(err)
	}
	hashValue := sha256.Sum256([]byte("synthetic Resource semantics"))
	resourceHash, err := resource.NewSemanticHash(hashValue)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := publication.NewResourceDestination(publication.ResourceDestinationParams{
		RuleID: rule.ID(), Scope: rule.Scope(), ResourceID: resourceID,
		ResourceVersion: 3, TargetGeneration: 2, InventoryRevision: 7,
		DestinationNodeID: rule.DestinationNodeID(), ResourceSemanticHash: resourceHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := publication.NewCandidateWithResourceDestinations(base.Snapshot(), []publication.ResourceDestination{destination})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := publication.NewResourceDestination(publication.ResourceDestinationParams{
		RuleID: rule.ID(), Scope: rule.Scope(), ResourceID: resourceID,
		ResourceVersion: 3, TargetGeneration: 3, InventoryRevision: 8,
		DestinationNodeID: rule.DestinationNodeID(), ResourceSemanticHash: resourceHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := publication.NewCandidateWithResourceDestinations(base.Snapshot(), []publication.ResourceDestination{changed})
	if err != nil {
		t.Fatal(err)
	}
	if first.CompilerFormatVersion() != 2 || len(first.ResourceDestinations()) != 1 ||
		first.SemanticHash() == second.SemanticHash() {
		t.Fatal("candidate did not bind format-v2 Resource provenance")
	}

	mismatchedRule := publicationRuleFixture(t, "000000000802", "000000000701", "000000000702", 443)
	mismatched := publicationCandidateFixture(t, 2, []policy.Rule{mismatchedRule})
	if _, err := publication.NewCandidateWithResourceDestinations(
		mismatched.Snapshot(),
		[]publication.ResourceDestination{destination},
	); err == nil {
		t.Fatal("resource provenance accepted a mismatched Access Rule")
	}
	alternateResourceID, err := resource.ParseID("01890f00-0000-7000-8000-000000000902")
	if err != nil {
		t.Fatal(err)
	}
	alternate, err := publication.NewResourceDestination(publication.ResourceDestinationParams{
		RuleID: rule.ID(), Scope: rule.Scope(), ResourceID: alternateResourceID,
		ResourceVersion: 1, TargetGeneration: 1, InventoryRevision: 7,
		DestinationNodeID: rule.DestinationNodeID(), ResourceSemanticHash: resourceHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publication.NewCandidateWithResourceDestinations(
		base.Snapshot(),
		[]publication.ResourceDestination{destination, alternate},
	); err == nil {
		t.Fatal("resource provenance accepted two Resources for one Access Rule")
	}
}

func TestCandidateHashBindsResourceGroupDefinitionAndMemberProvenance(t *testing.T) {
	t.Parallel()

	firstRule := publicationRuleFixture(t, "000000000811", "000000000701", "000000000702", 443)
	secondRule := publicationRuleFixture(t, "000000000811", "000000000701", "000000000703", 443)
	base := publicationCandidateFixture(t, 2, []policy.Rule{secondRule, firstRule})
	resourceHash, err := resource.NewSemanticHash(sha256.Sum256([]byte("group Resource semantics")))
	if err != nil {
		t.Fatal(err)
	}
	member := func(rule policy.Rule, suffix string, generation int64) publication.ResourceGroupMemberDestination {
		t.Helper()
		resourceID, parseErr := resource.ParseID("01890f00-0000-7000-8000-" + suffix)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		value, memberErr := publication.NewResourceGroupMemberDestination(
			publication.ResourceGroupMemberDestinationParams{
				Scope: rule.Scope(), ResourceID: resourceID, ResourceVersion: 3,
				TargetGeneration: generation, InventoryRevision: 7,
				DestinationNodeID: rule.DestinationNodeID(), ResourceSemanticHash: resourceHash,
			},
		)
		if memberErr != nil {
			t.Fatal(memberErr)
		}
		return value
	}
	groupID, err := resource.ParseGroupID("01890f00-0000-7000-8000-000000000951")
	if err != nil {
		t.Fatal(err)
	}
	groupHash, err := resource.NewSemanticHash(sha256.Sum256([]byte("group definition semantics")))
	if err != nil {
		t.Fatal(err)
	}
	newDestination := func(groupRevision int64, secondGeneration int64) publication.ResourceGroupDestination {
		t.Helper()
		destination, destinationErr := publication.NewResourceGroupDestination(
			publication.ResourceGroupDestinationParams{
				RuleID: firstRule.ID(), Scope: firstRule.Scope(), ResourceGroupID: groupID,
				GroupVersion: 2, DefinitionVersion: 2, GroupRevision: groupRevision,
				GroupSemanticHash: groupHash,
				Members: []publication.ResourceGroupMemberDestination{
					member(secondRule, "000000000902", secondGeneration),
					member(firstRule, "000000000901", 1),
				},
			},
		)
		if destinationErr != nil {
			t.Fatal(destinationErr)
		}
		return destination
	}
	first, err := publication.NewCandidateWithResourceGroupDestinations(
		base.Snapshot(), nil, []publication.ResourceGroupDestination{newDestination(8, 1)},
	)
	if err != nil {
		t.Fatal(err)
	}
	changedRevision, err := publication.NewCandidateWithResourceGroupDestinations(
		base.Snapshot(), nil, []publication.ResourceGroupDestination{newDestination(9, 1)},
	)
	if err != nil {
		t.Fatal(err)
	}
	changedMember, err := publication.NewCandidateWithResourceGroupDestinations(
		base.Snapshot(), nil, []publication.ResourceGroupDestination{newDestination(8, 2)},
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.CompilerFormatVersion() != 3 || len(first.ResourceGroupDestinations()) != 1 ||
		first.SemanticHash() == changedRevision.SemanticHash() ||
		first.SemanticHash() == changedMember.SemanticHash() {
		t.Fatal("candidate did not bind format-v3 Resource Group provenance")
	}

	incomplete := publicationCandidateFixture(t, 2, []policy.Rule{firstRule})
	if _, err := publication.NewCandidateWithResourceGroupDestinations(
		incomplete.Snapshot(), nil, []publication.ResourceGroupDestination{newDestination(8, 1)},
	); err == nil {
		t.Fatal("Resource Group provenance accepted an incomplete expansion")
	}
}
