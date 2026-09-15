package publication_test

import (
	"testing"

	"github.com/meshtransit/meshtransit/internal/policy"
	publication "github.com/meshtransit/meshtransit/internal/policy/publication"
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
