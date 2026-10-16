package publication_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"meshtransit.net/core/internal/domain/policy"
	publication "meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/resource"
)

func ruleFingerprintsFixture(t *testing.T, candidate publication.Candidate) publication.RuleFingerprintSet {
	t.Helper()
	set, err := publication.FingerprintRules(candidate)
	if err != nil {
		t.Fatalf("FingerprintRules() error = %v", err)
	}
	return set
}

func TestRuleFingerprintsRoundTripAndRejectCorruption(t *testing.T) {
	t.Parallel()

	candidate := publicationCandidateFixture(t, 2, []policy.Rule{
		publicationRuleFixture(t, "000000000802", "000000000701", "000000000702", 443),
		publicationRuleFixture(t, "000000000801", "000000000701", "000000000703", 22),
	})
	set := ruleFingerprintsFixture(t, candidate)
	if set.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", set.Len())
	}
	encoded := set.MarshalBinary()
	decoded, err := publication.ParseRuleFingerprintSet(encoded)
	if err != nil {
		t.Fatalf("ParseRuleFingerprintSet() error = %v", err)
	}
	if !bytes.Equal(decoded.MarshalBinary(), encoded) {
		t.Fatal("decoded fingerprints differ from the encoded ones")
	}
	reordered := publicationCandidateFixture(t, 2, []policy.Rule{
		publicationRuleFixture(t, "000000000801", "000000000701", "000000000703", 22),
		publicationRuleFixture(t, "000000000802", "000000000701", "000000000702", 443),
	})
	if !bytes.Equal(ruleFingerprintsFixture(t, reordered).MarshalBinary(), encoded) {
		t.Fatal("rule order changed the fingerprints")
	}

	corruptions := map[string][]byte{
		"empty":           {},
		"unknown format":  append([]byte{9}, encoded[1:]...),
		"truncated":       encoded[:len(encoded)-1],
		"trailing byte":   append(bytes.Clone(encoded), 0),
		"count too large": append([]byte{encoded[0], 0xff, 0xff, 0xff, 0xff}, encoded[5:]...),
	}
	unsorted := bytes.Clone(encoded)
	first, second := unsorted[5:5+publication.RuleFingerprintSize], unsorted[5+publication.RuleFingerprintSize:]
	swapped := append(append([]byte{}, unsorted[:5]...), append(bytes.Clone(second), first...)...)
	corruptions["unsorted"] = swapped
	for name, value := range corruptions {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := publication.ParseRuleFingerprintSet(value); !errors.Is(err, publication.ErrInvalidRuleFingerprints) {
				t.Fatalf("ParseRuleFingerprintSet() error = %v, want ErrInvalidRuleFingerprints", err)
			}
		})
	}
}

func TestRuleFingerprintsFollowTheRuleAsWritten(t *testing.T) {
	t.Parallel()

	base := ruleFingerprintsFixture(t, publicationCandidateFixture(t, 2, []policy.Rule{
		publicationRuleFixture(t, "000000000801", "000000000701", "000000000702", 443),
	}))
	tests := map[string]struct {
		rule    policy.Rule
		changed bool
	}{
		"same rule at a later revision": {publicationRuleFixture(t, "000000000801", "000000000701", "000000000702", 443), false},
		"other port":                    {publicationRuleFixture(t, "000000000801", "000000000701", "000000000702", 8443), true},
		"other source":                  {publicationRuleFixture(t, "000000000801", "000000000704", "000000000702", 443), true},
		"other destination":             {publicationRuleFixture(t, "000000000801", "000000000701", "000000000705", 443), true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			next := ruleFingerprintsFixture(t, publicationCandidateFixture(t, 3, []policy.Rule{test.rule}))
			summary := publication.SummarizeRuleChanges(base, publication.RuleBaselinePreviousRelease, next)
			if got := summary.Changed() == 1; got != test.changed {
				t.Fatalf("Changed() = %d, want changed=%v", summary.Changed(), test.changed)
			}
			if summary.Added() != 0 || summary.Removed() != 0 {
				t.Fatalf("summary = %+v, want only a change", summary)
			}
		})
	}
}

func TestRuleFingerprintsNameTheResourceDestination(t *testing.T) {
	t.Parallel()

	rule := publicationRuleFixture(t, "000000000801", "000000000701", "000000000702", 443)
	base := publicationCandidateFixture(t, 2, []policy.Rule{rule})
	resourceID, err := resource.ParseID("01890f00-0000-7000-8000-000000000901")
	if err != nil {
		t.Fatal(err)
	}
	resourceHash, err := resource.NewSemanticHash(sha256.Sum256([]byte("synthetic Resource semantics")))
	if err != nil {
		t.Fatal(err)
	}
	destination := func(version int64) publication.ResourceDestination {
		value, err := publication.NewResourceDestination(publication.ResourceDestinationParams{
			RuleID: rule.ID(), Scope: rule.Scope(), ResourceID: resourceID,
			ResourceVersion: version, TargetGeneration: version, InventoryRevision: 7,
			DestinationNodeID: rule.DestinationNodeID(), ResourceSemanticHash: resourceHash,
		})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	withResource := func(version int64) publication.RuleFingerprintSet {
		candidate, err := publication.NewCandidateWithResourceDestinations(
			base.Snapshot(), []publication.ResourceDestination{destination(version)},
		)
		if err != nil {
			t.Fatal(err)
		}
		return ruleFingerprintsFixture(t, candidate)
	}
	previous, next := withResource(1), withResource(2)
	summary := publication.SummarizeRuleChanges(previous, publication.RuleBaselinePreviousRelease, next)
	if summary.Changed() != 0 || summary.Unchanged() != 1 {
		t.Fatalf("a new Resource version counted as a rule change: %+v", summary)
	}
	device := ruleFingerprintsFixture(t, base)
	summary = publication.SummarizeRuleChanges(device, publication.RuleBaselinePreviousRelease, next)
	if summary.Changed() != 1 || len(summary.Rules()) != 1 {
		t.Fatalf("a Device destination replaced by a Resource is not a change: %+v", summary)
	}
	changed := summary.Rules()[0]
	if changed.Kind() != publication.RuleChangeChanged || changed.RuleID() != rule.ID() ||
		changed.DestinationKind() != publication.DestinationResource ||
		changed.DestinationID().String() != resourceID.String() {
		t.Fatalf("changed rule = %+v, want the Resource destination", changed)
	}
}

func TestSummarizeRuleChangesCountsAndBoundsTheList(t *testing.T) {
	t.Parallel()

	rules := func(first, count int, port uint16) []policy.Rule {
		values := make([]policy.Rule, count)
		for index := range values {
			values[index] = publicationRuleFixture(t, fmt.Sprintf("%012d", 800+first+index),
				"000000000701", "000000000702", port)
		}
		return values
	}
	// 30 kept unchanged, 25 changed, 25 removed, 25 added.
	previous := ruleFingerprintsFixture(t, publicationCandidateFixture(t, 2,
		append(append(rules(0, 30, 443), rules(30, 25, 443)...), rules(55, 25, 443)...)))
	next := ruleFingerprintsFixture(t, publicationCandidateFixture(t, 3,
		append(append(rules(0, 30, 443), rules(30, 25, 8443)...), rules(80, 25, 443)...)))
	summary := publication.SummarizeRuleChanges(previous, publication.RuleBaselinePreviousRelease, next)
	if !summary.BaselineKnown() || summary.Added() != 25 || summary.Removed() != 25 ||
		summary.Changed() != 25 || summary.Unchanged() != 30 {
		t.Fatalf("summary counts = added %d removed %d changed %d unchanged %d",
			summary.Added(), summary.Removed(), summary.Changed(), summary.Unchanged())
	}
	listed := summary.Rules()
	if len(listed) != publication.MaximumListedRuleChanges || !summary.Truncated() {
		t.Fatalf("listed %d rules, truncated %v; want %d and true",
			len(listed), summary.Truncated(), publication.MaximumListedRuleChanges)
	}
	kinds := map[publication.RuleChangeKind]int{}
	for _, change := range listed {
		kinds[change.Kind()]++
	}
	if kinds[publication.RuleChangeAdded] == 0 || kinds[publication.RuleChangeRemoved] == 0 ||
		kinds[publication.RuleChangeChanged] == 0 {
		t.Fatalf("listed kinds = %v, want every kind represented", kinds)
	}

	small := publication.SummarizeRuleChanges(previous, publication.RuleBaselinePreviousRelease, previous)
	if small.Truncated() || len(small.Rules()) != 0 || small.Unchanged() != 80 {
		t.Fatalf("identical policy summary = %+v", small)
	}
}

func TestSummarizeRuleChangesWithoutABaseline(t *testing.T) {
	t.Parallel()

	next := ruleFingerprintsFixture(t, publicationCandidateFixture(t, 3, []policy.Rule{
		publicationRuleFixture(t, "000000000801", "000000000701", "000000000702", 443),
	}))
	for _, baseline := range []publication.RuleBaseline{
		publication.RuleBaselineUnavailable, publication.RuleBaselineUnreadable, publication.RuleBaselineUnknown,
	} {
		summary := publication.SummarizeRuleChanges(next, baseline, next)
		if summary.BaselineKnown() || summary.Added() != 0 || summary.Removed() != 0 ||
			summary.Changed() != 0 || summary.Unchanged() != 0 || len(summary.Rules()) != 0 {
			t.Fatalf("summary with baseline %v = %+v", baseline, summary)
		}
	}
	first := publication.SummarizeRuleChanges(next, publication.RuleBaselineNone, next)
	if !first.BaselineKnown() || first.Baseline().String() != "none" || first.Added() != 1 || first.Unchanged() != 0 {
		t.Fatalf("first publication summary = %+v, want one added rule against nothing", first)
	}
}

// Group rules fingerprint their selectors, so a new source group or another
// destination group changes the rule; a Resource Group rule is one rule
// whatever its members.
func TestRuleFingerprintsCoverGroupRules(t *testing.T) {
	t.Parallel()

	base := publicationCandidateFixture(t, 2, nil)
	withGroupRule := func(rule publication.GroupRule) publication.RuleFingerprintSet {
		candidate, err := base.WithGroupRules([]publication.GroupRule{rule})
		if err != nil {
			t.Fatal(err)
		}
		return ruleFingerprintsFixture(t, candidate)
	}
	original := withGroupRule(groupRuleFixture(t, "000000000801", mustGroupID(t, "000000000601"), mustGroupID(t, "000000000602"), 443))
	tests := map[string]struct {
		rule    publication.GroupRule
		changed bool
	}{
		"same":                    {groupRuleFixture(t, "000000000801", mustGroupID(t, "000000000601"), mustGroupID(t, "000000000602"), 443), false},
		"other source group":      {groupRuleFixture(t, "000000000801", mustGroupID(t, "000000000603"), mustGroupID(t, "000000000602"), 443), true},
		"other destination group": {groupRuleFixture(t, "000000000801", mustGroupID(t, "000000000601"), mustGroupID(t, "000000000604"), 443), true},
		"other port":              {groupRuleFixture(t, "000000000801", mustGroupID(t, "000000000601"), mustGroupID(t, "000000000602"), 80), true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			summary := publication.SummarizeRuleChanges(original, publication.RuleBaselinePreviousRelease, withGroupRule(test.rule))
			if (summary.Changed() == 1) != test.changed || summary.Added() != 0 || summary.Removed() != 0 {
				t.Fatalf("summary = changed %d added %d removed %d, want changed=%v",
					summary.Changed(), summary.Added(), summary.Removed(), test.changed)
			}
			if test.changed && summary.Rules()[0].DestinationKind() != publication.DestinationDeviceGroup {
				t.Fatalf("destination kind = %v, want device_group", summary.Rules()[0].DestinationKind())
			}
		})
	}
}
