package postgres

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	publication "meshtransit.net/core/internal/domain/policy/publication"
)

// publishWithFakeDatabase resolves and applies one command on a fake
// transaction. Without previous the Network has no release yet; with it the
// active release is at the command's base revision and stores previous.
func publishWithFakeDatabase(
	t *testing.T,
	command publication.Command,
	previous *policyPublicationTestRow,
) (*fakePolicyPublicationTransaction, error) {
	t.Helper()
	databaseTransaction := newFakePolicyPublicationTransaction()
	enqueuePolicyPublicationResolution(t, databaseTransaction, command, 5, command.BasePolicyRevision())
	if previous != nil {
		hash := command.Candidate().SemanticHash().Bytes()
		databaseTransaction.rows[lockActivePolicyReleaseSQL] = []policyPublicationRow{policyPublicationTestRow{
			scan: func(destinations ...any) error {
				*destinations[0].(*string) = "01890f00-0000-7000-8000-000000000901"
				*destinations[1].(*int64) = command.BasePolicyRevision()
				*destinations[2].(*[]byte) = append([]byte(nil), hash[:]...)
				return nil
			},
		}}
		databaseTransaction.enqueueRow(readPolicyReleaseRuleFingerprintsSQL, *previous)
	}
	enqueuePolicyPublicationApply(databaseTransaction, 6, command.Candidate().Snapshot().Revision())
	if len(command.Candidate().ImportedResourceDestinations()) > 0 {
		enqueueActiveGuardrails(databaseTransaction, "[]")
	}
	store := beginTestPolicyPublicationStore(t, databaseTransaction)
	value, err := store.Begin(t.Context(), command.Candidate().Snapshot().Scope())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	transaction := value.(*policyPublicationTransaction)
	resolution, err := transaction.Resolve(t.Context(), command, policyPublicationTestTime)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	_, err = transaction.Apply(t.Context(), policyPublicationChangeFixture(t, command, resolution))
	return databaseTransaction, err
}

func publishedAuditPayload(t *testing.T, transaction *fakePolicyPublicationTransaction) policyPublicationAuditPayload {
	t.Helper()
	call := findPolicyPublicationCall(t, transaction.calls, appendPolicyPublicationEvidenceSQL)
	var payload policyPublicationAuditPayload
	if err := json.Unmarshal(call.arguments[len(call.arguments)-2].([]byte), &payload); err != nil {
		t.Fatalf("decode audit payload: %v", err)
	}
	return payload
}

func fingerprintsRow(t *testing.T, command publication.Command) policyPublicationTestRow {
	t.Helper()
	set, err := publication.FingerprintRules(command.Candidate())
	if err != nil {
		t.Fatal(err)
	}
	encoded := set.MarshalBinary()
	return policyPublicationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*[]byte) = encoded
		return nil
	}}
}

// The first publication of a Network has an empty, known baseline, so every
// rule is added; an Imported Resource rule names its consumer-local ID.
func TestPolicyPublicationAuditSummarizesTheFirstImportedResourceRelease(t *testing.T) {
	t.Parallel()

	command := policyImportedResourcePublicationCommandFixture(t)
	transaction, err := publishWithFakeDatabase(t, command, nil)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	queries := policyPublicationCallQueries(transaction.calls)
	for _, query := range queries {
		if query == readPolicyReleaseRuleFingerprintsSQL {
			t.Fatal("a Network without a release read previous fingerprints")
		}
	}
	record := findPolicyPublicationCall(t, transaction.calls, recordPolicyReleaseRuleFingerprintsSQL)
	stored, err := publication.ParseRuleFingerprintSet(record.arguments[1].([]byte))
	publish := findPolicyPublicationCall(t, transaction.calls, publishCompiledPolicySQL)
	if err != nil || stored.Len() != 1 || record.arguments[0] != publish.arguments[0] {
		t.Fatalf("recorded fingerprints = %d entries, error %v", stored.Len(), err)
	}
	payload := publishedAuditPayload(t, transaction)
	imported := command.Candidate().ImportedResourceDestinations()[0]
	want := policyPublicationChangeSummaryPayload{
		Baseline: "none", Added: 1,
		Rules: []policyPublicationRuleChangePayload{{
			Change: "added", RuleID: imported.RuleID().String(), DestinationKind: "imported_resource",
			DestinationID: imported.Resolution().ImportedResourceID().String(),
		}},
	}
	if payload.PolicyRevision != command.Candidate().Snapshot().Revision() ||
		!reflect.DeepEqual(payload.ChangeSummary, want) {
		t.Fatalf("audit payload revision %d summary %+v, want %d %+v",
			payload.PolicyRevision, payload.ChangeSummary, command.Candidate().Snapshot().Revision(), want)
	}
}

// With an active release, the summary compares its stored fingerprints with
// the new rules, and the new release's fingerprints are stored before the
// audit event.
func TestPolicyPublicationAuditComparesWithThePreviousRelease(t *testing.T) {
	t.Parallel()

	previous := fingerprintsRow(t, policyImportedResourcePublicationCommandFixture(t))
	command := policyPublicationCommandFixture(t)
	transaction, err := publishWithFakeDatabase(t, command, &previous)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	queries := policyPublicationCallQueries(transaction.calls)
	wantTail := []string{
		readPolicyReleaseRuleFingerprintsSQL, setPolicyPublicationChangeSQL, scaledPolicyPublicationGrantedSQL,
		publishCompiledPolicySQL, recordPolicyReleaseRuleFingerprintsSQL, appendPolicyPublicationEvidenceSQL,
	}
	if len(queries) < len(wantTail) || !reflect.DeepEqual(queries[len(queries)-len(wantTail):], wantTail) {
		t.Fatalf("call order = %#v, want it to end with %#v", queries, wantTail)
	}
	read := findPolicyPublicationCall(t, transaction.calls, readPolicyReleaseRuleFingerprintsSQL)
	if read.arguments[0] != "01890f00-0000-7000-8000-000000000901" {
		t.Fatalf("read fingerprints of %v, want the active release", read.arguments)
	}
	payload := publishedAuditPayload(t, transaction)
	summary := payload.ChangeSummary
	if summary.Baseline != "previous_release" || summary.Added != 1 || summary.Removed != 1 ||
		summary.Changed != 0 || len(summary.Rules) != 2 || summary.Rules[0].Change != "removed" ||
		summary.Rules[0].DestinationKind != "imported_resource" || summary.Rules[1].Change != "added" ||
		summary.Rules[1].DestinationKind != "device" {
		t.Fatalf("change summary = %+v", summary)
	}
}

// A release published before fingerprints existed leaves the baseline
// unknown: the event says so instead of claiming every rule is new.
func TestPolicyPublicationAuditMarksAnUnknownBaseline(t *testing.T) {
	t.Parallel()

	missing := policyPublicationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*[]byte) = nil
		return nil
	}}
	transaction, err := publishWithFakeDatabase(t, policyPublicationCommandFixture(t), &missing)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	summary := publishedAuditPayload(t, transaction).ChangeSummary
	want := policyPublicationChangeSummaryPayload{Baseline: "unavailable", Rules: []policyPublicationRuleChangePayload{}}
	if !reflect.DeepEqual(summary, want) {
		t.Fatalf("change summary = %+v, want %+v", summary, want)
	}
	findPolicyPublicationCall(t, transaction.calls, recordPolicyReleaseRuleFingerprintsSQL)
}

// Stored fingerprints that do not decode (altered, or a format this Core
// does not know) never stop publication, which may be revoking access; the
// event says the baseline was unreadable.
func TestPolicyPublicationRecordsUnreadablePreviousFingerprints(t *testing.T) {
	t.Parallel()

	corrupt := policyPublicationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*[]byte) = []byte{2, 0, 0, 0, 0}
		return nil
	}}
	transaction, err := publishWithFakeDatabase(t, policyPublicationCommandFixture(t), &corrupt)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	summary := publishedAuditPayload(t, transaction).ChangeSummary
	want := policyPublicationChangeSummaryPayload{Baseline: "unreadable", Rules: []policyPublicationRuleChangePayload{}}
	if !reflect.DeepEqual(summary, want) {
		t.Fatalf("change summary = %+v, want %+v", summary, want)
	}
}

// The listed rules are bounded, so the summary stays a small part of the
// 16 KiB audit payload however large the policy is.
func TestPolicyPublicationChangeSummaryPayloadIsBounded(t *testing.T) {
	t.Parallel()

	rules := make([]policyPublicationRuleChangePayload, publication.MaximumListedRuleChanges)
	for index := range rules {
		rules[index] = policyPublicationRuleChangePayload{
			Change: "removed", RuleID: "01890f00-0000-7000-8000-000000000901",
			DestinationKind: "imported_resource", DestinationID: "01890f00-0000-7000-8000-000000000902",
		}
	}
	encoded, err := json.Marshal(policyPublicationChangeSummaryPayload{
		Baseline: "previous_release", Added: 10000, Removed: 10000, Changed: 10000, Unchanged: 10000,
		Rules: rules, Truncated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 4096 {
		t.Fatalf("largest change summary = %d bytes, want at most 4096", len(encoded))
	}
}

// The largest payload a publication can produce, 100 audit-mode findings
// with the longest names and a full change summary, still fits the audit
// event: the lists shrink and say so, the counts stay whole.
func TestPolicyPublicationAuditPayloadFitsTheAuditEvent(t *testing.T) {
	t.Parallel()

	findings := make([]guardrailFindingEvidence, 100)
	for index := range findings {
		findings[index] = guardrailFindingEvidence{
			GuardrailID: "01890f00-0000-7000-8000-000000000901", Version: 1,
			Name: strings.Repeat("\u00e9", 80), Mode: "audit",
			Reason: strings.Repeat("a rule opens a new path to a shared Device ", 4),
		}
	}
	rules := make([]policyPublicationRuleChangePayload, 20)
	for index := range rules {
		rules[index] = policyPublicationRuleChangePayload{
			Change: "added", RuleID: "01890f00-0000-7000-8000-000000000801",
			DestinationKind: "imported_resource", DestinationID: "01890f00-0000-7000-8000-000000000924",
		}
	}
	evidence := policyPublicationAuditPayload{
		AuditReason: strings.Repeat("r", 512), BasePolicyRevision: 1, PolicyRevision: 2,
		CompilerFormatVersion: 4, RuleCount: 10000, GuardrailFindings: findings,
		ChangeSummary: policyPublicationChangeSummaryPayload{
			Baseline: "previous_release", Added: 10000, Rules: rules,
		},
	}
	encoded, err := encodePolicyPublicationAuditPayload(evidence)
	if err != nil {
		t.Fatalf("encode largest payload: %v", err)
	}
	if length := jsonbTextLength(encoded); length > maximumAuditPayloadBytes {
		t.Fatalf("payload = %d jsonb text bytes, want at most %d", length, maximumAuditPayloadBytes)
	}
	var decoded policyPublicationAuditPayload
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ChangeSummary.Added != 10000 || !decoded.ChangeSummary.Truncated ||
		len(decoded.ChangeSummary.Rules) != 0 || decoded.GuardrailFindingCount != 100 ||
		!decoded.GuardrailFindingsTruncated || len(decoded.GuardrailFindings) == 0 {
		t.Fatalf("shrunk payload = summary %+v findings %d/%d truncated %v",
			decoded.ChangeSummary, len(decoded.GuardrailFindings), decoded.GuardrailFindingCount,
			decoded.GuardrailFindingsTruncated)
	}

	small := evidence
	small.GuardrailFindings = findings[:2]
	encoded, err = encodePolicyPublicationAuditPayload(small)
	if err != nil {
		t.Fatal(err)
	}
	var fitted policyPublicationAuditPayload
	if err := json.Unmarshal(encoded, &fitted); err != nil {
		t.Fatal(err)
	}
	if len(fitted.ChangeSummary.Rules) != 20 || fitted.GuardrailFindingsTruncated || len(fitted.GuardrailFindings) != 2 {
		t.Fatal("a payload that fits was shrunk")
	}
}

// jsonbTextLength counts the space jsonb prints after each separator, and
// none for separators inside strings. The wants are PostgreSQL's output of
// payload::jsonb::TEXT for each input.
func TestJSONBTextLengthMatchesPostgreSQLOutput(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		`{}`:                           `{}`,
		`{"a":1}`:                      `{"a": 1}`,
		`{"a":[1,2],"b":{"c":true}}`:   `{"a": [1, 2], "b": {"c": true}}`,
		`{"a":"x:,y","b":"q\"u:o,te"}`: `{"a": "x:,y", "b": "q\"u:o,te"}`,
		`{"a":"back\\","b":[]}`:        `{"a": "back\\", "b": []}`,
	}
	for input, want := range tests {
		if got := jsonbTextLength([]byte(input)); got != len(want) {
			t.Errorf("jsonbTextLength(%s) = %d, want %d (%s)", input, got, len(want), want)
		}
	}
}
