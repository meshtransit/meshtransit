package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/identity/oidcauth"
)

const (
	testMigrationID      = "01890f00-0000-7000-8000-000000000001"
	testDeploymentID     = "01890f00-0000-7000-8000-000000000002"
	testActorID          = "01890f00-0000-7000-8000-000000000003"
	testSourceProviderID = "01890f00-0000-7000-8000-000000000004"
	testTargetProviderID = "01890f00-0000-7000-8000-000000000005"
	testSourceSubjectID  = "01890f00-0000-7000-8000-000000000006"
	testPrincipalID      = "01890f00-0000-7000-8000-000000000007"
	testTargetSubjectID  = "01890f00-0000-7000-8000-000000000008"
	testAuditEventID     = "01890f00-0000-7000-8000-000000000009"
	testOutboxEventID    = "01890f00-0000-7000-8000-000000000010"
	testSourceIssuer     = "https://source.example.test"
	testTargetIssuer     = "https://target.example.test"
	testSourceSubject    = " Case-sensitive-source "
	testTargetSubject    = "opaque-target"
)

func TestManifestRejectsAmbiguousAndUnsafeInput(t *testing.T) {
	t.Parallel()
	valid := validManifestJSON()
	if _, err := parseManifest([]byte(valid)); err != nil {
		t.Fatal("valid manifest rejected")
	}
	for _, candidate := range []struct {
		name  string
		value string
	}{
		{name: "unknown field", value: strings.Replace(valid, `"schema_version":`, `"unknown":true,"schema_version":`, 1)},
		{name: "duplicate field", value: strings.Replace(valid, `"schema_version":`, `"schema_version":"duplicate","schema_version":`, 1)},
		{name: "same provider", value: strings.Replace(valid, testTargetProviderID, testSourceProviderID, 1)},
		{name: "insecure issuer", value: strings.Replace(valid, testTargetIssuer, "http://target.example.test", 1)},
		{name: "source target id overlap", value: strings.Replace(valid, testTargetSubjectID, testSourceSubjectID, 1)},
		{name: "evidence id overlap", value: strings.Replace(valid, testOutboxEventID, testAuditEventID, 1)},
		{name: "empty audit reason", value: strings.Replace(valid, "Approved provider transition", "", 1)},
		{name: "trailing value", value: valid + ` {}`},
		{name: "null", value: `null`},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseManifest([]byte(candidate.value)); err == nil {
				t.Fatal("unsafe manifest accepted")
			}
		})
	}
}

func TestApplyRequiresExactEnableConfirmation(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest.json")
	sourceKeyPath := filepath.Join(directory, "source.key")
	targetKeyPath := filepath.Join(directory, "target.key")
	manifestBytes := []byte(validManifestJSON())
	writeProtectedFixture(t, manifestPath, manifestBytes)
	writeProtectedFixture(t, sourceKeyPath, encodedKey(1))
	writeProtectedFixture(t, targetKeyPath, encodedKey(2))
	hash := sha256.Sum256(manifestBytes)
	hashText := hex.EncodeToString(hash[:])
	confirmation := strings.Join([]string{
		testMigrationID,
		testDeploymentID,
		testSourceProviderID,
		testTargetProviderID,
		hashText,
	}, "/")
	environment := map[string]string{envConfirmation: confirmation}
	lookup := func(key string) (string, bool) { value, found := environment[key]; return value, found }
	options := rawOptions{
		manifestPath: manifestPath, expectedManifestHash: hashText,
		sourceKeyPath: sourceKeyPath, targetKeyPath: targetKeyPath,
		mode: string(transitionModeApply),
	}
	if _, err := loadPlanSpec(context.Background(), options, lookup); err == nil {
		t.Fatal("apply accepted without enable confirmation")
	}
	environment[envEnable] = "wrong"
	if _, err := loadPlanSpec(context.Background(), options, lookup); err == nil {
		t.Fatal("apply accepted wrong enable confirmation")
	}
	environment[envEnable] = applyEnableConfirmation
	spec, err := loadPlanSpec(context.Background(), options, lookup)
	if err != nil || spec.mode != transitionModeApply {
		t.Fatalf("enabled apply plan rejected: mode=%q error=%v", spec.mode, err)
	}
	spec.clear()
}

func TestProtectedFileRejectsWeakCustody(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	protected := filepath.Join(directory, "manifest.json")
	writeProtectedFixture(t, protected, []byte(validManifestJSON()))
	contents, err := readProtectedFile(context.Background(), protected, maximumManifestBytes)
	if err != nil || len(contents) == 0 {
		t.Fatal("protected file rejected")
	}
	clear(contents)
	if err := os.Chmod(protected, 0o644); err != nil { // #nosec G302 -- fixture proves weak custody is rejected.
		t.Fatal(err)
	}
	if _, err := readProtectedFile(context.Background(), protected, maximumManifestBytes); err == nil {
		t.Fatal("world-readable file accepted")
	}
	if err := os.Chmod(protected, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "manifest-link.json")
	if err := os.Symlink(protected, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedFile(context.Background(), symlink, maximumManifestBytes); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestPlanSpecUsesCanonicalDigestAndRedactsRawIdentity(t *testing.T) {
	t.Parallel()
	manifest, err := parseManifest([]byte(validManifestJSON()))
	if err != nil {
		t.Fatal(err)
	}
	sourceKey := testSubjectKey(t, "source-key-v1", 1)
	targetKey := testSubjectKey(t, "target-key-v1", 2)
	spec, err := buildPlanSpec(manifest, strings.Repeat("a", 64), sourceKey, targetKey)
	if err != nil || !spec.valid() || len(spec.mappings) != 1 {
		t.Fatal("valid plan rejected")
	}
	if !spec.mappings[0].sourceDigest.IsValid() || !spec.mappings[0].targetDigest.IsValid() ||
		spec.mappings[0].sourceDigest == spec.mappings[0].targetDigest {
		t.Fatal("subject namespaces were not separated")
	}
	formatted := fmt.Sprintf("%v %#v", spec, spec.manifest)
	if strings.Contains(formatted, testSourceIssuer) || strings.Contains(formatted, testSourceSubject) {
		t.Fatal("raw identity escaped redaction")
	}
	if _, err := spec.MarshalJSON(); err == nil {
		t.Fatal("plan allowed implicit JSON serialization")
	}
	spec.clear()
	if spec.manifest.Source.Issuer != "" || spec.manifest.Mappings[0].SourceSubject != "" {
		t.Fatal("plan clear retained raw identity")
	}
}

func TestRunEmitsOnlyBoundedPublicEvidence(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest.json")
	sourceKeyPath := filepath.Join(directory, "source.key")
	targetKeyPath := filepath.Join(directory, "target.key")
	manifestBytes := []byte(validManifestJSON())
	writeProtectedFixture(t, manifestPath, manifestBytes)
	writeProtectedFixture(t, sourceKeyPath, encodedKey(1))
	writeProtectedFixture(t, targetKeyPath, encodedKey(2))
	hash := sha256.Sum256(manifestBytes)
	hashText := hex.EncodeToString(hash[:])
	confirmation := strings.Join([]string{
		testMigrationID,
		testDeploymentID,
		testSourceProviderID,
		testTargetProviderID,
		hashText,
	}, "/")
	environment := map[string]string{
		envConfirmation:           confirmation,
		envPostgreSQLAddress:      "database.example.test:5432",
		envPostgreSQLDatabase:     "meshtransit",
		envPostgreSQLAdminUser:    "qualification_admin",
		envPostgreSQLPasswordFile: filepath.Join(directory, "password"),
		envPostgreSQLTrustFile:    filepath.Join(directory, "ca.pem"),
	}
	lookup := func(key string) (string, bool) { value, found := environment[key]; return value, found }
	args := []string{
		"-manifest", manifestPath,
		"-expected-manifest-sha256", hashText,
		"-source-key-file", sourceKeyPath,
		"-target-key-file", targetKeyPath,
	}
	var output strings.Builder
	var errorOutput strings.Builder
	executor := func(_ context.Context, spec planSpec, _ databaseSettings) (planOutput, error) {
		return planOutput{
			SchemaVersion: manifestSchemaVersion, Operation: "validated",
			MigrationID: spec.migrationID.String(), ManifestSHA256: spec.manifestSHA256,
			DeploymentID:     spec.deploymentID.String(),
			SourceProviderID: spec.sourceProviderID.String(), TargetProviderID: spec.targetProviderID.String(),
			MappingCount: 1, ActiveSourceSubjectCount: 1,
		}, nil
	}
	if code := run(context.Background(), args, lookup, &output, &errorOutput, executor); code != exitSuccess {
		t.Fatalf("run() = %d, stderr = %s", code, errorOutput.String())
	}
	for _, private := range []string{testSourceIssuer, testTargetIssuer, testSourceSubject, testTargetSubject} {
		if strings.Contains(output.String(), private) || strings.Contains(errorOutput.String(), private) {
			t.Fatal("private identity escaped command output")
		}
	}
}

func validManifestJSON() string {
	return `{
"schema_version":"` + manifestSchemaVersion + `",
"migration_id":"` + testMigrationID + `",
"deployment_id":"` + testDeploymentID + `",
"actor_principal_id":"` + testActorID + `",
"audit_reason":"Approved provider transition",
"evidence":{"audit_event_id":"` + testAuditEventID + `","outbox_event_id":"` + testOutboxEventID + `"},
"source":{"provider_id":"` + testSourceProviderID + `","issuer":"` + testSourceIssuer + `","subject_key_id":"source-key-v1","expected_generation":1,"expected_generation_version":1,"expected_provider_version":1},
"target":{"provider_id":"` + testTargetProviderID + `","issuer":"` + testTargetIssuer + `","subject_key_id":"target-key-v1","expected_generation":1,"expected_generation_version":1,"expected_provider_version":1},
"expected_active_source_subjects":1,
"expected_active_sessions":0,
"expected_open_auth_transactions":0,
"mappings":[{"source_subject_id":"` + testSourceSubjectID + `","target_subject_id":"` + testTargetSubjectID + `","principal_id":"` + testPrincipalID + `","expected_source_version":1,"expected_claims_revision":1,"source_subject":"` + testSourceSubject + `","target_subject":"` + testTargetSubject + `"}]
}`
}

func testSubjectKey(t *testing.T, id string, first byte) oidcauth.SubjectKey {
	t.Helper()
	keyID, err := oidcauth.NewDigestKeyID(id)
	if err != nil {
		t.Fatal(err)
	}
	material := make([]byte, 32)
	material[0] = first
	key, err := oidcauth.NewSubjectKey(keyID, material)
	clear(material)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func encodedKey(first byte) []byte {
	material := make([]byte, 32)
	material[0] = first
	encoded := []byte(base64.RawURLEncoding.EncodeToString(material))
	clear(material)
	return encoded
}

func writeProtectedFixture(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}
