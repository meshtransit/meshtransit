package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const (
	manifestSchemaVersion       = "meshtransit.identity-subject-transition/v1"
	maximumManifestBytes        = 64 * 1024
	maximumMappings             = 128
	maximumActiveSessions       = 10000
	maximumOpenAuthTransactions = 10000
)

type transitionManifest struct {
	SchemaVersion                string            `json:"schema_version"`
	MigrationID                  string            `json:"migration_id"`
	DeploymentID                 string            `json:"deployment_id"`
	ActorPrincipalID             string            `json:"actor_principal_id"`
	Source                       providerReference `json:"source"`
	Target                       providerReference `json:"target"`
	ExpectedActiveSourceSubjects int64             `json:"expected_active_source_subjects"`
	ExpectedActiveSessions       int64             `json:"expected_active_sessions"`
	ExpectedOpenAuthTransactions int64             `json:"expected_open_auth_transactions"`
	Mappings                     []subjectMapping  `json:"mappings"`
}

type providerReference struct {
	ProviderID                string `json:"provider_id"`
	Issuer                    string `json:"issuer"`
	SubjectKeyID              string `json:"subject_key_id"`
	ExpectedGeneration        int64  `json:"expected_generation"`
	ExpectedGenerationVersion int64  `json:"expected_generation_version"`
	ExpectedProviderVersion   int64  `json:"expected_provider_version"`
}

type subjectMapping struct {
	SourceSubjectID        string `json:"source_subject_id"`
	PrincipalID            string `json:"principal_id"`
	ExpectedSourceVersion  int64  `json:"expected_source_version"`
	ExpectedClaimsRevision int64  `json:"expected_claims_revision"`
	SourceSubject          string `json:"source_subject"`
	TargetSubject          string `json:"target_subject"`
}

type plannedMapping struct {
	sourceSubjectID        publicid.ID
	principalID            identity.PrincipalID
	expectedSourceVersion  int64
	expectedClaimsRevision int64
	sourceDigest           oidcauth.SubjectDigest
	targetDigest           oidcauth.SubjectDigest
}

type planSpec struct {
	manifest         transitionManifest
	manifestSHA256   string
	migrationID      publicid.ID
	deploymentID     deployment.ID
	actorPrincipalID identity.PrincipalID
	sourceProviderID oidcauth.ProviderID
	targetProviderID oidcauth.ProviderID
	sourceKey        oidcauth.SubjectKey
	targetKey        oidcauth.SubjectKey
	mappings         []plannedMapping
}

func loadPlanSpec(ctx context.Context, options rawOptions, lookup config.LookupFunc) (planSpec, error) {
	if ctx == nil || ctx.Err() != nil || lookup == nil {
		return planSpec{}, errInvalidInput
	}
	contents, err := readProtectedFile(ctx, options.manifestPath, maximumManifestBytes)
	if err != nil {
		return planSpec{}, errInvalidInput
	}
	defer clear(contents)
	hash := sha256.Sum256(contents)
	manifestHash := hex.EncodeToString(hash[:])
	if manifestHash != options.expectedManifestHash {
		return planSpec{}, errInvalidInput
	}
	manifest, err := parseManifest(contents)
	if err != nil {
		return planSpec{}, err
	}
	expectedConfirmation := strings.Join([]string{
		manifest.MigrationID,
		manifest.DeploymentID,
		manifest.Source.ProviderID,
		manifest.Target.ProviderID,
		manifestHash,
	}, "/")
	confirmation, found := lookup(envConfirmation)
	if !found || confirmation != expectedConfirmation {
		return planSpec{}, errInvalidInput
	}
	sourceKey, err := loadSubjectKey(ctx, manifest.Source.SubjectKeyID, options.sourceKeyPath)
	if err != nil {
		return planSpec{}, errInvalidInput
	}
	targetKey, err := loadSubjectKey(ctx, manifest.Target.SubjectKeyID, options.targetKeyPath)
	if err != nil {
		return planSpec{}, errInvalidInput
	}
	return buildPlanSpec(manifest, manifestHash, sourceKey, targetKey)
}

func parseManifest(contents []byte) (transitionManifest, error) {
	if len(contents) == 0 || len(contents) > maximumManifestBytes || rejectDuplicateJSONNames(contents) != nil {
		return transitionManifest{}, errInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	manifest := transitionManifest{}
	if err := decoder.Decode(&manifest); err != nil || requireJSONEOF(decoder) != nil || !manifest.valid() {
		return transitionManifest{}, errInvalidInput
	}
	return manifest, nil
}

func (manifest transitionManifest) valid() bool {
	if manifest.SchemaVersion != manifestSchemaVersion || len(manifest.Mappings) == 0 ||
		len(manifest.Mappings) > maximumMappings ||
		manifest.ExpectedActiveSourceSubjects != int64(len(manifest.Mappings)) ||
		manifest.ExpectedActiveSessions < 0 || manifest.ExpectedActiveSessions > maximumActiveSessions ||
		manifest.ExpectedOpenAuthTransactions < 0 ||
		manifest.ExpectedOpenAuthTransactions > maximumOpenAuthTransactions ||
		!manifest.Source.valid() || !manifest.Target.valid() ||
		manifest.Source.ProviderID == manifest.Target.ProviderID ||
		manifest.Source.Issuer == manifest.Target.Issuer {
		return false
	}
	if _, err := publicid.Parse(manifest.MigrationID); err != nil {
		return false
	}
	if _, err := deployment.ParseID(manifest.DeploymentID); err != nil {
		return false
	}
	if _, err := identity.ParsePrincipalID(manifest.ActorPrincipalID); err != nil {
		return false
	}
	sourceIDs := make(map[string]struct{}, len(manifest.Mappings))
	principalIDs := make(map[string]struct{}, len(manifest.Mappings))
	targetSubjects := make(map[string]struct{}, len(manifest.Mappings))
	previousID := ""
	for _, mapping := range manifest.Mappings {
		if !mapping.valid() || previousID >= mapping.SourceSubjectID {
			return false
		}
		if _, duplicate := sourceIDs[mapping.SourceSubjectID]; duplicate {
			return false
		}
		if _, duplicate := principalIDs[mapping.PrincipalID]; duplicate {
			return false
		}
		if _, duplicate := targetSubjects[mapping.TargetSubject]; duplicate {
			return false
		}
		sourceIDs[mapping.SourceSubjectID] = struct{}{}
		principalIDs[mapping.PrincipalID] = struct{}{}
		targetSubjects[mapping.TargetSubject] = struct{}{}
		previousID = mapping.SourceSubjectID
	}
	return true
}

func (provider providerReference) valid() bool {
	if _, err := oidcauth.ParseProviderID(provider.ProviderID); err != nil {
		return false
	}
	if !validBoundedText(provider.Issuer, 2048) ||
		!validKeyID(provider.SubjectKeyID) ||
		!validPositive(provider.ExpectedGeneration) ||
		!validPositive(provider.ExpectedGenerationVersion) ||
		!validPositive(provider.ExpectedProviderVersion) {
		return false
	}
	return strings.HasPrefix(provider.Issuer, "https://")
}

func (mapping subjectMapping) valid() bool {
	if _, err := publicid.Parse(mapping.SourceSubjectID); err != nil {
		return false
	}
	if _, err := identity.ParsePrincipalID(mapping.PrincipalID); err != nil {
		return false
	}
	return validPositive(mapping.ExpectedSourceVersion) &&
		validPositive(mapping.ExpectedClaimsRevision) &&
		validOpaqueSubject(mapping.SourceSubject) && validOpaqueSubject(mapping.TargetSubject)
}

func buildPlanSpec(
	manifest transitionManifest,
	manifestHash string,
	sourceKey oidcauth.SubjectKey,
	targetKey oidcauth.SubjectKey,
) (planSpec, error) {
	migrationID, migrationErr := publicid.Parse(manifest.MigrationID)
	deploymentID, deploymentErr := deployment.ParseID(manifest.DeploymentID)
	actorID, actorErr := identity.ParsePrincipalID(manifest.ActorPrincipalID)
	sourceProviderID, sourceErr := oidcauth.ParseProviderID(manifest.Source.ProviderID)
	targetProviderID, targetErr := oidcauth.ParseProviderID(manifest.Target.ProviderID)
	if migrationErr != nil || deploymentErr != nil || actorErr != nil || sourceErr != nil || targetErr != nil ||
		!validSHA256(manifestHash) {
		return planSpec{}, errInvalidInput
	}
	spec := planSpec{
		manifest: manifest, manifestSHA256: manifestHash,
		migrationID: migrationID, deploymentID: deploymentID, actorPrincipalID: actorID,
		sourceProviderID: sourceProviderID, targetProviderID: targetProviderID,
		sourceKey: sourceKey, targetKey: targetKey,
		mappings: make([]plannedMapping, 0, len(manifest.Mappings)),
	}
	for _, mapping := range manifest.Mappings {
		sourceSubjectID, err := publicid.Parse(mapping.SourceSubjectID)
		if err != nil {
			return planSpec{}, errInvalidInput
		}
		principalID, err := identity.ParsePrincipalID(mapping.PrincipalID)
		if err != nil {
			return planSpec{}, errInvalidInput
		}
		sourceDigest, err := oidcauth.NewSubjectMigrationDigest(
			deploymentID, sourceProviderID, sourceKey,
			manifest.Source.Issuer, mapping.SourceSubject,
		)
		if err != nil {
			return planSpec{}, errInvalidInput
		}
		targetDigest, err := oidcauth.NewSubjectMigrationDigest(
			deploymentID, targetProviderID, targetKey,
			manifest.Target.Issuer, mapping.TargetSubject,
		)
		if err != nil {
			return planSpec{}, errInvalidInput
		}
		spec.mappings = append(spec.mappings, plannedMapping{
			sourceSubjectID: sourceSubjectID, principalID: principalID,
			expectedSourceVersion:  mapping.ExpectedSourceVersion,
			expectedClaimsRevision: mapping.ExpectedClaimsRevision,
			sourceDigest:           sourceDigest, targetDigest: targetDigest,
		})
	}
	return spec, nil
}

func loadSubjectKey(ctx context.Context, id, path string) (oidcauth.SubjectKey, error) {
	keyID, err := oidcauth.NewDigestKeyID(id)
	if err != nil {
		return oidcauth.SubjectKey{}, errInvalidInput
	}
	contents, err := readProtectedFile(ctx, path, 45)
	if err != nil {
		return oidcauth.SubjectKey{}, errInvalidInput
	}
	defer clear(contents)
	contents = bytes.TrimSuffix(contents, []byte("\r\n"))
	contents = bytes.TrimSuffix(contents, []byte("\n"))
	if len(contents) != 43 {
		return oidcauth.SubjectKey{}, errInvalidInput
	}
	material := make([]byte, 32)
	defer clear(material)
	decoded, err := base64.RawURLEncoding.Strict().Decode(material, contents)
	if err != nil || decoded != len(material) {
		return oidcauth.SubjectKey{}, errInvalidInput
	}
	return oidcauth.NewSubjectKey(keyID, material)
}

func readProtectedFile(ctx context.Context, path string, maximum int64) (result []byte, resultErr error) {
	if ctx == nil || ctx.Err() != nil || path == "" || len(path) > 4096 ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 {
		return nil, errInvalidInput
	}
	beforeReference, err := os.Lstat(path)
	if err != nil || !validProtectedInfo(beforeReference, maximum) {
		return nil, errInvalidInput
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, errInvalidInput
	}
	defer func() {
		if root.Close() != nil || ctx.Err() != nil {
			resultErr = errInvalidInput
		}
		if resultErr != nil {
			clear(result)
			result = nil
		}
	}()
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, errInvalidInput
	}
	before, statErr := file.Stat()
	if statErr != nil || !validProtectedInfo(before, maximum) || !os.SameFile(beforeReference, before) {
		_ = file.Close()
		return nil, errInvalidInput
	}
	result, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	after, afterErr := file.Stat()
	current, currentErr := os.Lstat(path)
	closeErr := file.Close()
	if readErr != nil || afterErr != nil || currentErr != nil || closeErr != nil ||
		!unchangedProtectedInfo(before, after, maximum) ||
		!unchangedProtectedInfo(after, current, maximum) || int64(len(result)) != before.Size() ||
		ctx.Err() != nil {
		return result, errInvalidInput
	}
	return result, nil
}

func validProtectedInfo(info os.FileInfo, maximum int64) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return false
	}
	mode := info.Mode()
	return mode == 0o400 || mode == 0o600 || mode == 0o440 || mode == 0o640
}

func unchangedProtectedInfo(before, after os.FileInfo, maximum int64) bool {
	return validProtectedInfo(before, maximum) && validProtectedInfo(after, maximum) &&
		os.SameFile(before, after) && before.Mode() == after.Mode() && before.Size() == after.Size() &&
		before.ModTime().Equal(after.ModTime())
}

func rejectDuplicateJSONNames(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return errInvalidInput
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		names := make(map[string]struct{})
		for decoder.More() {
			nameToken, nameErr := decoder.Token()
			name, ok := nameToken.(string)
			if nameErr != nil || !ok {
				return errInvalidInput
			}
			if _, duplicate := names[name]; duplicate {
				return errInvalidInput
			}
			names[name] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errInvalidInput
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errInvalidInput
		}
	default:
		return errInvalidInput
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errInvalidInput
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func validPositive(value int64) bool { return value > 0 }

func validKeyID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		letterOrDigit := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
		if !letterOrDigit && (index == 0 || !strings.ContainsRune("._:-", character)) {
			return false
		}
	}
	return true
}

func validBoundedText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validOpaqueSubject(value string) bool {
	if value == "" || len(value) > 255 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func (spec *planSpec) clear() {
	if spec == nil {
		return
	}
	for index := range spec.manifest.Mappings {
		spec.manifest.Mappings[index].SourceSubject = ""
		spec.manifest.Mappings[index].TargetSubject = ""
	}
	spec.manifest.Source.Issuer = ""
	spec.manifest.Target.Issuer = ""
	spec.mappings = nil
	spec.sourceKey = oidcauth.SubjectKey{}
	spec.targetKey = oidcauth.SubjectKey{}
}

func (planSpec) String() string { return "[REDACTED]" }

func (planSpec) GoString() string { return "identitysubjecttransition.planSpec([REDACTED])" }

func (transitionManifest) String() string { return "[REDACTED]" }

func (transitionManifest) GoString() string {
	return "identitysubjecttransition.transitionManifest([REDACTED])"
}

func (transitionManifest) MarshalJSON() ([]byte, error) { return nil, errInvalidInput }

func (planSpec) MarshalJSON() ([]byte, error) { return nil, errInvalidInput }
