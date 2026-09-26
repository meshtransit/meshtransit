package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	maximumPatchBytes      = 16 << 20
	maximumEvidenceBytes   = 512 << 20
	maximumBinaryBytes     = 1 << 30
	maximumGitOutputBytes  = 64 << 20
	maximumSourceFileBytes = 256 << 20
	maximumSourceTreeBytes = 2 << 30
	maximumSourceTreeFiles = 100_000
	sourceTreeDigestDomain = "meshtransit-dex-source-tree-v1"
	meshcoreModulePath     = "github.com/meshtransit/meshtransit"
)

var (
	errVerification       = errors.New("dex artifact verifier: verification failed")
	errCommandOutputLimit = errors.New("dex artifact verifier: command output limit exceeded")
)

type gitRunner struct {
	executable  string
	environment []string
}

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining <= 0 {
		return 0, errCommandOutputLimit
	}
	if len(data) > remaining {
		_, _ = buffer.buffer.Write(data[:remaining])
		return remaining, errCommandOutputLimit
	}
	return buffer.buffer.Write(data)
}

func verifyArtifact(ctx context.Context, options rawOptions) (report verificationReport, resultErr error) {
	if ctx == nil {
		return verificationReport{}, errVerification
	}
	loaded, err := loadManifest(options.manifestPath)
	if err != nil {
		return verificationReport{}, errVerification
	}
	defer func() {
		if closeErr := loaded.close(); resultErr == nil && closeErr != nil {
			resultErr = errVerification
			report = verificationReport{}
		}
	}()

	sourcePath, err := directoryAbsolutePath(options.sourcePath)
	if err != nil {
		return verificationReport{}, errVerification
	}
	binaryPath, err := executableAbsolutePath(options.binaryPath)
	if err != nil {
		return verificationReport{}, errVerification
	}
	preparedRoot := ""
	if options.preparedRootPath != "" {
		preparedRoot, err = emptyDirectoryAbsolutePath(options.preparedRootPath)
		if err != nil {
			return verificationReport{}, errVerification
		}
	}
	workspaceModule := ""
	if options.workspaceModulePath != "" {
		workspaceModule, err = validateWorkspaceModule(
			options.workspaceModulePath,
			loaded.manifest.Upstream.ModuleVersion,
			loaded.manifest.Build.GoVersion,
		)
		if err != nil {
			return verificationReport{}, errVerification
		}
	}

	manifest := loaded.manifest
	patchPaths, err := verifyManifestFiles(loaded.root, manifest)
	if err != nil {
		return verificationReport{}, errVerification
	}
	defer func() {
		if cleanupErr := os.RemoveAll(patchPaths[0]); resultErr == nil && cleanupErr != nil {
			resultErr = errVerification
			report = verificationReport{}
		}
	}()
	binaryDigest, err := digestRegularFile(binaryPath, maximumBinaryBytes)
	if err != nil || binaryDigest != manifest.Build.BinarySHA256 {
		return verificationReport{}, errVerification
	}

	runner, err := newGitRunner()
	if err != nil {
		return verificationReport{}, errVerification
	}
	sourceDigest, err := verifyPatchedSourceTo(ctx, runner, sourcePath, manifest, patchPaths, preparedRoot)
	if err != nil || sourceDigest != manifest.SourceTreeSHA256 {
		return verificationReport{}, errVerification
	}
	workspacePrepared := false
	if workspaceModule != "" {
		if err := writeGoWorkspace(preparedRoot, workspaceModule, manifest.Build.GoVersion); err != nil {
			_ = os.RemoveAll(filepath.Join(preparedRoot, "source"))
			_ = os.Remove(filepath.Join(preparedRoot, "go.work"))
			return verificationReport{}, errVerification
		}
		workspacePrepared = true
	}

	return verificationReport{
		SchemaVersion:         manifest.SchemaVersion,
		UpstreamVersion:       manifest.Upstream.Version,
		UpstreamCommit:        manifest.Upstream.Commit,
		UpstreamModuleVersion: manifest.Upstream.ModuleVersion,
		PatchCount:            len(manifest.Patches),
		SourceTreeSHA256:      sourceDigest,
		BinarySHA256:          binaryDigest,
		SourcePrepared:        preparedRoot != "",
		WorkspacePrepared:     workspacePrepared,
		Verified:              true,
	}, nil
}

func verifyManifestFiles(root *os.Root, manifest artifactManifest) ([]string, error) {
	if root == nil {
		return nil, errVerification
	}
	temporaryDirectory, err := os.MkdirTemp("", "meshtransit-dex-patches-")
	if err != nil {
		return nil, errVerification
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(temporaryDirectory)
		}
	}()

	patchPaths := make([]string, 0, len(manifest.Patches)+1)
	patchPaths = append(patchPaths, temporaryDirectory)
	for index, patch := range manifest.Patches {
		contents, err := readRootRegularFile(root, patch.Path, maximumPatchBytes)
		if err != nil || digestBytes(contents) != patch.SHA256 {
			return nil, errVerification
		}
		copyPath := filepath.Join(temporaryDirectory, fmt.Sprintf("patch-%02d.patch", index+1))
		if err := os.WriteFile(copyPath, contents, 0o600); err != nil {
			return nil, errVerification
		}
		patchPaths = append(patchPaths, copyPath)
	}

	references := [...]fileReference{
		manifest.Evidence.LicenseInventory,
		manifest.Evidence.SBOM,
		manifest.Evidence.VulnerabilityReport,
		manifest.Evidence.QualificationReport,
	}
	for _, reference := range references {
		digest, err := digestRootRegularFile(root, reference.Path, maximumEvidenceBytes)
		if err != nil || digest != reference.SHA256 {
			return nil, errVerification
		}
	}
	cleanup = false
	return patchPaths, nil
}

func newGitRunner() (gitRunner, error) {
	executable, err := exec.LookPath("git")
	if err != nil {
		return gitRunner{}, errVerification
	}
	environment := []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"LANG=C",
		"LC_ALL=C",
	}
	for _, key := range [...]string{"PATH", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT"} {
		if value, found := os.LookupEnv(key); found {
			environment = append(environment, key+"="+value)
		}
	}
	return gitRunner{executable: executable, environment: environment}, nil
}

func (runner gitRunner) output(ctx context.Context, args ...string) ([]byte, error) {
	if ctx == nil || runner.executable == "" {
		return nil, errVerification
	}
	arguments := append([]string{
		"-c", "core.hooksPath=" + os.DevNull,
		"-c", "protocol.file.allow=always",
	}, args...)
	command := exec.CommandContext(ctx, runner.executable, arguments...) // #nosec G204 -- executable is resolved locally and every argument is passed without a shell.
	command.Env = runner.environment
	stdout := &boundedBuffer{limit: maximumGitOutputBytes}
	stderr := &boundedBuffer{limit: maximumGitOutputBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("run git operation: %w", errVerification)
	}
	return bytes.Clone(stdout.buffer.Bytes()), nil
}

func verifyPatchedSource(
	ctx context.Context,
	runner gitRunner,
	sourcePath string,
	manifest artifactManifest,
	patchPaths []string,
) (digest string, resultErr error) {
	return verifyPatchedSourceTo(ctx, runner, sourcePath, manifest, patchPaths, "")
}

func verifyPatchedSourceTo(
	ctx context.Context,
	runner gitRunner,
	sourcePath string,
	manifest artifactManifest,
	patchPaths []string,
	preparedRoot string,
) (digest string, resultErr error) {
	if len(patchPaths) != len(manifest.Patches)+1 {
		return "", errVerification
	}

	remote, err := runner.output(ctx, "-C", sourcePath, "remote", "get-url", "origin")
	if err != nil || strings.TrimSpace(string(remote)) != manifest.Upstream.Repository {
		return "", errVerification
	}
	tagCommit, err := runner.output(
		ctx,
		"-C", sourcePath,
		"rev-parse", "--verify", "refs/tags/"+manifest.Upstream.Version+"^{commit}",
	)
	if err != nil || strings.TrimSpace(string(tagCommit)) != manifest.Upstream.Commit {
		return "", errVerification
	}
	commitTimestamp, err := runner.output(
		ctx, "-C", sourcePath, "show", "-s", "--format=%ct", manifest.Upstream.Commit,
	)
	if err != nil {
		return "", errVerification
	}
	seconds, err := strconv.ParseInt(strings.TrimSpace(string(commitTimestamp)), 10, 64)
	if err != nil {
		return "", errVerification
	}
	expectedModuleVersion, err := moduleVersionForCommit(manifest.Upstream.Commit, seconds)
	if err != nil || expectedModuleVersion != manifest.Upstream.ModuleVersion {
		return "", errVerification
	}

	checkoutRoot := preparedRoot
	removeCheckoutRoot := false
	if checkoutRoot == "" {
		checkoutRoot, err = os.MkdirTemp("", "meshtransit-dex-source-")
		if err != nil {
			return "", errVerification
		}
		removeCheckoutRoot = true
	} else {
		entries, err := os.ReadDir(checkoutRoot)
		if err != nil || len(entries) != 0 {
			return "", errVerification
		}
	}
	checkout := filepath.Join(checkoutRoot, "source")
	removeCheckout := true
	defer func() {
		if removeCheckout {
			cleanupPath := checkout
			if removeCheckoutRoot {
				cleanupPath = checkoutRoot
			}
			if cleanupErr := os.RemoveAll(cleanupPath); resultErr == nil && cleanupErr != nil {
				resultErr = errVerification
				digest = ""
			}
		}
	}()
	if _, err := os.Lstat(checkout); err == nil || !os.IsNotExist(err) {
		return "", errVerification
	}
	if _, err := runner.output(
		ctx,
		"clone", "--quiet", "--no-checkout", "--no-hardlinks", "--local", "--",
		sourcePath, checkout,
	); err != nil {
		return "", errVerification
	}
	if _, err := runner.output(
		ctx,
		"-C", checkout, "checkout", "--quiet", "--detach", manifest.Upstream.Commit,
	); err != nil {
		return "", errVerification
	}
	status, err := runner.output(ctx, "-C", checkout, "status", "--porcelain=v1", "--untracked-files=all", "-z")
	if err != nil || len(status) != 0 {
		return "", errVerification
	}

	for _, patchPath := range patchPaths[1:] {
		if _, err := runner.output(
			ctx, "-C", checkout, "apply", "--check", "--whitespace=error-all", "--", patchPath,
		); err != nil {
			return "", errVerification
		}
		if _, err := runner.output(
			ctx, "-C", checkout, "apply", "--index", "--whitespace=error-all", "--", patchPath,
		); err != nil {
			return "", errVerification
		}
	}
	if _, err := runner.output(ctx, "-C", checkout, "diff", "--cached", "--check"); err != nil {
		return "", errVerification
	}
	worktreeDiff, err := runner.output(ctx, "-C", checkout, "diff", "--name-only", "-z")
	if err != nil || len(worktreeDiff) != 0 {
		return "", errVerification
	}
	untracked, err := runner.output(ctx, "-C", checkout, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil || len(untracked) != 0 {
		return "", errVerification
	}
	digest, err = sourceTreeDigest(ctx, runner, checkout)
	if err != nil {
		return "", errVerification
	}
	if preparedRoot != "" {
		if digest != manifest.SourceTreeSHA256 {
			return "", errVerification
		}
		if err := os.RemoveAll(filepath.Join(checkout, ".git")); err != nil {
			return "", errVerification
		}
		removeCheckout = false
	}
	return digest, nil
}

func moduleVersionForCommit(commit string, unixSeconds int64) (string, error) {
	if !commitPattern.MatchString(commit) || unixSeconds <= 0 {
		return "", errVerification
	}
	timestamp := time.Unix(unixSeconds, 0).UTC().Format("20060102150405")
	return "v0.0.0-" + timestamp + "-" + commit[:12], nil
}

func validateWorkspaceModule(value, dexModuleVersion, goToolchain string) (string, error) {
	moduleRoot, err := directoryAbsolutePath(value)
	if err != nil {
		return "", errVerification
	}
	moduleFile := filepath.Join(moduleRoot, "go.mod")
	info, err := os.Lstat(moduleFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 0 || info.Size() > maximumManifestBytes {
		return "", errVerification
	}
	contents, err := readBoundedFile(moduleFile, maximumManifestBytes)
	if err != nil {
		return "", errVerification
	}

	moduleCount := 0
	goVersionCount := 0
	requireCount := 0
	expectedGoVersion := strings.TrimPrefix(goToolchain, "go")
	for _, rawLine := range strings.Split(string(contents), "\n") {
		line, _, _ := strings.Cut(rawLine, "//")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 2 && fields[0] == "module" && fields[1] == meshcoreModulePath {
			moduleCount++
		}
		if len(fields) == 2 && fields[0] == "go" && fields[1] == expectedGoVersion {
			goVersionCount++
		}
		if (len(fields) == 2 && fields[0] == dexUpstreamModule && fields[1] == dexModuleVersion) ||
			(len(fields) == 3 && fields[0] == "require" && fields[1] == dexUpstreamModule &&
				fields[2] == dexModuleVersion) {
			requireCount++
		}
		if hasDexReplacement(fields) {
			return "", errVerification
		}
	}
	if moduleCount != 1 || goVersionCount != 1 || requireCount != 1 {
		return "", errVerification
	}
	return moduleRoot, nil
}

func hasDexReplacement(fields []string) bool {
	arrow := -1
	for index, field := range fields {
		if field == "=>" {
			arrow = index
			break
		}
	}
	if arrow < 1 {
		return false
	}
	oldPathIndex := 0
	if fields[0] == "replace" {
		oldPathIndex = 1
	}
	if oldPathIndex >= arrow {
		return false
	}
	oldPath := fields[oldPathIndex]
	return oldPath == dexUpstreamModule || oldPath == dexUpstreamModule+"/api/v2"
}

func writeGoWorkspace(preparedRoot, moduleRoot, goToolchain string) error {
	if preparedRoot == "" || moduleRoot == "" || !goVersionPattern.MatchString(goToolchain) {
		return errVerification
	}
	sourceRoot := filepath.Join(preparedRoot, "source")
	apiRoot := filepath.Join(sourceRoot, "api", "v2")
	contents := "go " + strings.TrimPrefix(goToolchain, "go") + "\n\n" +
		"toolchain " + goToolchain + "\n\n" +
		"use (\n\t" + strconv.Quote(filepath.ToSlash(moduleRoot)) +
		"\n\t" + strconv.Quote(filepath.ToSlash(sourceRoot)) +
		"\n\t" + strconv.Quote(filepath.ToSlash(apiRoot)) + "\n)\n"
	workspacePath := filepath.Join(preparedRoot, "go.work")
	workspace, err := os.OpenFile(workspacePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path is within the validated empty preparation root.
	if err != nil {
		return errVerification
	}
	if _, err := workspace.WriteString(contents); err != nil {
		_ = workspace.Close()
		return errVerification
	}
	if err := workspace.Close(); err != nil {
		return errVerification
	}
	return nil
}

func sourceTreeDigest(ctx context.Context, runner gitRunner, checkout string) (string, error) {
	index, err := runner.output(ctx, "-C", checkout, "ls-files", "--stage", "-z")
	if err != nil || len(index) == 0 || index[len(index)-1] != 0 {
		return "", errVerification
	}
	records := bytes.Split(index[:len(index)-1], []byte{0})
	if len(records) == 0 || len(records) > maximumSourceTreeFiles {
		return "", errVerification
	}

	digest := sha256.New()
	if err := writeDigestField(digest, sourceTreeDigestDomain); err != nil {
		return "", errVerification
	}
	var totalBytes int64
	for _, record := range records {
		mode, filePath, err := parseIndexRecord(record)
		if err != nil {
			return "", errVerification
		}
		filesystemPath := filepath.FromSlash(filePath)
		if !filepath.IsLocal(filesystemPath) || path.Clean(filePath) != filePath {
			return "", errVerification
		}
		fullPath := filepath.Join(checkout, filesystemPath)
		contents, err := readIndexedFile(fullPath, mode)
		if err != nil {
			return "", errVerification
		}
		totalBytes += int64(len(contents))
		if totalBytes > maximumSourceTreeBytes {
			return "", errVerification
		}
		if err := writeDigestField(digest, mode); err != nil {
			return "", errVerification
		}
		if err := writeDigestField(digest, filePath); err != nil {
			return "", errVerification
		}
		if err := writeDigestField(digest, strconv.Itoa(len(contents))); err != nil {
			return "", errVerification
		}
		if _, err := digest.Write(contents); err != nil {
			return "", errVerification
		}
		if _, err := digest.Write([]byte{0}); err != nil {
			return "", errVerification
		}
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func parseIndexRecord(record []byte) (string, string, error) {
	tab := bytes.IndexByte(record, '\t')
	if tab <= 0 || tab == len(record)-1 {
		return "", "", errVerification
	}
	metadata := strings.Fields(string(record[:tab]))
	if len(metadata) != 3 || metadata[2] != "0" {
		return "", "", errVerification
	}
	mode := metadata[0]
	if mode != "100644" && mode != "100755" && mode != "120000" {
		return "", "", errVerification
	}
	return mode, string(record[tab+1:]), nil
}

func readIndexedFile(filePath, mode string) ([]byte, error) {
	info, err := os.Lstat(filePath)
	if err != nil {
		return nil, errVerification
	}
	if mode == "120000" {
		if info.Mode()&os.ModeSymlink == 0 {
			return nil, errVerification
		}
		target, err := os.Readlink(filePath)
		if err != nil || len(target) > maximumSourceFileBytes {
			return nil, errVerification
		}
		return []byte(target), nil
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximumSourceFileBytes {
		return nil, errVerification
	}
	return readBoundedFile(filePath, maximumSourceFileBytes)
}

func writeDigestField(digest hash.Hash, value string) error {
	if _, err := io.WriteString(digest, value); err != nil {
		return err
	}
	_, err := digest.Write([]byte{0})
	return err
}

func readRootRegularFile(root *os.Root, relativePath string, maximum int64) ([]byte, error) {
	if root == nil || !validRelativePath(relativePath) {
		return nil, errVerification
	}
	info, err := root.Lstat(relativePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 0 || info.Size() > maximum {
		return nil, errVerification
	}
	file, err := root.Open(relativePath)
	if err != nil {
		return nil, errVerification
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum || int64(len(data)) != info.Size() {
		return nil, errVerification
	}
	return data, nil
}

func digestRootRegularFile(root *os.Root, relativePath string, maximum int64) (string, error) {
	data, err := readRootRegularFile(root, relativePath, maximum)
	if err != nil {
		return "", err
	}
	return digestBytes(data), nil
}

func digestRegularFile(filePath string, maximum int64) (string, error) {
	info, err := os.Lstat(filePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 0 || info.Size() > maximum {
		return "", errVerification
	}
	file, err := os.Open(filePath) // #nosec G304 -- the path was validated as an absolute non-symlink regular file.
	if err != nil {
		return "", errVerification
	}
	defer func() { _ = file.Close() }()
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, maximum+1))
	if err != nil || written != info.Size() || written > maximum {
		return "", errVerification
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
