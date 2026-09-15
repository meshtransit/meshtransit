package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/meshtransit/meshtransit/internal/enrollment"
)

const credentialTokenBytes = 32

type stagedBearerFile struct {
	root *os.Root
	name string
}

func prepareCredential(
	spec issueSpec,
	database databaseSettings,
	credentialID enrollment.CredentialID,
	recoveryEpoch int64,
	entropy io.Reader,
) (enrollment.CredentialDigest, *stagedBearerFile, error) {
	if !spec.isValid() || !credentialID.IsValid() || !validPositiveInt64(recoveryEpoch) ||
		entropy == nil {
		return enrollment.CredentialDigest{}, nil, errInvalidInput
	}
	keyring, err := loadCredentialKeyring(database)
	if err != nil {
		return enrollment.CredentialDigest{}, nil, err
	}
	var secret [credentialTokenBytes]byte
	defer clear(secret[:])
	if _, err := io.ReadFull(entropy, secret[:]); err != nil {
		return enrollment.CredentialDigest{}, nil,
			fmt.Errorf("read enrollment credential entropy: %w", err)
	}
	token, err := enrollment.NewCredentialToken(secret)
	if err != nil {
		return enrollment.CredentialDigest{}, nil, errInvalidInput
	}
	presentation, err := enrollment.NewCredentialPresentation(credentialID, token)
	if err != nil {
		return enrollment.CredentialDigest{}, nil, errInvalidInput
	}
	digest, err := keyring.Digest(spec.deploymentID, recoveryEpoch, token)
	if err != nil {
		return enrollment.CredentialDigest{}, nil, errors.New("derive enrollment credential digest")
	}
	contents := []byte(presentation.Reveal() + "\n")
	defer clear(contents)
	staged, err := stageBearerFile(spec.tokenOutput, contents)
	if err != nil {
		return enrollment.CredentialDigest{}, nil, err
	}
	return digest, staged, nil
}

func loadCredentialKeyring(database databaseSettings) (*enrollment.CredentialKeyring, error) {
	encoded, err := database.digestKeyFile.Read()
	if err != nil {
		return nil, errors.New("read enrollment credential digest key")
	}
	material, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(material) != encoded {
		clear(material)
		return nil, errors.New("decode enrollment credential digest key")
	}
	defer clear(material)
	key, err := enrollment.NewDigestKey(database.digestKeyID, material)
	if err != nil {
		return nil, errors.New("construct enrollment credential digest key")
	}
	keyring, err := enrollment.NewCredentialKeyring(key)
	if err != nil {
		return nil, errors.New("construct enrollment credential keyring")
	}
	return keyring, nil
}

func stageBearerFile(path string, contents []byte) (_ *stagedBearerFile, resultErr error) {
	if !validTokenOutputPath(path) || len(contents) == 0 {
		return nil, errInvalidInput
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("open bearer output directory: %w", err)
	}
	name := filepath.Base(path)
	owned := false
	defer func() {
		if owned {
			return
		}
		resultErr = errors.Join(resultErr, root.Close())
	}()
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create bearer output: %w", err)
	}
	fileClosed := false
	defer func() {
		if !fileClosed {
			resultErr = errors.Join(resultErr, file.Close())
		}
	}()
	defer func() {
		if !owned {
			resultErr = errors.Join(resultErr, root.Remove(name))
		}
	}()
	information, err := file.Stat()
	if err != nil || !information.Mode().IsRegular() || information.Mode().Perm() != 0o600 {
		return nil, errors.New("bearer output is not a private regular file")
	}
	if _, err := file.Write(contents); err != nil {
		return nil, fmt.Errorf("write bearer output: %w", err)
	}
	if err := file.Sync(); err != nil {
		return nil, fmt.Errorf("sync bearer output: %w", err)
	}
	closeErr := file.Close()
	fileClosed = true
	if closeErr != nil {
		return nil, fmt.Errorf("close bearer output: %w", closeErr)
	}
	owned = true
	return &stagedBearerFile{root: root, name: name}, nil
}

func (file *stagedBearerFile) keep() error {
	if file == nil || file.root == nil || file.name == "" {
		return errInvalidInput
	}
	err := file.root.Close()
	file.root = nil
	return err
}

func (file *stagedBearerFile) discard() error {
	if file == nil || file.root == nil || file.name == "" {
		return nil
	}
	err := errors.Join(file.root.Remove(file.name), file.root.Close())
	file.root = nil
	return err
}
