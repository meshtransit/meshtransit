package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
)

const accountSessionSecretBytes = 32

type stagedBearerFile struct {
	root *os.Root
	name string
}

func prepareBearer(
	spec seedSpec,
	database databaseSettings,
	recoveryEpoch int64,
	entropy io.Reader,
) (accountsession.Token, accountsession.Digest, *stagedBearerFile, error) {
	if !spec.isValid() || !validPositiveInt64(recoveryEpoch) || entropy == nil {
		return accountsession.Token{}, accountsession.Digest{}, nil, errInvalidInput
	}
	keyring, err := loadSessionKeyring(database)
	if err != nil {
		return accountsession.Token{}, accountsession.Digest{}, nil, err
	}
	secret := make([]byte, accountSessionSecretBytes)
	defer clear(secret)
	if _, err := io.ReadFull(entropy, secret); err != nil {
		return accountsession.Token{}, accountsession.Digest{}, nil,
			fmt.Errorf("read account session entropy: %w", err)
	}
	allZero := true
	for _, value := range secret {
		allZero = allZero && value == 0
	}
	if allZero {
		return accountsession.Token{}, accountsession.Digest{}, nil, errInvalidInput
	}
	rawToken := "mtas1." + spec.deploymentID.String() + "." +
		fmt.Sprintf("%d", recoveryEpoch) + "." +
		base64.RawURLEncoding.EncodeToString(secret)
	token, err := accountsession.ParseToken(rawToken)
	if err != nil {
		return accountsession.Token{}, accountsession.Digest{}, nil, errInvalidInput
	}
	digests, err := keyring.Digests(token)
	if err != nil || len(digests) != 1 {
		return accountsession.Token{}, accountsession.Digest{}, nil, errInvalidInput
	}
	staged, err := stageBearerFile(spec.tokenOutput, []byte(rawToken+"\n"))
	if err != nil {
		return accountsession.Token{}, accountsession.Digest{}, nil, err
	}
	return token, digests[0], staged, nil
}

func loadSessionKeyring(database databaseSettings) (*accountsession.Keyring, error) {
	encoded, err := database.digestKeyFile.Read()
	if err != nil {
		return nil, errors.New("read account session digest key")
	}
	material, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(material) != encoded {
		clear(material)
		return nil, errors.New("decode account session digest key")
	}
	defer clear(material)
	key, err := accountsession.NewDigestKey(database.digestKeyID, material)
	if err != nil {
		return nil, errors.New("construct account session digest key")
	}
	keyring, err := accountsession.NewKeyring(key)
	if err != nil {
		return nil, errors.New("construct account session keyring")
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
