// Package secretstore protects persistent secret records with a bounded,
// authenticated envelope key supplied by the host platform.
package secretstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// KeySize is the required AES-256 envelope-key size.
	KeySize = 32

	credentialMagic      = "meshtransit-keyset\x00"
	credentialVersion    = byte(1)
	credentialKeyCount   = byte(2)
	credentialHeaderSize = len(credentialMagic) + 2
	credentialSize       = credentialHeaderSize + int(credentialKeyCount)*KeySize
	maxKeyFileBytes      = credentialSize + 1
	maximumKeys          = int(credentialKeyCount)
	systemdRoot          = "/run/credentials"

	// MaxCredentialSize bounds decrypted platform credential input.
	MaxCredentialSize = credentialSize
)

var (
	// ErrKeyMissing indicates that the platform did not provide an envelope key.
	ErrKeyMissing = errors.New("secretstore: key missing")
	// ErrKeyLocked indicates that the service identity cannot read the envelope key.
	ErrKeyLocked = errors.New("secretstore: key locked")
	// ErrKeyInvalid indicates malformed key material or unsafe key-file metadata.
	ErrKeyInvalid = errors.New("secretstore: key invalid")
	// ErrClosed indicates use after the protector released its key material.
	ErrClosed = errors.New("secretstore: protector closed")
	// ErrAuthentication indicates that protected bytes failed authentication.
	ErrAuthentication = errors.New("secretstore: authentication failed")
)

// Protector encrypts and authenticates bounded records with AES-256-GCM.
// It owns a defensive copy of the supplied key and clears that copy on Close.
type Protector struct {
	mu       sync.RWMutex
	keys     [maximumKeys][KeySize]byte
	keyCount int
	random   io.Reader
	isClosed bool
}

// New validates and takes a defensive copy of one envelope key.
func New(key []byte) (*Protector, error) {
	return newWithRandom(key, nil, rand.Reader)
}

// NewWithFallback creates a protector that seals with active and can open
// records protected by either active or fallback. The fallback is never used
// for new ciphertext.
func NewWithFallback(active, fallback []byte) (*Protector, error) {
	return newWithRandom(active, fallback, rand.Reader)
}

func newWithRandom(active, fallback []byte, random io.Reader) (*Protector, error) {
	if len(active) != KeySize || (fallback != nil && len(fallback) != KeySize) {
		return nil, ErrKeyInvalid
	}
	if fallback != nil && subtle.ConstantTimeCompare(active, fallback) == 1 {
		return nil, ErrKeyInvalid
	}
	if random == nil {
		return nil, errors.New("secretstore: randomness source is required")
	}

	protector := &Protector{keyCount: 1, random: random}
	copy(protector.keys[0][:], active)
	if fallback != nil {
		copy(protector.keys[1][:], fallback)
		protector.keyCount = 2
	}

	return protector, nil
}

// EncodeKeySet returns the strict credential representation used while one
// fallback key is retained during rotation. The caller owns and should clear
// the returned bytes after use.
func EncodeKeySet(active, fallback []byte) ([]byte, error) {
	if len(active) != KeySize || len(fallback) != KeySize ||
		subtle.ConstantTimeCompare(active, fallback) == 1 {
		return nil, ErrKeyInvalid
	}

	encoded := make([]byte, credentialSize)
	copy(encoded, credentialMagic)
	encoded[len(credentialMagic)] = credentialVersion
	encoded[len(credentialMagic)+1] = credentialKeyCount
	offset := credentialHeaderSize
	copy(encoded[offset:offset+KeySize], active)
	copy(encoded[offset+KeySize:], fallback)

	return encoded, nil
}

// NewFromCredential accepts either the legacy raw key or the bounded key-set
// representation used during rotation.
func NewFromCredential(encoded []byte) (*Protector, error) {
	return newFromCredentialWithRandom(encoded, rand.Reader)
}

func newFromCredentialWithRandom(encoded []byte, random io.Reader) (*Protector, error) {
	if len(encoded) == KeySize {
		return newWithRandom(encoded, nil, random)
	}
	if len(encoded) != credentialSize ||
		string(encoded[:len(credentialMagic)]) != credentialMagic ||
		encoded[len(credentialMagic)] != credentialVersion ||
		encoded[len(credentialMagic)+1] != credentialKeyCount {
		return nil, ErrKeyInvalid
	}

	offset := credentialHeaderSize
	return newWithRandom(
		encoded[offset:offset+KeySize],
		encoded[offset+KeySize:],
		random,
	)
}

// Load reads an owner-only key from an absolute, non-symlink path.
func Load(path string) (*Protector, error) {
	return load(path, validateOwnerOnly)
}

// LoadSystemdCredential reads a key from a systemd private credential mount.
// The mount uses root-owned mode 0440 files and isolates access per service.
func LoadSystemdCredential(path string) (*Protector, error) {
	if !isSystemdCredentialPath(path) {
		return nil, fmt.Errorf("%w: path is outside a systemd service credential mount", ErrKeyInvalid)
	}

	return load(path, validateSystemdCredentialMetadata)
}

func load(path string, validateMetadata func(os.FileInfo) error) (*Protector, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return nil, fmt.Errorf("%w: key path must be an absolute file", ErrKeyInvalid)
	}
	if validateMetadata == nil {
		return nil, fmt.Errorf("%w: key metadata policy is required", ErrKeyInvalid)
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrKeyMissing
	}
	if errors.Is(err, os.ErrPermission) {
		return nil, ErrKeyLocked
	}
	if err != nil {
		return nil, fmt.Errorf("inspecting secret-store key: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: key must be a regular file, not a link", ErrKeyInvalid)
	}
	if !validCredentialSize(info.Size()) {
		return nil, fmt.Errorf("%w: credential has an unsupported size", ErrKeyInvalid)
	}
	if err := validateMetadata(info); err != nil {
		return nil, err
	}

	file, err := os.Open(path) //nolint:gosec // The path is absolute and validated above.
	if errors.Is(err, os.ErrPermission) {
		return nil, ErrKeyLocked
	}
	if err != nil {
		return nil, fmt.Errorf("opening secret-store key: %w", err)
	}
	defer func() { _ = file.Close() }()

	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspecting opened secret-store key: %w", err)
	}
	if !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: key changed while opening", ErrKeyInvalid)
	}
	if !validCredentialSize(openedInfo.Size()) {
		return nil, fmt.Errorf("%w: opened key metadata is unsafe", ErrKeyInvalid)
	}
	if err := validateMetadata(openedInfo); err != nil {
		return nil, err
	}

	encoded, err := io.ReadAll(io.LimitReader(file, int64(maxKeyFileBytes)))
	if err != nil {
		return nil, fmt.Errorf("reading secret-store key: %w", err)
	}
	defer clear(encoded)
	if len(encoded) != int(openedInfo.Size()) || !validCredentialSize(int64(len(encoded))) {
		return nil, fmt.Errorf("%w: credential changed while reading", ErrKeyInvalid)
	}

	protector, err := NewFromCredential(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: credential format", err)
	}

	return protector, nil
}

func validCredentialSize(size int64) bool {
	return size == KeySize || size == int64(credentialSize)
}

func validateOwnerOnly(info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: key permissions are too broad", ErrKeyInvalid)
	}

	return nil
}

func isSystemdCredentialPath(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	cleaned := filepath.Clean(path)
	relative, err := filepath.Rel(systemdRoot, cleaned)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	parts := strings.Split(relative, string(filepath.Separator))

	return len(parts) == 2 && strings.HasSuffix(parts[0], ".service") && parts[1] != ""
}

// Seal returns nonce-prefixed authenticated ciphertext bound to additionalData.
func (p *Protector) Seal(
	ctx context.Context,
	plaintext []byte,
	additionalData []byte,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("protecting secret record: %w", err)
	}
	if len(additionalData) == 0 {
		return nil, errors.New("secretstore: additional data is required")
	}
	if p == nil {
		return nil, ErrClosed
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.isClosed {
		return nil, ErrClosed
	}

	aead, err := newGCM(p.keys[0][:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(p.random, nonce); err != nil {
		return nil, fmt.Errorf("reading secret-record randomness: %w", err)
	}

	return aead.Seal(nonce, nonce, plaintext, additionalData), nil
}

// Open authenticates and decrypts one nonce-prefixed record.
func (p *Protector) Open(
	ctx context.Context,
	protected []byte,
	additionalData []byte,
) ([]byte, error) {
	plaintext, _, err := p.OpenWithRotation(ctx, protected, additionalData)

	return plaintext, err
}

// OpenWithRotation authenticates and decrypts one record and reports whether
// it was protected by the fallback key and should be sealed again.
func (p *Protector) OpenWithRotation(
	ctx context.Context,
	protected []byte,
	additionalData []byte,
) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, fmt.Errorf("opening secret record: %w", err)
	}
	if len(additionalData) == 0 {
		return nil, false, errors.New("secretstore: additional data is required")
	}
	if p == nil {
		return nil, false, ErrClosed
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.isClosed {
		return nil, false, ErrClosed
	}

	for index := 0; index < p.keyCount; index++ {
		aead, err := newGCM(p.keys[index][:])
		if err != nil {
			return nil, false, err
		}
		if len(protected) < aead.NonceSize()+aead.Overhead() {
			return nil, false, ErrAuthentication
		}
		nonce := protected[:aead.NonceSize()]
		ciphertext := protected[aead.NonceSize():]
		plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
		if err == nil {
			return plaintext, index != 0, nil
		}
	}

	return nil, false, ErrAuthentication
}

// Close clears the in-memory envelope key. It is safe to call more than once.
func (p *Protector) Close() error {
	if p == nil {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.isClosed {
		for index := range p.keys {
			clear(p.keys[index][:])
		}
		p.keyCount = 0
		p.isClosed = true
	}

	return nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating secret-record cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating secret-record aead: %w", err)
	}

	return aead, nil
}
