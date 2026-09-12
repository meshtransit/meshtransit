// Package secretstore protects persistent secret records with a bounded,
// authenticated envelope key supplied by the host platform.
package secretstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	// KeySize is the required AES-256 envelope-key size.
	KeySize         = 32
	maxKeyFileBytes = KeySize + 1
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
	key      [KeySize]byte
	random   io.Reader
	isClosed bool
}

// New validates and takes a defensive copy of one envelope key.
func New(key []byte) (*Protector, error) {
	return newWithRandom(key, rand.Reader)
}

func newWithRandom(key []byte, random io.Reader) (*Protector, error) {
	if len(key) != KeySize {
		return nil, ErrKeyInvalid
	}
	if random == nil {
		return nil, errors.New("secretstore: randomness source is required")
	}

	protector := &Protector{random: random}
	copy(protector.key[:], key)

	return protector, nil
}

// Load reads an owner-only key from an absolute, non-symlink path.
func Load(path string) (*Protector, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return nil, fmt.Errorf("%w: key path must be an absolute file", ErrKeyInvalid)
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
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: key permissions are too broad", ErrKeyInvalid)
	}
	if info.Size() != KeySize {
		return nil, fmt.Errorf("%w: key must contain exactly %d bytes", ErrKeyInvalid, KeySize)
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
	if openedInfo.Mode().Perm()&0o077 != 0 || openedInfo.Size() != KeySize {
		return nil, fmt.Errorf("%w: opened key metadata is unsafe", ErrKeyInvalid)
	}

	key := make([]byte, maxKeyFileBytes)
	readBytes, err := io.ReadFull(file, key)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		clear(key)
		if err == nil {
			return nil, fmt.Errorf("%w: key exceeds %d bytes", ErrKeyInvalid, KeySize)
		}

		return nil, fmt.Errorf("reading secret-store key: %w", err)
	}
	if readBytes != KeySize {
		clear(key)

		return nil, fmt.Errorf("%w: key must contain exactly %d bytes", ErrKeyInvalid, KeySize)
	}

	protector, err := New(key[:KeySize])
	clear(key)
	if err != nil {
		return nil, err
	}

	return protector, nil
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

	aead, err := newGCM(p.key[:])
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
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("opening secret record: %w", err)
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

	aead, err := newGCM(p.key[:])
	if err != nil {
		return nil, err
	}
	if len(protected) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrAuthentication
	}
	nonce := protected[:aead.NonceSize()]
	ciphertext := protected[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, ErrAuthentication
	}

	return plaintext, nil
}

// Close clears the in-memory envelope key. It is safe to call more than once.
func (p *Protector) Close() error {
	if p == nil {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.isClosed {
		clear(p.key[:])
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
