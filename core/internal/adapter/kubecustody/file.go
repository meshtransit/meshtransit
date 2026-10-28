// Package kubecustody keeps the keys that wrap the data keys of Kubernetes
// cluster CAs (K1a4 §15.2, ADR-053): a key in a secret file, or a key in a
// KMS. Only the worker builds one.
package kubecustody

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"meshtransit.net/core/internal/domain/kubeca"
)

const fileCustody = "file"

// File wraps data keys with AES-256-GCM under a key read from a secret
// file, bound to the data key's Network. Previous keys, kept after
// rotations of the file key until every data key is wrapped again, still
// open what they wrapped but never wrap (the new key is primary first, R3).
// It never formats its keys.
type File struct {
	primary  kubeca.DataKey
	keyID    string
	previous map[string]kubeca.DataKey
}

var _ kubeca.Custody = (*File)(nil)

// maximumPreviousKeys bounds the older keys a custody keeps for opening.
const maximumPreviousKeys = 8

// NewFile builds a file custody from its primary key and, during
// rotations, the previous ones. An all-zero key (a failed read) or the same
// key twice is refused.
func NewFile(primary kubeca.DataKey, previous []kubeca.DataKey) (*File, error) {
	if primary.IsZero() || len(previous) > maximumPreviousKeys {
		return nil, kubeca.ErrInvalid
	}
	custody := &File{primary: primary, keyID: fileKeyID(primary), previous: map[string]kubeca.DataKey{}}
	for _, key := range previous {
		id := fileKeyID(key)
		if _, seen := custody.previous[id]; seen || key.IsZero() || key == primary {
			return nil, kubeca.ErrInvalid
		}
		custody.previous[id] = key
	}
	return custody, nil
}

// String redacts the custody's keys.
func (*File) String() string { return "kubecustody.File([REDACTED])" }

// fileKeyID names a file key by a domain-separated MAC under it: stable,
// and revealing nothing of the key.
func fileKeyID(key kubeca.DataKey) string {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("meshtransit kube wrap key id v1"))
	return hex.EncodeToString(mac.Sum(nil)[:8])
}

// NewDataKey implements kubeca.Custody.
func (custody *File) NewDataKey(_ context.Context, network string) (kubeca.DataKey, kubeca.WrappedKey, error) {
	if network == "" {
		return kubeca.DataKey{}, kubeca.WrappedKey{}, kubeca.ErrInvalid
	}
	var dataKey kubeca.DataKey
	if _, err := rand.Read(dataKey[:]); err != nil {
		return kubeca.DataKey{}, kubeca.WrappedKey{}, err
	}
	sealed, err := kubeca.Seal(custody.primary, kubeca.DataKeyAAD(network), dataKey[:])
	if err != nil {
		return kubeca.DataKey{}, kubeca.WrappedKey{}, err
	}
	return dataKey, kubeca.WrappedKey{Custody: fileCustody, KeyID: custody.keyID, Ciphertext: sealed}, nil
}

// WrapDataKey implements kubeca.Custody.
func (custody *File) WrapDataKey(_ context.Context, network string, dataKey kubeca.DataKey) (kubeca.WrappedKey, error) {
	if network == "" || dataKey.IsZero() {
		return kubeca.WrappedKey{}, kubeca.ErrInvalid
	}
	sealed, err := kubeca.Seal(custody.primary, kubeca.DataKeyAAD(network), dataKey[:])
	if err != nil {
		return kubeca.WrappedKey{}, err
	}
	return kubeca.WrappedKey{Custody: fileCustody, KeyID: custody.keyID, Ciphertext: sealed}, nil
}

// OpenDataKey implements kubeca.Custody.
func (custody *File) OpenDataKey(_ context.Context, network string, wrapped kubeca.WrappedKey) (kubeca.DataKey, error) {
	key, known := custody.previous[wrapped.KeyID]
	if wrapped.KeyID == custody.keyID {
		key, known = custody.primary, true
	}
	if wrapped.Custody != fileCustody || !known || network == "" {
		return kubeca.DataKey{}, kubeca.ErrInvalid
	}
	opened, err := kubeca.Open(key, kubeca.DataKeyAAD(network), wrapped.Ciphertext)
	if err != nil || len(opened) != len(kubeca.DataKey{}) {
		return kubeca.DataKey{}, kubeca.ErrInvalid
	}
	return kubeca.DataKey(opened), nil
}
