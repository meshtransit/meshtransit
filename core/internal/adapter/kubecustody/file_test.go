package kubecustody

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/kubeca"
)

func newKey(t *testing.T) kubeca.DataKey {
	t.Helper()
	var key kubeca.DataKey
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	return key
}

// A file custody wraps data keys under its primary key; after a wrap key
// rotation the previous key still opens what it wrapped, and nothing else
// does (K1a4 §15.7, R3).
func TestFileCustodyWrapsUnderItsPrimaryKey(t *testing.T) {
	t.Parallel()
	old, current := newKey(t), newKey(t)
	before, err := NewFile(old, nil)
	if err != nil {
		t.Fatal(err)
	}
	dataKey, wrapped, err := before.NewDataKey(t.Context(), "net-1")
	if err != nil || wrapped.Custody != "file" || wrapped.KeyID == "" || len(wrapped.Ciphertext) == 0 {
		t.Fatalf("NewDataKey() = %+v, %v", wrapped, err)
	}
	if opened, err := before.OpenDataKey(t.Context(), "net-1", wrapped); err != nil || opened != dataKey {
		t.Fatalf("OpenDataKey() = %v", err)
	}
	rotated, err := NewFile(current, &old)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := rotated.OpenDataKey(t.Context(), "net-1", wrapped); err != nil || opened != dataKey {
		t.Fatalf("the previous key no longer opens: %v", err)
	}
	_, fresh, err := rotated.NewDataKey(t.Context(), "net-1")
	if err != nil || fresh.KeyID == wrapped.KeyID {
		t.Fatalf("a rotated custody wraps under the old key: %+v, %v", fresh, err)
	}
	stranger, _ := NewFile(newKey(t), nil)
	for name, open := range map[string]func() (kubeca.DataKey, error){
		"unknown key":   func() (kubeca.DataKey, error) { return stranger.OpenDataKey(t.Context(), "net-1", wrapped) },
		"other Network": func() (kubeca.DataKey, error) { return rotated.OpenDataKey(t.Context(), "net-2", wrapped) },
		"other custody": func() (kubeca.DataKey, error) {
			kms := wrapped
			kms.Custody = "kms"
			return rotated.OpenDataKey(t.Context(), "net-1", kms)
		},
		"tampered": func() (kubeca.DataKey, error) {
			tampered := wrapped
			tampered.Ciphertext = append([]byte(nil), wrapped.Ciphertext...)
			tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 1
			return rotated.OpenDataKey(t.Context(), "net-1", tampered)
		},
	} {
		if _, err := open(); !errors.Is(err, kubeca.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := NewFile(current, &current); err == nil {
		t.Fatal("the same key twice was taken")
	}
	if _, err := NewFile(kubeca.DataKey{}, nil); err == nil {
		t.Fatal("an all-zero key was taken")
	}
	if strings.Contains(fmt.Sprintf("%v %+v", rotated, *rotated), fmt.Sprintf("%x", current[:4])) {
		t.Fatal("a file custody formats its key")
	}
}
