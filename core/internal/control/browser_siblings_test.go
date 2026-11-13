package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node"
)

type browserSiblingIntentFake struct {
	browserIntentRepositoryFake
	encoded  string
	siblings [][32]byte
	calls    int
}

func (fake *browserSiblingIntentFake) RecordSiblings(_ context.Context, _ deployment.ID, _ int64,
	_ node.RegistrationIdentity, encoded string, siblings [][32]byte,
) error {
	fake.calls++
	fake.encoded, fake.siblings = encoded, siblings
	return nil
}

func siblingTestMachine(t *testing.T) (AuthenticatedMachine, node.Key, node.Hostname) {
	t.Helper()
	machineKey, err := node.NewMachineKey([32]byte{0: 1})
	if err != nil {
		t.Fatal(err)
	}
	machine, err := NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := node.NewKey([32]byte{0: 2})
	if err != nil {
		t.Fatal(err)
	}
	hostname, err := node.ParseHostname("node-one.example")
	if err != nil {
		t.Fatal(err)
	}
	return machine, nodeKey, hostname
}

func TestBrowserRegistrationServiceRecordsSiblings(t *testing.T) {
	t.Parallel()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := enrollment.NewBrowserIntentKeyID("browser-v1")
	if err != nil {
		t.Fatal(err)
	}
	key, err := enrollment.NewBrowserIntentKey(keyID, bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := enrollment.NewBrowserIntentKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	fake := &browserSiblingIntentFake{browserIntentRepositoryFake: browserIntentRepositoryFake{keys: keys, found: true}}
	service, err := NewBrowserRegistrationService(fake, deploymentID, 1, "https://console.example.test", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	machine, nodeKey, hostname := siblingTestMachine(t)
	issued, err := service.RegisterBrowser(t.Context(), machine, nodeKey, hostname, "")
	if err != nil {
		t.Fatal(err)
	}
	siblings := [][32]byte{{0: 9}}
	if err := service.RecordSiblings(t.Context(), machine, nodeKey, issued, nil); err != nil || fake.calls != 0 {
		t.Fatalf("no siblings = (%v, calls=%d)", err, fake.calls)
	}
	if err := service.RecordSiblings(t.Context(), machine, nodeKey, issued, siblings); err != nil ||
		fake.calls != 1 || fake.encoded != fake.issuedURL || len(fake.siblings) != 1 {
		t.Fatalf("record = (%v, calls=%d, %q)", err, fake.calls, fake.encoded)
	}
	for _, forged := range []string{strings.Replace(issued, "console", "other", 1), issued + "/x", "token"} {
		if err := service.RecordSiblings(t.Context(), machine, nodeKey, forged, siblings); !errors.Is(err,
			ErrInvalidBrowserRegistration) {
			t.Fatalf("accepted %q: %v", forged, err)
		}
	}
	// A repository that keeps no siblings: nothing to do.
	plain, err := NewBrowserRegistrationService(&fake.browserIntentRepositoryFake, deploymentID, 1,
		"https://console.example.test", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.RecordSiblings(t.Context(), machine, nodeKey, issued, siblings); err != nil {
		t.Fatal(err)
	}
}

type browserSiblingCompletionFake struct {
	err      error
	siblings [][32]byte
	plain    int
}

func (fake *browserSiblingCompletionFake) Complete(context.Context, node.RegistrationIdentity, node.Hostname,
	string,
) (registration.Result, bool, error) {
	fake.plain++
	return registration.Result{}, false, fake.err
}

func (fake *browserSiblingCompletionFake) CompleteWithSiblings(_ context.Context, _ node.RegistrationIdentity,
	_ node.Hostname, _ string, siblings [][32]byte,
) (registration.Result, bool, error) {
	fake.siblings = siblings
	return registration.Result{}, false, fake.err
}

// "Use that account" and the sibling refusal reach the protocol adapter as
// they are; other store failures stay unavailable.
func TestBrowserCompletionServicePassesSiblingOutcomes(t *testing.T) {
	t.Parallel()
	machine, nodeKey, hostname := siblingTestMachine(t)
	followup := "https://console.example.test/register/v1/" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	joined := &registration.JoinedExistingError{SiblingMachineKey: [32]byte{0: 5}}
	for _, test := range []struct {
		name  string
		err   error
		check func(error) bool
	}{
		{name: "joined", err: joined, check: func(err error) bool {
			var got *registration.JoinedExistingError
			return errors.As(err, &got) && got == joined && !errors.Is(err, ErrBrowserRegistrationUnavailable)
		}},
		{name: "conflict", err: registration.ErrSiblingConflict, check: func(err error) bool {
			return errors.Is(err, registration.ErrSiblingConflict) &&
				errors.Is(err, registration.ErrKeysHeldElsewhere) && !errors.Is(err, ErrBrowserRegistrationUnavailable)
		}},
		{name: "other", err: errors.New("store down"), check: func(err error) bool {
			return errors.Is(err, ErrBrowserRegistrationUnavailable)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &browserSiblingCompletionFake{err: test.err}
			service, err := NewBrowserCompletionService(store, "https://console.example.test")
			if err != nil {
				t.Fatal(err)
			}
			_, found, err := service.CompleteBrowserWithSiblings(t.Context(), machine, nodeKey, hostname, followup,
				[][32]byte{{0: 7}})
			if found || !test.check(err) || len(store.siblings) != 1 || store.plain != 0 {
				t.Fatalf("complete = (%v, %v), siblings=%d plain=%d", found, err, len(store.siblings), store.plain)
			}
		})
	}
}
