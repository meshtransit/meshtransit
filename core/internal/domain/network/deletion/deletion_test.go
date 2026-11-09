package deletion

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

func TestValidReason(t *testing.T) {
	t.Parallel()
	for reason, want := range map[string]bool{
		"Dự án kết thúc":           true,
		strings.Repeat("a", 512):   true,
		strings.Repeat("ạ", 170):   true, // 510 bytes
		strings.Repeat("ạ", 171):   false,
		"":                         false,
		" padded":                  false,
		"line\nbreak":              false,
		"tab\tinside":              false,
		"bidi \u202e override":     false,
		"zero\u200bwidth":          false,
		string([]byte{0xff, 0x61}): false,
	} {
		if ValidReason(reason) != want {
			t.Errorf("ValidReason(%q) = %v", reason, !want)
		}
	}
}

func TestBlockersMustAgree(t *testing.T) {
	t.Parallel()
	id, _ := publicid.Parse("01890f00-0000-7000-8000-000000000901")
	good := Blockers{Total: 2, TrustContracts: 1, KubernetesClusters: 1, Items: []Blocker{
		{Kind: BlockerTrustContract, ID: id}, {Kind: BlockerKubernetesCluster, ID: id, Name: "prod"}}}
	if !good.IsValid() {
		t.Fatal("good blockers refused")
	}
	for name, change := range map[string]func(*Blockers){
		"total off":          func(b *Blockers) { b.Total = 3 },
		"none named":         func(b *Blockers) { b.Items = nil },
		"unknown kind":       func(b *Blockers) { b.Items[0].Kind = "share" },
		"named contract":     func(b *Blockers) { b.Items[0].Name = "x" },
		"cluster without id": func(b *Blockers) { b.Items[1].ID = publicid.ID{} },
		"cluster no name":    func(b *Blockers) { b.Items[1].Name = "" },
	} {
		copied := good
		copied.Items = append([]Blocker(nil), good.Items...)
		change(&copied)
		if copied.IsValid() {
			t.Errorf("%s accepted", name)
		}
	}
}

type fakeStore struct {
	outcome Outcome
	view    View
	err     error
}

func (store fakeStore) Delete(context.Context, Command) (Outcome, error) {
	return store.outcome, store.err
}

func (store fakeStore) Read(context.Context, accountsession.Session, network.Scope) (View, error) {
	return store.view, store.err
}

type fixedClock time.Time

func (clock fixedClock) Now() time.Time { return time.Time(clock) }

func TestServiceRefusesWhatDoesNotMatch(t *testing.T) {
	t.Parallel()
	if _, err := NewService(nil, fixedClock(time.Now())); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil store: %v", err)
	}
	service, err := NewService(fakeStore{}, fixedClock(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Delete(t.Context(), Command{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty command: %v", err)
	}
	if _, err := service.Read(t.Context(), accountsession.Session{}, network.Scope{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty read: %v", err)
	}
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	other, _ := network.ParseID("01890f00-0000-7000-8000-000000000202")
	requested := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	command := Command{ExpectedVersion: 3}
	command.Scope, _ = network.NewScope(workspaceID, networkID)
	for name, outcome := range map[string]Outcome{
		"deleted, no newer version": {Kind: OutcomeDeleted, Version: 3,
			Progress: Progress{NetworkID: networkID, RequestedAt: requested}},
		"deleted, another Network": {Kind: OutcomeDeleted, Version: 4,
			Progress: Progress{NetworkID: other, RequestedAt: requested}},
		"deleting, completed": {Kind: OutcomeDeleting, Progress: Progress{NetworkID: networkID,
			RequestedAt: requested, CompletedAt: &requested}},
		"blocked, nothing named": {Kind: OutcomeBlocked, Blockers: Blockers{Total: 1, TrustContracts: 1}},
		"unknown kind":           {Kind: "gone"},
	} {
		if outcome.matches(command) {
			t.Errorf("%s matched", name)
		}
	}
	if !(Outcome{Kind: OutcomeDeleted, Version: 4, Progress: Progress{NetworkID: networkID, RequestedAt: requested}}).
		matches(command) {
		t.Error("a valid deletion did not match")
	}
}
