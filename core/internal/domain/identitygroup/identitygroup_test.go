package identitygroup_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

func TestDefinitionValidation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		definition identitygroup.Definition
		valid      bool
	}{
		{name: "plain", definition: identitygroup.Definition{Name: "Engineering", Description: "Builds things"}, valid: true},
		{name: "longest", definition: identitygroup.Definition{Name: strings.Repeat("é", 64)}, valid: true},
		{name: "empty", definition: identitygroup.Definition{Name: ""}},
		{name: "padded", definition: identitygroup.Definition{Name: " Ops"}},
		{name: "too long", definition: identitygroup.Definition{Name: strings.Repeat("a", 65)}},
		{name: "control", definition: identitygroup.Definition{Name: "Ops\n"}},
		{name: "long description", definition: identitygroup.Definition{Name: "Ops", Description: strings.Repeat("a", 281)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := test.definition.IsValid(); got != test.valid {
				t.Fatalf("IsValid() = %t, want %t", got, test.valid)
			}
		})
	}
}

type recordingStore struct {
	identitygroup.Store
	membership identitygroup.MembershipChange
	calls      int
}

func (store *recordingStore) ChangeMembers(_ context.Context, change identitygroup.MembershipChange) (
	identitygroup.MembershipResult, error) {
	store.calls++
	store.membership = change
	return identitygroup.MembershipResult{}, nil
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

func TestChangeMembersRejectsBeforeStore(t *testing.T) {
	t.Parallel()
	store := &recordingStore{}
	service, err := identitygroup.NewService(store, fixedClock{time.Now()}, identitygroup.SystemIDs{})
	if err != nil {
		t.Fatal(err)
	}
	principal, _ := publicid.New()
	group, _ := publicid.New()
	workspaceID, _ := publicid.New()
	correlation, _ := publicid.New()
	tooMany := make([]publicid.ID, identitygroup.MaximumMembersPerChange+1)
	for index := range tooMany {
		tooMany[index], _ = publicid.New()
	}
	for _, test := range []struct {
		name        string
		add, remove []publicid.ID
	}{
		{name: "nothing"},
		{name: "added and removed", add: []publicid.ID{principal}, remove: []publicid.ID{principal}},
		{name: "duplicate", add: []publicid.ID{principal, principal}},
		{name: "too many", add: tooMany},
	} {
		_, err := service.ChangeMembers(t.Context(), accountsession.Session{}, workspace.ID(workspaceID),
			identitygroup.ID(group), 1, test.add, test.remove, correlation)
		if !errors.Is(err, identitygroup.ErrForbidden) && !errors.Is(err, identitygroup.ErrInvalid) {
			t.Errorf("%s: err = %v", test.name, err)
		}
	}
	if store.calls != 0 {
		t.Fatalf("store called %d times for invalid changes", store.calls)
	}
}
