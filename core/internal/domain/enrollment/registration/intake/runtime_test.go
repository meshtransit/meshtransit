package intake

import (
	"errors"
	"sync"
	"testing"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/publicid"
)

func TestPublicRegistrationIDGeneratorIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	const generationCount = 64
	results := make([]enrollment.RegistrationID, generationCount)
	resultErrors := make([]error, generationCount)
	var group sync.WaitGroup
	for index := range generationCount {
		group.Go(func() {
			results[index], resultErrors[index] = (PublicRegistrationIDGenerator{}).NewRegistrationID()
		})
	}
	group.Wait()

	seen := make(map[enrollment.RegistrationID]struct{}, generationCount)
	for index, id := range results {
		if resultErrors[index] != nil {
			t.Fatalf("PublicRegistrationIDGenerator.NewRegistrationID() error = %v", resultErrors[index])
		}
		if !id.IsValid() {
			t.Fatal("PublicRegistrationIDGenerator.NewRegistrationID() returned an invalid ID")
		}
		if _, exists := seen[id]; exists {
			t.Fatalf("PublicRegistrationIDGenerator.NewRegistrationID() returned duplicate ID %s", id)
		}
		seen[id] = struct{}{}
	}
}

func TestGenerateRegistrationIDRejectsInvalidFactoryResult(t *testing.T) {
	t.Parallel()

	if _, err := generateRegistrationID(nil); !errors.Is(err, enrollment.ErrInvalidID) {
		t.Fatalf("generateRegistrationID(nil) error = %v, want enrollment.ErrInvalidID", err)
	}
	if _, err := generateRegistrationID(func() (publicid.ID, error) {
		return publicid.ID{}, nil
	}); !errors.Is(err, enrollment.ErrInvalidID) {
		t.Fatalf("generateRegistrationID(zero) error = %v, want enrollment.ErrInvalidID", err)
	}
	wantErr := errors.New("entropy unavailable")
	if _, err := generateRegistrationID(func() (publicid.ID, error) {
		return publicid.ID{}, wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("generateRegistrationID(error) = %v, want wrapped entropy error", err)
	}
}

func TestPublicEvidenceIDGeneratorIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	const generationCount = 64
	results := make([]EvidenceIDs, generationCount)
	resultErrors := make([]error, generationCount)
	var group sync.WaitGroup
	for index := range generationCount {
		group.Go(func() {
			results[index], resultErrors[index] = (PublicEvidenceIDGenerator{}).NewEvidenceIDs()
		})
	}
	group.Wait()

	seen := make(map[publicid.ID]struct{}, generationCount*3)
	for index, ids := range results {
		if resultErrors[index] != nil {
			t.Fatalf("PublicEvidenceIDGenerator.NewEvidenceIDs() error = %v", resultErrors[index])
		}
		if !ids.IsValid() {
			t.Fatal("PublicEvidenceIDGenerator.NewEvidenceIDs() returned invalid IDs")
		}
		for _, id := range []publicid.ID{ids.ChangeID(), ids.AuditEventID(), ids.OutboxEventID()} {
			if _, exists := seen[id]; exists {
				t.Fatalf("PublicEvidenceIDGenerator.NewEvidenceIDs() returned duplicate ID %s", id)
			}
			seen[id] = struct{}{}
		}
	}
}

func TestGenerateEvidenceIDsPropagatesEntropyFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("entropy unavailable")
	calls := 0
	_, err := generateEvidenceIDs(func() (publicid.ID, error) {
		calls++
		if calls == 2 {
			return publicid.ID{}, wantErr
		}
		return publicid.New()
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("generateEvidenceIDs() error = %v, want wrapped entropy failure", err)
	}
}

func TestGenerateEvidenceIDsRejectsInvalidFactory(t *testing.T) {
	t.Parallel()

	if _, err := generateEvidenceIDs(nil); !errors.Is(err, ErrInvalidEvidenceIDs) {
		t.Fatalf("generateEvidenceIDs(nil) error = %v, want ErrInvalidEvidenceIDs", err)
	}
	oneID, err := publicid.New()
	if err != nil {
		t.Fatalf("publicid.New() error = %v", err)
	}
	if _, err := generateEvidenceIDs(func() (publicid.ID, error) {
		return oneID, nil
	}); !errors.Is(err, ErrInvalidEvidenceIDs) {
		t.Fatalf("generateEvidenceIDs(duplicate) error = %v, want ErrInvalidEvidenceIDs", err)
	}
}
