package network

import (
	"errors"
	"strings"
	"testing"
)

const testNetworkPublicID = "01890f00-0000-7000-8000-000000000201"

func TestNewRevisionAdvanced(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		networkPublicID string
		revision        int64
		wantErr         bool
	}{
		{name: "valid", networkPublicID: testNetworkPublicID, revision: 42},
		{name: "missing network", revision: 42, wantErr: true},
		{name: "non canonical network", networkPublicID: strings.ToUpper(testNetworkPublicID), revision: 42, wantErr: true},
		{name: "wrong uuid version", networkPublicID: "01890f00-0000-4000-8000-000000000201", revision: 42, wantErr: true},
		{name: "wrong uuid variant", networkPublicID: "01890f00-0000-7000-c000-000000000201", revision: 42, wantErr: true},
		{name: "zero revision", networkPublicID: testNetworkPublicID, wantErr: true},
		{name: "negative revision", networkPublicID: testNetworkPublicID, revision: -1, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			revision, err := NewRevisionAdvanced(test.networkPublicID, test.revision)
			if test.wantErr {
				if !errors.Is(err, ErrInvalidRevision) {
					t.Fatalf("NewRevisionAdvanced() error = %v, want ErrInvalidRevision", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewRevisionAdvanced() error = %v", err)
			}
			if revision.NetworkPublicID() != test.networkPublicID ||
				revision.NetworkID().String() != test.networkPublicID ||
				revision.Number() != test.revision {
				t.Fatalf(
					"NewRevisionAdvanced() = (%q, %d), want (%q, %d)",
					revision.NetworkPublicID(),
					revision.Number(),
					test.networkPublicID,
					test.revision,
				)
			}
		})
	}
}

func TestRevisionAdvancedZeroValueIsInvalid(t *testing.T) {
	t.Parallel()

	if (RevisionAdvanced{}).IsValid() {
		t.Fatal("zero RevisionAdvanced is valid")
	}
}
