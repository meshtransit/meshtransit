package node_test

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/node"
)

func TestNextAvailableHostnameSelectsLowestDeterministicCandidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		requested string
		occupied  []string
		want      string
	}{
		{
			name:      "requested name is free",
			requested: "edge.example",
			occupied:  []string{"unrelated.example"},
			want:      "edge.example",
		},
		{
			name:      "first collision uses one",
			requested: "edge.example",
			occupied:  []string{"edge.example"},
			want:      "edge-1.example",
		},
		{
			name:      "gap uses lowest ordinal",
			requested: "edge.example",
			occupied:  []string{"edge-3.example", "edge.example", "edge-1.example"},
			want:      "edge-2.example",
		},
		{
			name:      "single label",
			requested: "gateway",
			occupied:  []string{"gateway", "gateway-1"},
			want:      "gateway-2",
		},
		{
			name:      "long first label is trimmed",
			requested: strings.Repeat("a", 63) + ".example",
			occupied:  []string{strings.Repeat("a", 63) + ".example"},
			want:      strings.Repeat("a", 61) + "-1.example",
		},
		{
			name:      "maximum hostname length remains bounded",
			requested: maximumLengthHostname(),
			occupied:  []string{maximumLengthHostname()},
			want: strings.Repeat("a", 61) + "-1." + strings.Repeat("b", 63) + "." +
				strings.Repeat("c", 63) + "." + strings.Repeat("d", 61),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			requested := mustHostname(t, test.requested)
			occupied := make([]node.Hostname, len(test.occupied))
			for index, value := range test.occupied {
				occupied[index] = mustHostname(t, value)
			}
			before := slices.Clone(occupied)

			got, err := node.NextAvailableHostname(requested, occupied)
			if err != nil {
				t.Fatalf("NextAvailableHostname() error = %v", err)
			}
			if got.String() != test.want || !got.IsValid() {
				t.Fatalf("NextAvailableHostname() = %q, want %q", got.String(), test.want)
			}
			if !slices.Equal(occupied, before) {
				t.Fatal("NextAvailableHostname() mutated the occupied snapshot")
			}
		})
	}
}

func TestNextAvailableHostnameIsIndependentOfSnapshotOrder(t *testing.T) {
	t.Parallel()

	requested := mustHostname(t, "node.example")
	left := []node.Hostname{
		mustHostname(t, "node.example"),
		mustHostname(t, "node-1.example"),
		mustHostname(t, "node-3.example"),
	}
	right := slices.Clone(left)
	slices.Reverse(right)

	first, err := node.NextAvailableHostname(requested, left)
	if err != nil {
		t.Fatalf("NextAvailableHostname(left) error = %v", err)
	}
	second, err := node.NextAvailableHostname(requested, right)
	if err != nil {
		t.Fatalf("NextAvailableHostname(right) error = %v", err)
	}
	if first != second || first.String() != "node-2.example" {
		t.Fatalf("allocation differs by snapshot order: left=%q right=%q", first.String(), second.String())
	}
}

func TestNextAvailableHostnameUsesBoundedFinalCandidate(t *testing.T) {
	t.Parallel()

	requested := mustHostname(t, "node")
	occupied := make([]node.Hostname, 1024)
	occupied[0] = requested
	for ordinal := 1; ordinal < len(occupied); ordinal++ {
		occupied[ordinal] = mustHostname(t, "node-"+strconv.Itoa(ordinal))
	}

	got, err := node.NextAvailableHostname(requested, occupied)
	if err != nil {
		t.Fatalf("NextAvailableHostname() error = %v", err)
	}
	if got.String() != "node-1024" {
		t.Fatalf("NextAvailableHostname() = %q, want node-1024", got.String())
	}
}

func TestNextAvailableHostnameRejectsUnsafeInput(t *testing.T) {
	t.Parallel()

	valid := mustHostname(t, "node.example")
	tooMany := make([]node.Hostname, node.MaximumHostnameFamily+1)
	for index := range tooMany {
		tooMany[index] = valid
	}

	for _, test := range []struct {
		name      string
		requested node.Hostname
		occupied  []node.Hostname
	}{
		{name: "invalid requested hostname", occupied: []node.Hostname{valid}},
		{name: "invalid occupied hostname", requested: valid, occupied: []node.Hostname{{}}},
		{name: "unbounded snapshot", requested: valid, occupied: tooMany},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := node.NextAvailableHostname(test.requested, test.occupied)
			if !errors.Is(err, node.ErrInvalidHostnameAllocation) {
				t.Fatalf("NextAvailableHostname() error = %v, want ErrInvalidHostnameAllocation", err)
			}
			if got.IsValid() {
				t.Fatalf("NextAvailableHostname() = %q after invalid input", got.String())
			}
		})
	}
}

func maximumLengthHostname() string {
	return strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
}

func mustHostname(t *testing.T, value string) node.Hostname {
	t.Helper()

	hostname, err := node.ParseHostname(value)
	if err != nil {
		t.Fatalf("node.ParseHostname(%q) error = %v", value, err)
	}
	return hostname
}
