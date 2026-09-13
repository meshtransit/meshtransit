package node_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/internal/node"
)

func TestParseHostname(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		value     string
		want      string
		wantError bool
	}{
		{name: "single label", value: "node-1", want: "node-1"},
		{name: "fully qualified", value: "Node-1.Example", want: "node-1.example"},
		{name: "empty", wantError: true},
		{name: "leading whitespace", value: " node", wantError: true},
		{name: "trailing root dot", value: "node.example.", wantError: true},
		{name: "empty label", value: "node..example", wantError: true},
		{name: "leading hyphen", value: "-node", wantError: true},
		{name: "trailing hyphen", value: "node-", wantError: true},
		{name: "underscore", value: "node_one", wantError: true},
		{name: "unicode requires boundary", value: "nộde", wantError: true},
		{name: "label too long", value: strings.Repeat("a", 64), wantError: true},
		{name: "hostname too long", value: strings.Repeat("a.", 127) + "a", wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			hostname, err := node.ParseHostname(test.value)
			if test.wantError {
				if !errors.Is(err, node.ErrInvalidHostname) {
					t.Fatalf("ParseHostname() error = %v, want ErrInvalidHostname", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseHostname() error = %v", err)
			}
			if hostname.String() != test.want || !hostname.IsValid() {
				t.Fatalf("ParseHostname() = %q, want %q", hostname.String(), test.want)
			}
		})
	}

	if (node.Hostname{}).IsValid() {
		t.Fatal("zero Hostname is valid")
	}
}
