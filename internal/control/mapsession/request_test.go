package mapsession

import (
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/internal/node"
)

func TestRequestValidatesNodeKeyAndCapability(t *testing.T) {
	nodeKey, err := node.NewKey([32]byte{2})
	if err != nil {
		t.Fatalf("node.NewKey() error = %v", err)
	}
	request, err := NewRequest(nodeKey, 142)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if !request.IsValid() || request.NodeKey() != nodeKey || request.CapabilityVersion() != 142 {
		t.Fatalf("request = %+v, want valid immutable request", request)
	}

	for _, test := range []struct {
		name       string
		nodeKey    node.Key
		capability int
	}{
		{name: "missing Node key", capability: 142},
		{name: "zero capability", nodeKey: nodeKey},
		{name: "negative capability", nodeKey: nodeKey, capability: -1},
		{name: "excess capability", nodeKey: nodeKey, capability: maximumCapabilityVersion + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewRequest(test.nodeKey, test.capability); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("NewRequest() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}
