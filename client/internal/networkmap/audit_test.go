package networkmap

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestAuditCredentialsScopesAndRedaction(t *testing.T) {
	t.Parallel()

	nodeToken := testAuditToken(7, 11)
	networkToken := testAuditToken(7, 0)
	credentials, err := NewAuditCredentials(nodeToken, networkToken, 11)
	if err != nil {
		t.Fatalf("NewAuditCredentials() error = %v", err)
	}
	if !credentials.Enabled() || credentials.NetworkID() != 7 || credentials.NodeID() != 11 {
		t.Fatalf("credentials scope = network %d node %d", credentials.NetworkID(), credentials.NodeID())
	}
	if credentials.NodeToken() != nodeToken || credentials.NetworkToken() != networkToken {
		t.Fatal("credential tokens changed")
	}
	if strings.Contains(credentials.String(), nodeToken) || strings.Contains(credentials.GoString(), nodeToken) {
		t.Fatal("credential formatting disclosed token")
	}
}

func TestAuditCredentialsRejectScopeMismatch(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		node    string
		network string
		self    uint64
	}{
		{name: "node", node: testAuditToken(7, 12), network: testAuditToken(7, 0), self: 11},
		{name: "network", node: testAuditToken(7, 11), network: testAuditToken(8, 0), self: 11},
		{name: "network node", node: testAuditToken(7, 11), network: testAuditToken(7, 12), self: 11},
		{name: "encoding", node: strings.Repeat("A", 64), network: testAuditToken(7, 0), self: 11},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewAuditCredentials(test.node, test.network, test.self); err == nil {
				t.Fatal("NewAuditCredentials() error = nil")
			}
		})
	}
}

func testAuditToken(networkID, nodeID uint64) string {
	var token [32]byte
	binary.BigEndian.PutUint64(token[0:8], networkID)
	binary.BigEndian.PutUint64(token[8:16], nodeID)
	for index := 16; index < len(token); index++ {
		token[index] = byte(index)
	}

	return hex.EncodeToString(token[:])
}
