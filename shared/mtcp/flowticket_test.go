package mtcp

import (
	"testing"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/shared/flowlog"
)

// FlowTicket carries a connection log token of up to flowlog.MaxTokenSize
// (mtcp-v1 §9.1): the largest must encode and decode within its limit.
func TestFlowTicketTakesTheLargestToken(t *testing.T) {
	ticket := &mtcpv1.FlowTicket{
		Token:       make([]byte, flowlog.MaxTokenSize),
		NotAfterMs:  1<<62 - 1,
		ReceiverKey: make([]byte, 32),
	}
	ticket.Token[0] = 1
	fragments, err := EncodeMessage(MessageFlowTicket, ticket, CoreToNode, EncodeOptions{})
	if err != nil {
		t.Fatalf("EncodeMessage() error = %v", err)
	}
	assembler := NewAssembler(CoreToNode)
	var payload []byte
	for _, fragment := range fragments {
		_, decoded, _, err := assembler.Add(fragment)
		if err != nil {
			t.Fatal(err)
		}
		payload = decoded
	}
	decoded, err := DecodeMessage(MessageFlowTicket, payload)
	if err != nil || !proto.Equal(decoded, ticket) {
		t.Fatalf("DecodeMessage() did not return the ticket: %v", err)
	}
}
