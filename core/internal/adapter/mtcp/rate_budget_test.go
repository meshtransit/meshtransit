package mtcp

import (
	"context"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

func TestRateBudget(t *testing.T) {
	t.Parallel()
	budget := newRateBudget(identityBurst, identityRate)
	start := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	for attempt := range identityBurst {
		if _, ok := budget.spend(start, 1); !ok {
			t.Fatalf("request %d of a fresh session refused", attempt+1)
		}
	}
	wait, ok := budget.spend(start, 1)
	if ok || wait != time.Second {
		t.Fatalf("request over the burst: %s, %t; want refused for 1s", wait, ok)
	}
	// A refused request costs nothing; a token comes back each second.
	if _, ok := budget.spend(start.Add(time.Second), 1); !ok {
		t.Fatal("request after one second refused")
	}
	if _, ok := budget.spend(start.Add(time.Second), 1); ok {
		t.Fatal("two requests within one recovered token admitted")
	}
	if _, ok := budget.spend(start.Add(time.Hour), 1); !ok {
		t.Fatal("request after a quiet hour refused")
	}
	// A clock stepping back costs nothing.
	spent := budget.spent
	if _, ok := budget.spend(start, 1); !ok || budget.spent != spent+1 {
		t.Fatalf("spend after the clock stepped back: spent %v, want %v", budget.spent, spent+1)
	}
}

func TestRateBudgetChargesByCost(t *testing.T) {
	t.Parallel()
	budget := newRateBudget(inboundByteBurst, inboundByteRate)
	start := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	if _, ok := budget.spend(start, inboundByteBurst); !ok {
		t.Fatal("a burst-sized spend of a fresh budget refused")
	}
	wait, ok := budget.spend(start, inboundByteRate)
	if ok || wait != time.Second {
		t.Fatalf("spend over the burst: %s, %t; want refused for 1s", wait, ok)
	}
	if _, ok := budget.spend(start.Add(time.Second), inboundByteRate); !ok {
		t.Fatal("a second's worth refused after a second")
	}
}

func TestRetryAfterMS(t *testing.T) {
	t.Parallel()
	for wait, want := range map[time.Duration]uint32{
		0: 0, time.Millisecond: 1000, 40 * time.Minute: 2_400_000, -time.Second: 0,
		1 << 62: 4_294_967_295,
	} {
		if got := retryAfterMS(wait); got != want {
			t.Errorf("retryAfterMS(%s) = %d, want %d", wait, got, want)
		}
	}
}

type acceptingConversation struct{}

func (acceptingConversation) Run(ctx context.Context) error { <-ctx.Done(); return nil }

func (acceptingConversation) Receive(context.Context, sharedmtcp.MessageType, proto.Message) error {
	return nil
}

// TestSessionLimitsWhatANodeSends checks the session's inbound budget: a
// burst of messages, or of bytes, then the session ends with OVERLOADED.
func TestSessionLimitsWhatANodeSends(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		size, admitted int
		retryMS        uint32
	}{
		"messages": {size: 64, admitted: inboundMessageBurst, retryMS: 1000},
		"bytes":    {size: 64 << 10, admitted: inboundByteBurst / (64 << 10), retryMS: 1000},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			session, node, _ := testSession(t)
			session.ctx, session.cancel = context.WithCancelCause(t.Context())
			now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
			session.server.options.Now = func() time.Time { return now }
			report := inbound{t: sharedmtcp.MessageHostinfoReport, message: &mtcpv1.HostinfoReport{}, size: test.size}
			for index := range test.admitted {
				if !session.dispatch(acceptingConversation{}, report) {
					t.Fatalf("message %d within the budget ended the session", index+1)
				}
			}
			if session.dispatch(acceptingConversation{}, report) {
				t.Fatal("a message over the budget was admitted")
			}
			got, message, ok := node.read()
			failure, _ := message.(*mtcpv1.Error)
			if !ok || got != sharedmtcp.MessageError || failure.GetCode() != mtcpv1.Error_OVERLOADED ||
				!failure.GetFatal() || failure.GetRetryAfterMs() != test.retryMS {
				t.Fatalf("over the budget the node got %#x %v", uint8(got), message)
			}
			if session.ctx.Err() == nil {
				t.Fatal("the session did not end")
			}
		})
	}
}

// TestSessionInboundBudgetLetsAFollowingNodeThrough sends what a node that
// follows the protocol may: an ack for every map message, the largest
// report, and a steady rate after the burst.
func TestSessionInboundBudgetLetsAFollowingNodeThrough(t *testing.T) {
	t.Parallel()
	session, _, _ := testSession(t)
	session.ctx, session.cancel = context.WithCancelCause(t.Context())
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	session.server.options.Now = func() time.Time { return now }
	// Acks follow Core's own sends and count only as bytes.
	ack := inbound{t: sharedmtcp.MessageMapAck, message: &mtcpv1.MapAck{}, size: 40}
	for index := range 10 * inboundMessageBurst {
		if !session.dispatch(acceptingConversation{}, ack) {
			t.Fatalf("ack %d ended the session", index+1)
		}
	}
	// The largest message a node sends, a 256 KiB PathStatsReport with the
	// tags of the records carrying it, fits the byte burst.
	largest := inbound{t: sharedmtcp.MessagePathStatsReport, message: &mtcpv1.PathStatsReport{},
		size: 256<<10 + 16*(256<<10/sharedmtcp.MaxTransportPlaintext+1)}
	if !session.dispatch(acceptingConversation{}, largest) {
		t.Fatal("the largest legal message was refused")
	}
	// After the burst, the steady rate is admitted.
	report := inbound{t: sharedmtcp.MessageHostinfoReport, message: &mtcpv1.HostinfoReport{}, size: 64}
	for range inboundMessageBurst - 1 {
		session.dispatch(acceptingConversation{}, report)
	}
	for second := range 10 {
		now = now.Add(time.Second)
		for index := range int(inboundMessageRate) {
			if !session.dispatch(acceptingConversation{}, report) {
				t.Fatalf("second %d, message %d of the steady rate refused", second+1, index+1)
			}
		}
	}
}

// auditRecordingConversation notes, for each message, whether the session
// said it was over its audit budget.
type auditRecordingConversation struct {
	acceptingConversation
	session *Session
	over    []bool
}

func (conversation *auditRecordingConversation) Receive(context.Context, sharedmtcp.MessageType,
	proto.Message,
) error {
	conversation.over = append(conversation.over, conversation.session.AuditOverBudget())
	return nil
}

// gateway.audit1 messages spend their own budget, never the inbound one:
// over it they are still handed on, marked over; only past four times it
// does the session end (K1b0 §3.5).
func TestSessionAuditBudget(t *testing.T) {
	t.Parallel()
	session, _, _ := testSession(t)
	session.ctx, session.cancel = context.WithCancelCause(t.Context())
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	session.server.options.Now = func() time.Time { return now }
	session.gate.Gateway = true
	session.capabilities = append(session.capabilities, CapabilityKubeAudit)
	conversation := &auditRecordingConversation{session: session}
	intents := inbound{t: sharedmtcp.MessageKubeAuditIntents, message: &mtcpv1.KubeAuditIntents{}, size: 128 << 10}
	// Four full messages fit the audit burst; the general budget is untouched.
	for index := range 4 {
		if !session.dispatch(conversation, intents) {
			t.Fatalf("intents %d ended the session", index+1)
		}
	}
	if session.inboundBytes.spent != 0 || session.inboundMessages.spent != 0 {
		t.Fatalf("audit spent the inbound budget: %v bytes, %v messages", session.inboundBytes.spent,
			session.inboundMessages.spent)
	}
	// Past the audit burst: still handed on, marked over.
	for range 13 {
		if !session.dispatch(conversation, intents) {
			break
		}
	}
	if conversation.over[3] || slices.Contains(conversation.over[4:], false) {
		t.Fatalf("over = %v", conversation.over)
	}
	// Past the ceiling: the session ends.
	if session.ctx.Err() == nil {
		t.Fatal("past the audit ceiling the session went on")
	}
	if len(conversation.over) != 16 {
		t.Fatalf("handed on %d messages, want 16 within the ceiling", len(conversation.over))
	}
}

// A session that is no gateway with gateway.audit1 pays for audit messages
// from the inbound budget, as any message (review b0b1 H1); a tiny one costs
// a gateway at least the floor.
func TestSessionAuditBudgetIsTheGatewaysOnly(t *testing.T) {
	t.Parallel()
	session, _, _ := testSession(t)
	session.ctx, session.cancel = context.WithCancelCause(t.Context())
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	session.server.options.Now = func() time.Time { return now }
	small := inbound{t: sharedmtcp.MessageKubeAuditIntents, message: &mtcpv1.KubeAuditIntents{}, size: 40}
	session.dispatch(acceptingConversation{}, small)
	if session.inboundMessages.spent != 1 || session.auditBytes.spent != 0 {
		t.Fatalf("a node's audit message: inbound %v, audit %v", session.inboundMessages.spent,
			session.auditBytes.spent)
	}
	session.gate.Gateway = true
	session.capabilities = append(session.capabilities, CapabilityKubeAudit)
	session.dispatch(acceptingConversation{}, small)
	if session.inboundMessages.spent != 1 || session.auditBytes.spent != auditMessageFloor {
		t.Fatalf("a gateway's tiny audit message: inbound %v, audit %v", session.inboundMessages.spent,
			session.auditBytes.spent)
	}
}
