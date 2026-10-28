package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
)

// A call goes to the map stream with a deadline and returns its answer;
// one no session takes in time fails without being sent later.
func TestGatewayCertificatesRequest(t *testing.T) {
	t.Parallel()
	certificates := &gatewayCertificates{calls: make(chan controlplane.KubeCertCall)}
	go func() {
		call := <-certificates.calls
		if call.Deadline.IsZero() || cap(call.Reply) != 1 || call.Request.Token != "pod" {
			return
		}
		call.Reply <- controlplane.KubeCertReply{Result: controlplane.KubeCertResult{Reason: "busy"}}
	}()
	result, err := certificates.request(t.Context(), controlplane.KubeCertRequest{Token: "pod"})
	if err != nil || result.Reason != "busy" {
		t.Fatalf("request() = %+v, %v", result, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := certificates.request(ctx, controlplane.KubeCertRequest{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a call nobody took: %v", err)
	}
	// Without certificates the stream takes no calls and status has none.
	service := &Service{}
	if service.kubeCertCalls() != nil || service.gatewayCertificateStatus() != nil {
		t.Fatal("a service without certificates offered them")
	}
}
