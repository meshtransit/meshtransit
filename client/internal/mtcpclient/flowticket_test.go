package mtcpclient

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/shared/flowlog"
	"meshtransit.net/shared/key"
)

// flow.report1 is declared only by a node that takes tickets.
func TestFlowReportCapability(t *testing.T) {
	t.Parallel()
	if slices.Contains(streamCapabilities(controlplane.NetmapOptions{}, false), flowReportCapability) {
		t.Fatal("declared without a ticket sink")
	}
	with := controlplane.NetmapOptions{FlowTickets: func(controlplane.FlowTicket) {}}
	for _, gateway := range []bool{false, true} {
		if !slices.Contains(streamCapabilities(with, gateway), flowReportCapability) {
			t.Fatalf("not declared (gateway %t)", gateway)
		}
	}
}

// A ticket reaches the daemon with the session's machine key and a way to
// post to the control origin; an empty one turns logging off; a malformed
// one changes nothing.
func TestFlowTicketDelivery(t *testing.T) {
	t.Parallel()
	var posted struct {
		path, token, contentType string
		body                     []byte
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		posted.path, posted.token = request.URL.Path, request.Header.Get(flowlog.TokenHeader)
		posted.contentType = request.Header.Get("Content-Type")
		posted.body, _ = io.ReadAll(request.Body)
		if bytes.Equal(posted.body, []byte("busy")) {
			response.Header().Set("Retry-After", "7")
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = response.Write([]byte("sealed answer"))
	}))
	t.Cleanup(server.Close)
	client := New()
	client.httpClient = server.Client()
	origin, _ := url.Parse(server.URL + "/ignored/path")
	machine, _ := key.NewMachinePrivate(nil)
	var delivered []controlplane.FlowTicket
	run := &sessionRun{stream: &netmapStream{
		client: client, origin: origin, keys: profileKeys{machine: machine},
		options: controlplane.NetmapOptions{FlowTickets: func(ticket controlplane.FlowTicket) {
			delivered = append(delivered, ticket)
		}},
	}}
	run.flowTicket(&mtcpv1.FlowTicket{Token: []byte("token"), ReceiverKey: make([]byte, 31), NotAfterMs: 1})
	run.flowTicket(&mtcpv1.FlowTicket{Token: make([]byte, flowlog.MaxTokenSize+1), ReceiverKey: make([]byte, 32), NotAfterMs: 1})
	if len(delivered) != 0 {
		t.Fatalf("malformed tickets delivered: %d", len(delivered))
	}
	run.flowTicket(&mtcpv1.FlowTicket{Token: []byte("token"), ReceiverKey: make([]byte, 32), NotAfterMs: 1_800_000_000_000})
	run.flowTicket(&mtcpv1.FlowTicket{})
	if len(delivered) != 2 || len(delivered[1].Token) != 0 || delivered[0].Machine.Public() != machine.Public() ||
		!delivered[0].NotAfter.Equal(time.UnixMilli(1_800_000_000_000)) {
		t.Fatalf("delivered %+v", delivered)
	}
	result, err := delivered[0].Post(t.Context(), "header", []byte("batch"))
	if err != nil || result.Status != http.StatusOK || string(result.Body) != "sealed answer" {
		t.Fatalf("post %+v %v", result, err)
	}
	if posted.path != flowlog.Path || posted.token != "header" || posted.contentType != flowlog.ContentType ||
		string(posted.body) != "batch" {
		t.Fatalf("posted %+v", posted)
	}
	result, err = delivered[0].Post(t.Context(), "header", []byte("busy"))
	if err != nil || result.Status != http.StatusServiceUnavailable || result.RetryAfter != 7*time.Second ||
		len(result.Body) != 0 {
		t.Fatalf("busy %+v %v", result, err)
	}
}

func TestRetryAfter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	for value, want := range map[string]time.Duration{
		"": 0, "7": 7 * time.Second, "-3": 0, "99999": time.Hour, "soon": 0,
		now.Add(90 * time.Second).Format(http.TimeFormat): 90 * time.Second,
		now.Add(-time.Minute).Format(http.TimeFormat):     0,
	} {
		if got := retryAfter(value, now); got != want {
			t.Errorf("retryAfter(%q) = %v, want %v", value, got, want)
		}
	}
}
