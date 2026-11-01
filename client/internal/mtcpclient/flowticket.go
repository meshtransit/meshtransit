package mtcpclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/shared/flowlog"
)

// flowReportCapability is flow.report1: the node counts its traffic and
// sends connection logs with the token of FlowTicket (mtcp-v1 §9.1).
const flowReportCapability = "flow.report1"

// maxFlowAnswer bounds a receiver's answer body: one frame.
const maxFlowAnswer = 2 + 65535

// flowTicket hands a FlowTicket to the daemon with the session's machine key
// and a way to post to the control origin. A malformed ticket ends nothing:
// logging stays as it was.
func (run *sessionRun) flowTicket(ticket *mtcpv1.FlowTicket) {
	deliver := run.stream.options.FlowTickets
	if deliver == nil {
		return
	}
	token := ticket.GetToken()
	if len(token) == 0 {
		deliver(controlplane.FlowTicket{})
		return
	}
	if len(token) > flowlog.MaxTokenSize || len(ticket.GetReceiverKey()) != 32 || ticket.GetNotAfterMs() <= 0 {
		return
	}
	client, origin := run.stream.client, run.stream.origin
	deliver(controlplane.FlowTicket{
		Token: bytes.Clone(token), ReceiverKey: bytes.Clone(ticket.GetReceiverKey()),
		NotAfter: time.UnixMilli(ticket.GetNotAfterMs()), Machine: run.stream.keys.machine,
		Post: func(ctx context.Context, header string, body []byte) (controlplane.FlowPostResult, error) {
			return client.postFlow(ctx, origin, header, body)
		},
	})
}

// postFlow sends one connection log request to origin's fixed path: the
// same TLS, no proxy and no redirects as the control channel (ADR-054).
func (c *Client) postFlow(ctx context.Context, origin *url.URL, header string, body []byte,
) (controlplane.FlowPostResult, error) {
	target := url.URL{Scheme: origin.Scheme, Host: origin.Host, Path: flowlog.Path}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return controlplane.FlowPostResult{}, fmt.Errorf("mtcp: connection log request: %w", err)
	}
	request.Header.Set(flowlog.TokenHeader, header)
	request.Header.Set("Content-Type", flowlog.ContentType)
	// The control client's 15-second limit would cut a large batch on a
	// slow uplink short every time: the caller's context bounds it instead.
	flowClient := &http.Client{Transport: c.httpClient.Transport, CheckRedirect: c.httpClient.CheckRedirect}
	response, err := flowClient.Do(request)
	if err != nil {
		return controlplane.FlowPostResult{}, fmt.Errorf("mtcp: connection log request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	result := controlplane.FlowPostResult{Status: response.StatusCode}
	result.RetryAfter = retryAfter(response.Header.Get("Retry-After"), c.now())
	if response.StatusCode == http.StatusOK {
		answer, err := io.ReadAll(io.LimitReader(response.Body, maxFlowAnswer+1))
		if err != nil {
			return controlplane.FlowPostResult{}, fmt.Errorf("mtcp: connection log answer: %w", err)
		}
		if len(answer) > maxFlowAnswer {
			return controlplane.FlowPostResult{}, fmt.Errorf("mtcp: connection log answer over %d bytes", maxFlowAnswer)
		}
		result.Body = answer
	}
	return result, nil
}

// retryAfter reads a Retry-After header, seconds or an HTTP date, capped at
// an hour; 0 when absent or unreadable.
func retryAfter(value string, now time.Time) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		return min(max(time.Duration(seconds)*time.Second, 0), time.Hour)
	}
	if at, err := http.ParseTime(value); err == nil {
		return min(max(at.Sub(now), 0), time.Hour)
	}
	return 0
}
