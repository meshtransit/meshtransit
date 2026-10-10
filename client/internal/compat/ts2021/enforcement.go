package ts2021

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"time"

	"tailscale.com/types/key"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/shared/policydigest"
)

// EnforcementReport is controlplane.EnforcementReport.
type EnforcementReport = controlplane.EnforcementReport

const (
	enforcementPath = "machine/meshtransit/enforcement"
	// enforcementConfirm resends a new report once, so a report that raced
	// the start of its map session on Core is not lost.
	enforcementConfirm = 30 * time.Second
	// enforcementHeartbeat keeps the evidence fresh while nothing changes.
	enforcementHeartbeat = 5 * time.Minute
	// enforcementUnsupportedDelay spaces retries to a Core that does not
	// accept reports yet.
	enforcementUnsupportedDelay = 30 * time.Minute
	enforcementRetryMinimum     = 2 * time.Second
	enforcementRetryMaximum     = time.Minute
	maxEnforcementResponseBytes = 4 << 10
)

var (
	// ErrEnforcementReport classifies a report Core did not store.
	ErrEnforcementReport = errors.New("ts2021: enforcement report")
	// errEnforcementUnsupported reports a Core without the report endpoint.
	errEnforcementUnsupported = errors.New("ts2021: enforcement reports unsupported")
	// errEnforcementRefused reports a report Core judged malformed.
	errEnforcementRefused = errors.New("ts2021: enforcement report refused")
)

type enforcementReportWire struct {
	Version   int                 `json:"version"`
	NodeKey   string              `json:"node_key"`
	Digest    policydigest.Digest `json:"digest"`
	Grants    int                 `json:"grants"`
	AppliedAt time.Time           `json:"applied_at"`
}

// runEnforcementReports sends what the packet filter enforces over fresh
// Noise sessions to the pinned control key.
func (c *Client) runEnforcementReports(
	ctx context.Context,
	controlURL string,
	machineKey key.MachinePrivate,
	nodeKey key.NodePrivate,
	controlKey key.MachinePublic,
	options NetmapOptions,
) {
	runEnforcementLoop(ctx, options.EnforcementReports, func(sendCtx context.Context, report EnforcementReport) error {
		return c.sendEnforcementReport(sendCtx, controlURL, machineKey, nodeKey, controlKey, options, report)
	})
}

// runEnforcementLoop sends the latest report, confirms it once, then repeats
// it every heartbeat. Failures are retried with backoff and never end the map
// session: reports are evidence, not authority.
func runEnforcementLoop(
	ctx context.Context,
	reports <-chan EnforcementReport,
	send func(context.Context, EnforcementReport) error,
) {
	var latest EnforcementReport
	pending := false
	confirmed := false
	backoff := enforcementRetryMinimum
	timer := time.NewTimer(time.Hour)
	stopTimer(timer)
	defer stopTimer(timer)
	for {
		select {
		case <-ctx.Done():
			return
		case report, open := <-reports:
			if !open {
				reports = nil
				continue
			}
			stopTimer(timer)
			latest, pending, confirmed, backoff = report, true, false, enforcementRetryMinimum
		case <-timer.C:
			pending = !latest.Digest.IsZero()
		}
		if !pending {
			continue
		}
		pending = false
		err := send(ctx, latest)
		next := enforcementHeartbeat
		switch {
		case ctx.Err() != nil:
			return
		case err == nil:
			backoff = enforcementRetryMinimum
			if !confirmed {
				confirmed, next = true, enforcementConfirm
			}
		case errors.Is(err, errEnforcementUnsupported):
			next = enforcementUnsupportedDelay
		case errors.Is(err, errEnforcementRefused):
		default:
			next = jitteredReconnectDelay(backoff)
			backoff = min(backoff*2, enforcementRetryMaximum)
		}
		timer.Reset(next)
	}
}

func (c *Client) sendEnforcementReport(
	ctx context.Context,
	controlURL string,
	machineKey key.MachinePrivate,
	nodeKey key.NodePrivate,
	controlKey key.MachinePublic,
	options NetmapOptions,
	report EnforcementReport,
) error {
	discovered, err := c.discoverControlKey(ctx, controlURL)
	if err != nil {
		return err
	}
	if !constantTimeFingerprintEqual(discovered.fingerprint, options.PinnedFingerprint) ||
		discovered.publicKey != controlKey {
		return ErrControlKeyChanged
	}
	encoded, err := encodeEnforcementReport(nodeKey.Public(), report)
	if err != nil {
		return err
	}
	endpoint := *discovered.endpoint
	endpoint.RawQuery = ""
	endpoint.Path = path.Join("/", path.Dir(discovered.endpoint.Path), enforcementPath)
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint.String(),
		bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEnforcementReport, err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "meshd")
	httpClient, transport, dialed := newNoiseHTTPClient(discovered, &endpoint, machineKey, controlKey)
	defer transport.CloseIdleConnections()
	response, err := httpClient.Do(request)
	if err != nil {
		select {
		case connection := <-dialed:
			_ = connection.Close()
		default:
		}
		return fmt.Errorf("%w: %w", ErrEnforcementReport, err)
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxEnforcementResponseBytes))
	return classifyEnforcementStatus(response.StatusCode)
}

func encodeEnforcementReport(nodeKey key.NodePublic, report EnforcementReport) ([]byte, error) {
	if report.Digest.IsZero() || report.Grants < 0 || report.AppliedAt.IsZero() {
		return nil, fmt.Errorf("%w: incomplete report", ErrEnforcementReport)
	}
	encoded, err := json.Marshal(enforcementReportWire{
		Version: 1, NodeKey: nodeKey.String(), Digest: report.Digest, Grants: report.Grants,
		AppliedAt: report.AppliedAt.UTC(),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encoding: %w", ErrEnforcementReport, err)
	}
	return encoded, nil
}

func classifyEnforcementStatus(status int) error {
	switch status {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusNotFound:
		return errEnforcementUnsupported
	case http.StatusBadRequest:
		return errEnforcementRefused
	default:
		// 409: Core has not recorded this session yet; 5xx: retry later.
		return fmt.Errorf("%w: control returned http %d", ErrEnforcementReport, status)
	}
}
