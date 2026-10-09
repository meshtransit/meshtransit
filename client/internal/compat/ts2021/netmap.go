package ts2021

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
)

const (
	maxNetmapFrameBytes    = 16 << 20
	maxNetmapErrorBytes    = 4 << 10
	netmapReadTimeout      = 2 * time.Minute
	minReconnectDelay      = time.Second
	maxReconnectDelay      = 30 * time.Second
	reconnectResetAfter    = 30 * time.Second
	maxIgnoredDNSSuffixes  = 512
	maxIgnoredCertDomains  = 256
	meshDataPlaneAuditLogs = tailcfg.NodeCapability("https://meshtransit.io/cap/data-plane-audit-logs")
)

var (
	// ErrNetmapRejected indicates a permanent client or registration error.
	ErrNetmapRejected = errors.New("ts2021: netmap request rejected")
	// ErrNetmapInvalid indicates that a received update failed validation.
	ErrNetmapInvalid = errors.New("ts2021: invalid netmap update")
	// ErrNetmapConsumer indicates that the product consumer rejected a snapshot.
	ErrNetmapConsumer = errors.New("ts2021: netmap consumer failed")
	// ErrNetmapAuthorityRevoked indicates that an authenticated control stream
	// explicitly withdrew the active session's authority.
	ErrNetmapAuthorityRevoked = errors.New("ts2021: netmap authority revoked")
	// ErrNetmapAuthorityPaused indicates that control suspended this Device:
	// it keeps its identity and should retry until an administrator resumes it.
	ErrNetmapAuthorityPaused = errors.New("ts2021: netmap authority paused")
	// ErrEndpointUpdate indicates that a candidate publication did not complete.
	ErrEndpointUpdate = errors.New("ts2021: endpoint update failed")
)

// NetmapOptions contains stable host facts, the persisted control-key pin, and
// an optional active-session stream of complete candidate sets.
type NetmapOptions struct {
	// EnableDeviceAliases explicitly advertises the qualified peer translation contract.
	EnableDeviceAliases bool
	Hostname            string
	Version             string
	PinnedFingerprint   string
	PeerProbePublicKey  string
	Candidates          pathdiscovery.Set
	PreferredRelay      int
	HasPreferredRelay   bool
	EndpointUpdates     <-chan EndpointUpdate
	// EnforcementReports, when set, carries what the packet filter enforces;
	// each report is sent to Core and repeated while it stays current.
	EnforcementReports <-chan EnforcementReport
}

// EndpointUpdate is one complete product-owned network presence update. The
// direct candidates and preferred relay are published atomically.
type EndpointUpdate struct {
	Candidates        pathdiscovery.Set
	PreferredRelay    int
	HasPreferredRelay bool
}

// NetmapHandler consumes one fully validated, defensive network snapshot.
type NetmapHandler func(context.Context, networkmap.Snapshot) error

// StreamNetmap maintains a bounded streaming map session until cancellation or
// a permanent security/registration failure. Reconnects always re-verify the
// persisted control key and use a fresh full snapshot before accepting deltas.
func (c *Client) StreamNetmap(
	ctx context.Context,
	controlURL string,
	material KeyMaterial,
	options NetmapOptions,
	handler NetmapHandler,
) error {
	if c == nil || c.httpClient == nil {
		return errors.New("ts2021: client is not initialized")
	}
	if handler == nil {
		return errors.New("ts2021: netmap handler is required")
	}
	discoKey, err := parseNetmapOptions(options)
	if err != nil {
		return err
	}
	machineKey, nodeKey, controlKey, err := parseMaterial(material)
	if err != nil {
		return err
	}
	if options.EnforcementReports != nil {
		reportCtx, stopReports := context.WithCancel(ctx)
		var reports sync.WaitGroup
		reports.Go(func() {
			c.runEnforcementReports(reportCtx, controlURL, machineKey, nodeKey, controlKey, options)
		})
		defer func() {
			stopReports()
			reports.Wait()
		}()
	}
	endpointState := newEndpointState(EndpointUpdate{
		Candidates:        options.Candidates,
		PreferredRelay:    options.PreferredRelay,
		HasPreferredRelay: options.HasPreferredRelay,
	})
	if options.EndpointUpdates == nil {
		return c.streamNetmapLoop(
			ctx,
			controlURL,
			machineKey,
			nodeKey,
			controlKey,
			discoKey,
			options,
			endpointState,
			handler,
		)
	}

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	mapDone := make(chan error, 1)
	go func() {
		mapDone <- c.streamNetmapLoop(
			streamCtx,
			controlURL,
			machineKey,
			nodeKey,
			controlKey,
			discoKey,
			options,
			endpointState,
			handler,
		)
	}()
	endpointDone := make(chan error, 1)
	go func() {
		endpointDone <- c.runEndpointUpdates(
			streamCtx,
			controlURL,
			machineKey,
			nodeKey,
			controlKey,
			discoKey,
			options,
			endpointState,
		)
	}()

	select {
	case err := <-mapDone:
		cancel()
		<-endpointDone

		return err
	case err := <-endpointDone:
		cancel()
		<-mapDone

		return err
	case <-ctx.Done():
		cancel()
		<-mapDone
		<-endpointDone

		return ctx.Err()
	}
}

func (c *Client) streamNetmapLoop(
	ctx context.Context,
	controlURL string,
	machineKey key.MachinePrivate,
	nodeKey key.NodePrivate,
	controlKey key.MachinePublic,
	discoKey key.DiscoPublic,
	options NetmapOptions,
	endpointState *endpointState,
	handler NetmapHandler,
) error {
	accumulator := newMapAccumulator()

	return runNetmapReconnectLoop(
		ctx,
		func(pollCtx context.Context) (bool, error) {
			return c.pollNetmapOnce(
				pollCtx,
				controlURL,
				machineKey,
				nodeKey,
				controlKey,
				discoKey,
				options,
				endpointState,
				accumulator,
				handler,
			)
		},
		time.Now,
		jitteredReconnectDelay,
		waitForReconnect,
	)
}

type (
	netmapPollFunc     func(context.Context) (bool, error)
	reconnectDelayFunc func(time.Duration) time.Duration
	reconnectWaitFunc  func(context.Context, time.Duration) error
)

func runNetmapReconnectLoop(
	ctx context.Context,
	poll netmapPollFunc,
	now func() time.Time,
	reconnectDelay reconnectDelayFunc,
	wait reconnectWaitFunc,
) error {
	backoff := minReconnectDelay
	for {
		startedAt := now()
		receivedMap, pollErr := poll(ctx)
		endedAt := now()
		if err := ctx.Err(); err != nil {
			return err
		}
		if isPermanentNetmapError(pollErr) {
			return pollErr
		}
		if receivedMap && endedAt.Sub(startedAt) >= reconnectResetAfter {
			backoff = minReconnectDelay
		}
		delay := reconnectDelay(backoff)
		if err := wait(ctx, delay); err != nil {
			return err
		}
		if backoff < maxReconnectDelay {
			backoff *= 2
			if backoff > maxReconnectDelay {
				backoff = maxReconnectDelay
			}
		}
	}
}

func (c *Client) pollNetmapOnce(
	ctx context.Context,
	controlURL string,
	machineKey key.MachinePrivate,
	nodeKey key.NodePrivate,
	controlKey key.MachinePublic,
	discoKey key.DiscoPublic,
	options NetmapOptions,
	endpointState *endpointState,
	accumulator *mapAccumulator,
	handler NetmapHandler,
) (bool, error) {
	discovered, err := c.discoverControlKey(ctx, controlURL)
	if err != nil {
		return false, err
	}
	if _, err := verifyFingerprint(
		options.PinnedFingerprint,
		controlKeyFingerprint(controlKey),
	); err != nil {
		return false, fmt.Errorf("%w: persisted pin and key disagree", ErrInvalidMaterial)
	}
	if !constantTimeFingerprintEqual(discovered.fingerprint, options.PinnedFingerprint) ||
		discovered.publicKey != controlKey {
		return false, ErrControlKeyChanged
	}

	if err := c.sendEndpointState(
		ctx,
		discovered,
		machineKey,
		nodeKey,
		controlKey,
		discoKey,
		options,
		endpointState,
	); err != nil {
		return false, err
	}

	latest, _ := endpointState.snapshot()
	options.Candidates = latest.Candidates
	options.PreferredRelay = latest.PreferredRelay
	options.HasPreferredRelay = latest.HasPreferredRelay
	mapRequest := newMapRequest(nodeKey, discoKey, options, true)
	exchange, err := c.openMapExchange(
		ctx,
		discovered,
		machineKey,
		nodeKey,
		controlKey,
		mapRequest,
	)
	if err != nil {
		return false, err
	}
	defer exchange.Close()
	response := exchange.response
	streamConnection := exchange.connection

	receivedMap := false
	accumulator.resetSession()
	for {
		responseFrame, err := readMapFrameWithWatchdog(
			streamConnection,
			response.Body,
			time.Now(),
		)
		if err != nil {
			return receivedMap, err
		}

		update := tailcfg.MapResponse{}
		if err := json.Unmarshal(responseFrame, &update); err != nil {
			return receivedMap, fmt.Errorf("%w: decoding response: %w", ErrNetmapInvalid, err)
		}
		if update.KeepAlive {
			continue
		}
		snapshot, changed, err := accumulator.apply(update, time.Now())
		if err != nil {
			return receivedMap, err
		}
		if !changed {
			continue
		}
		if snapshot.Self.PublicKey != nodeKey.Public().String() {
			return receivedMap, fmt.Errorf(
				"%w: self public key does not match the registered identity",
				ErrNetmapInvalid,
			)
		}
		if err := validateRequestedDeviceAliases(snapshot, options.EnableDeviceAliases); err != nil {
			return receivedMap, err
		}
		if err := handler(ctx, snapshot); err != nil {
			return receivedMap, fmt.Errorf("%w: %w", ErrNetmapConsumer, err)
		}
		receivedMap = true
	}
}

type readDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

func readMapFrameWithWatchdog(
	connection readDeadlineSetter,
	reader io.Reader,
	now time.Time,
) ([]byte, error) {
	if err := connection.SetReadDeadline(now.Add(netmapReadTimeout)); err != nil {
		return nil, fmt.Errorf("ts2021: setting netmap watchdog: %w", err)
	}
	frame, err := readMapFrame(reader)
	if err != nil {
		return nil, fmt.Errorf("ts2021: reading netmap stream: %w", err)
	}

	return frame, nil
}

type endpointState struct {
	mu         sync.RWMutex
	publishMu  sync.Mutex
	update     EndpointUpdate
	shouldSend bool
}

func newEndpointState(update EndpointUpdate) *endpointState {
	return &endpointState{
		update:     update,
		shouldSend: true,
	}
}

func (s *endpointState) set(update EndpointUpdate) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.update.Candidates.Equal(update.Candidates) &&
		s.update.PreferredRelay == update.PreferredRelay &&
		s.update.HasPreferredRelay == update.HasPreferredRelay {
		return false
	}
	s.update = update
	s.shouldSend = true

	return true
}

func (s *endpointState) snapshot() (EndpointUpdate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.update, s.shouldSend
}

func (c *Client) sendEndpointState(
	ctx context.Context,
	discovered discoveredControlKey,
	machineKey key.MachinePrivate,
	nodeKey key.NodePrivate,
	controlKey key.MachinePublic,
	discoKey key.DiscoPublic,
	options NetmapOptions,
	state *endpointState,
) error {
	if state == nil {
		return errors.New("ts2021: endpoint state is required")
	}
	state.publishMu.Lock()
	defer state.publishMu.Unlock()
	update, shouldSend := state.snapshot()
	if !shouldSend {
		return nil
	}
	options.Candidates = update.Candidates
	options.PreferredRelay = update.PreferredRelay
	options.HasPreferredRelay = update.HasPreferredRelay

	return c.sendEndpointUpdate(
		ctx,
		discovered,
		machineKey,
		nodeKey,
		controlKey,
		discoKey,
		options,
	)
}

func (c *Client) runEndpointUpdates(
	ctx context.Context,
	controlURL string,
	machineKey key.MachinePrivate,
	nodeKey key.NodePrivate,
	controlKey key.MachinePublic,
	discoKey key.DiscoPublic,
	options NetmapOptions,
	state *endpointState,
) error {
	updates := options.EndpointUpdates
	backoff := minReconnectDelay
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case update, open := <-updates:
			if !open {
				if err := ctx.Err(); err != nil {
					return err
				}

				return fmt.Errorf("%w: update channel closed", ErrEndpointUpdate)
			}
			if err := validateEndpointUpdate(update); err != nil {
				return err
			}
			if !state.set(update) {
				continue
			}
		}

		for {
			err := c.publishEndpointState(
				ctx,
				controlURL,
				machineKey,
				nodeKey,
				controlKey,
				discoKey,
				options,
				state,
			)
			if err == nil {
				backoff = minReconnectDelay

				break
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if isPermanentNetmapError(err) {
				return err
			}

			delay := jitteredReconnectDelay(backoff)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				stopTimer(timer)

				return ctx.Err()
			case update, open := <-updates:
				stopTimer(timer)
				if !open {
					return fmt.Errorf("%w: update channel closed", ErrEndpointUpdate)
				}
				if err := validateEndpointUpdate(update); err != nil {
					return err
				}
				state.set(update)
				backoff = minReconnectDelay
			case <-timer.C:
				if backoff < maxReconnectDelay {
					backoff *= 2
					if backoff > maxReconnectDelay {
						backoff = maxReconnectDelay
					}
				}
			}
		}
	}
}

func stopTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func (c *Client) publishEndpointState(
	ctx context.Context,
	controlURL string,
	machineKey key.MachinePrivate,
	nodeKey key.NodePrivate,
	controlKey key.MachinePublic,
	discoKey key.DiscoPublic,
	options NetmapOptions,
	state *endpointState,
) error {
	discovered, err := c.discoverControlKey(ctx, controlURL)
	if err != nil {
		return err
	}
	if _, err := verifyFingerprint(
		options.PinnedFingerprint,
		controlKeyFingerprint(controlKey),
	); err != nil {
		return fmt.Errorf("%w: persisted pin and key disagree", ErrInvalidMaterial)
	}
	if !constantTimeFingerprintEqual(discovered.fingerprint, options.PinnedFingerprint) ||
		discovered.publicKey != controlKey {
		return ErrControlKeyChanged
	}

	return c.sendEndpointState(
		ctx,
		discovered,
		machineKey,
		nodeKey,
		controlKey,
		discoKey,
		options,
		state,
	)
}

type mapExchange struct {
	response   *http.Response
	connection net.Conn
	transport  *http.Transport
}

func (e *mapExchange) Close() {
	_ = e.response.Body.Close()
	e.transport.CloseIdleConnections()
}

func (c *Client) sendEndpointUpdate(
	ctx context.Context,
	discovered discoveredControlKey,
	machineKey key.MachinePrivate,
	nodeKey key.NodePrivate,
	controlKey key.MachinePublic,
	discoKey key.DiscoPublic,
	options NetmapOptions,
) (returnErr error) {
	defer func() {
		if returnErr != nil {
			returnErr = fmt.Errorf("%w: %w", ErrEndpointUpdate, returnErr)
		}
	}()
	request := newMapRequest(nodeKey, discoKey, options, false)
	exchange, err := c.openMapExchange(
		ctx,
		discovered,
		machineKey,
		nodeKey,
		controlKey,
		request,
	)
	if err != nil {
		return fmt.Errorf("ts2021: updating endpoints: %w", err)
	}
	defer exchange.Close()
	if err := exchange.connection.SetReadDeadline(time.Now().Add(requestTimeout)); err != nil {
		return fmt.Errorf("ts2021: setting endpoint-update deadline: %w", err)
	}
	read, err := io.Copy(
		io.Discard,
		io.LimitReader(exchange.response.Body, maxNetmapFrameBytes+1),
	)
	if err != nil {
		return fmt.Errorf("ts2021: draining endpoint-update response: %w", err)
	}
	if read > maxNetmapFrameBytes {
		return errors.New("ts2021: endpoint-update response exceeds the allowed size")
	}

	return nil
}

// newNoiseHTTPClient returns an HTTP/2 client whose single connection is a
// Noise session to the pinned control key, and the channel that hands over
// that connection once dialed.
func newNoiseHTTPClient(
	discovered discoveredControlKey,
	endpoint *url.URL,
	machineKey key.MachinePrivate,
	controlKey key.MachinePublic,
) (*http.Client, *http.Transport, chan net.Conn) {
	expectedAddress := net.JoinHostPort(endpoint.Hostname(), "443")
	dialed := make(chan net.Conn, 1)
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{
		Protocols:              protocols,
		DisableCompression:     true,
		MaxConnsPerHost:        1,
		MaxIdleConnsPerHost:    1,
		MaxResponseHeaderBytes: maxNetmapErrorBytes,
		ResponseHeaderTimeout:  requestTimeout,
		ExpectContinueTimeout:  requestTimeout,
		DialTLSContext: func(
			dialCtx context.Context,
			network string,
			address string,
		) (net.Conn, error) {
			if network != "tcp" || address != expectedAddress {
				return nil, errors.New("ts2021: netmap transport attempted an unexpected dial")
			}

			connection, err := strictBaseNoiseConnection(
				dialCtx,
				discovered.endpoint,
				machineKey,
				controlKey,
			)
			if err != nil {
				return nil, err
			}
			wrapped := newEarlyPayloadConn(connection)
			select {
			case dialed <- wrapped:
				return wrapped, nil
			default:
				_ = wrapped.Close()

				return nil, errors.New("ts2021: netmap transport opened multiple connections")
			}
		},
	}
	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return httpClient, transport, dialed
}

func (c *Client) openMapExchange(
	ctx context.Context,
	discovered discoveredControlKey,
	machineKey key.MachinePrivate,
	nodeKey key.NodePrivate,
	controlKey key.MachinePublic,
	mapRequest controlMapRequest,
) (*mapExchange, error) {
	encoded, err := marshalMapRequest(mapRequest)
	if err != nil {
		return nil, fmt.Errorf("ts2021: encoding netmap request: %w", err)
	}
	endpoint := netmapEndpoint(discovered.endpoint)
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint.String(),
		bytes.NewReader(encoded),
	)
	if err != nil {
		return nil, fmt.Errorf("ts2021: creating netmap request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "meshd")
	request.Header.Set(tailcfg.LBHeader, nodeKey.Public().String())

	httpClient, transport, dialed := newNoiseHTTPClient(discovered, endpoint, machineKey, controlKey)

	response, err := httpClient.Do(request)
	if err != nil {
		transport.CloseIdleConnections()
		select {
		case connection := <-dialed:
			_ = connection.Close()
		default:
		}

		return nil, fmt.Errorf("ts2021: opening netmap exchange: %w", err)
	}
	var connection net.Conn
	select {
	case connection = <-dialed:
	default:
		_ = response.Body.Close()
		transport.CloseIdleConnections()

		return nil, errors.New("ts2021: netmap exchange has no owned connection")
	}
	if response.StatusCode != http.StatusOK {
		defer func() { _ = response.Body.Close() }()
		defer transport.CloseIdleConnections()
		if err := connection.SetReadDeadline(time.Now().Add(requestTimeout)); err != nil {
			return nil, fmt.Errorf("ts2021: setting netmap error-response deadline: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(response.Body, maxNetmapErrorBytes))
		message := sanitizeServerError(string(body))
		if response.StatusCode == http.StatusLocked {
			return nil, fmt.Errorf("%w: control endpoint returned http 423", ErrNetmapAuthorityPaused)
		}
		if response.StatusCode >= 400 && response.StatusCode < 500 {
			return nil, fmt.Errorf(
				"%w: control endpoint returned http %d: %s",
				ErrNetmapRejected,
				response.StatusCode,
				message,
			)
		}

		return nil, fmt.Errorf(
			"ts2021: netmap endpoint returned http %d: %s",
			response.StatusCode,
			message,
		)
	}

	return &mapExchange{
		response:   response,
		connection: connection,
		transport:  transport,
	}, nil
}

// controlMapRequest confines the product extension to the compatibility adapter.
// The declaration is support only; Core derives authority from Noise identity.
type controlMapRequest struct {
	tailcfg.MapRequest
	DeviceAliasVersion uint8 `json:"DeviceAliasVersion,omitempty"`
}

func marshalMapRequest(request controlMapRequest) ([]byte, error) {
	if request.Stream || request.Endpoints == nil || len(request.Endpoints) != 0 {
		return json.Marshal(request)
	}
	type requestWithEndpointWithdrawal struct {
		controlMapRequest
		Endpoints []netip.AddrPort `json:"Endpoints"`
	}

	return json.Marshal(requestWithEndpointWithdrawal{
		controlMapRequest: request,
		Endpoints:         []netip.AddrPort{},
	})
}

func newMapRequest(
	nodeKey key.NodePrivate,
	discoKey key.DiscoPublic,
	options NetmapOptions,
	stream bool,
) controlMapRequest {
	request := controlMapRequest{MapRequest: tailcfg.MapRequest{
		Version:   tailcfg.CurrentCapabilityVersion,
		KeepAlive: true,
		NodeKey:   nodeKey.Public(),
		DiscoKey:  discoKey,
		Stream:    stream,
		Hostinfo: &tailcfg.Hostinfo{
			IPNVersion:      options.Version,
			OS:              runtime.GOOS,
			Hostname:        options.Hostname,
			GoArch:          runtime.GOARCH,
			GoVersion:       runtime.Version(),
			NoLogsNoSupport: true,
		},
	}}
	if options.EnableDeviceAliases {
		request.DeviceAliasVersion = 1
	}
	if options.HasPreferredRelay {
		request.Hostinfo.NetInfo = &tailcfg.NetInfo{
			PreferredDERP: options.PreferredRelay,
		}
	}
	if !stream {
		request.OmitPeers = true
		candidates := options.Candidates.Candidates()
		request.Endpoints = make([]netip.AddrPort, len(candidates))
		request.EndpointTypes = make([]tailcfg.EndpointType, len(request.Endpoints))
		for index, candidate := range candidates {
			request.Endpoints[index] = candidate.Endpoint()
			request.EndpointTypes[index] = protocolEndpointType(candidate.Source())
		}
	}

	return request
}

func parseNetmapOptions(options NetmapOptions) (key.DiscoPublic, error) {
	discoKey, err := parsePeerProbePublicKey(options.PeerProbePublicKey)
	if err != nil {
		return key.DiscoPublic{}, err
	}
	if _, err := canonicalFingerprint(options.PinnedFingerprint); err != nil {
		return key.DiscoPublic{}, err
	}
	if err := validateDisplayText("hostname", options.Hostname, maxHostnameRunes); err != nil {
		return key.DiscoPublic{}, err
	}
	if err := validateCandidateSet(options.Candidates); err != nil {
		return key.DiscoPublic{}, err
	}
	if err := validatePreferredRelay(
		options.PreferredRelay,
		options.HasPreferredRelay,
	); err != nil {
		return key.DiscoPublic{}, err
	}
	if err := validateDisplayText("version", options.Version, maxVersionRunes); err != nil {
		return key.DiscoPublic{}, err
	}

	return discoKey, nil
}

func validateEndpointUpdate(update EndpointUpdate) error {
	if err := validateCandidateSet(update.Candidates); err != nil {
		return err
	}

	return validatePreferredRelay(update.PreferredRelay, update.HasPreferredRelay)
}

func validatePreferredRelay(regionID int, isSet bool) error {
	if regionID < 0 || regionID > 65_535 || (!isSet && regionID != 0) {
		return fmt.Errorf("%w: preferred relay is invalid", ErrInvalidMaterial)
	}

	return nil
}

func parsePeerProbePublicKey(value string) (key.DiscoPublic, error) {
	var discoKey key.DiscoPublic
	if err := discoKey.UnmarshalText([]byte(value)); err != nil ||
		discoKey.IsZero() || discoKey.String() != value {
		return key.DiscoPublic{}, fmt.Errorf(
			"%w: peer-probe public key is invalid",
			ErrInvalidMaterial,
		)
	}

	return discoKey, nil
}

func validateCandidateSet(candidates pathdiscovery.Set) error {
	validated, err := pathdiscovery.NewSet(candidates.Candidates())
	if err != nil || !validated.Equal(candidates) {
		return errors.New("ts2021: advertised candidates are invalid")
	}

	return nil
}

func protocolEndpointType(source pathdiscovery.Source) tailcfg.EndpointType {
	switch source {
	case pathdiscovery.SourceHost:
		return tailcfg.EndpointLocal
	case pathdiscovery.SourceServerReflexive:
		return tailcfg.EndpointSTUN
	case pathdiscovery.SourcePortMapping:
		return tailcfg.EndpointPortmapped
	case pathdiscovery.SourceConfigured:
		return tailcfg.EndpointExplicitConf
	default:
		return tailcfg.EndpointUnknownType
	}
}

func netmapEndpoint(keyURL *url.URL) *url.URL {
	endpoint := *keyURL
	endpoint.RawQuery = ""
	endpoint.Path = path.Join("/", path.Dir(keyURL.Path), "machine/map")

	return &endpoint
}

func readMapFrame(reader io.Reader) ([]byte, error) {
	var sizeBuffer [4]byte
	if _, err := io.ReadFull(reader, sizeBuffer[:]); err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint32(sizeBuffer[:])
	if size == 0 || size > maxNetmapFrameBytes {
		return nil, fmt.Errorf("netmap frame size %d is outside the allowed range", size)
	}
	frame := make([]byte, int(size))
	if _, err := io.ReadFull(reader, frame); err != nil {
		return nil, err
	}

	return frame, nil
}

func isPermanentNetmapError(err error) bool {
	return errors.Is(err, ErrInvalidMaterial) ||
		errors.Is(err, ErrInvalidFingerprint) ||
		errors.Is(err, ErrControlKeyChanged) ||
		errors.Is(err, ErrNetmapRejected) ||
		errors.Is(err, ErrNetmapInvalid) ||
		errors.Is(err, ErrNetmapAuthorityRevoked) ||
		// A pause ends this session; the daemon clears the data plane and
		// retries on its own schedule.
		errors.Is(err, ErrNetmapAuthorityPaused) ||
		errors.Is(err, ErrNetmapConsumer) ||
		errors.Is(err, networkmap.ErrInvalid)
}

func waitForReconnect(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func jitteredReconnectDelay(base time.Duration) time.Duration {
	if base <= time.Nanosecond {
		return base
	}
	half := base / 2
	random, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(half)))
	if err != nil {
		return half
	}

	return half + time.Duration(random.Int64())
}

type mapAccumulator struct {
	initialized   bool
	revision      uint64
	networkName   string
	controlTime   time.Time
	self          networkmap.Node
	peers         map[tailcfg.NodeID]networkmap.Node
	namedPolicies map[string][]networkmap.Rule
	relays        map[int]networkmap.RelayRegion
	dns           *networkmap.DNSConfig
	audit         networkmap.AuditCredentials
	interchange   *interchangeGrant // immutable once held
}

func newMapAccumulator() *mapAccumulator {
	return &mapAccumulator{
		peers:         make(map[tailcfg.NodeID]networkmap.Node),
		namedPolicies: make(map[string][]networkmap.Rule),
		relays:        make(map[int]networkmap.RelayRegion),
	}
}

func (a *mapAccumulator) resetSession() { a.initialized = false }

func (a *mapAccumulator) apply(
	response tailcfg.MapResponse,
	now time.Time,
) (networkmap.Snapshot, bool, error) {
	if response.KeepAlive {
		return networkmap.Snapshot{}, false, nil
	}
	if !a.initialized && response.Node == nil {
		return networkmap.Snapshot{}, false, fmt.Errorf(
			"%w: initial response omitted self node",
			ErrNetmapInvalid,
		)
	}
	if a.isAuthorityRevocation(response) {
		return networkmap.Snapshot{}, false, ErrNetmapAuthorityRevoked
	}
	if a.isAuthorityPause(response) {
		return networkmap.Snapshot{}, false, ErrNetmapAuthorityPaused
	}

	candidate := a.clone()
	if !a.initialized {
		candidate = newMapAccumulator()
		candidate.revision = a.revision
	}
	if response.Node != nil {
		converted, err := convertNode(response.Node)
		if err != nil {
			return networkmap.Snapshot{}, false, err
		}
		candidate.self = converted
		// A grant that fails verification, or an entry without one, keeps
		// the previous grant until its ticket expires.
		if grant, present, grantErr := parseInterchange(response.Node, now); present && grantErr == nil &&
			grant.supersedes(candidate.interchange) {
			candidate.interchange = grant
		}
		if response.Node.DataPlaneAuditLogID != "" || response.DomainDataPlaneAuditLogID != "" {
			if !response.Node.CapMap.Contains(tailcfg.CapabilityDataPlaneAuditLogs) &&
				!response.Node.CapMap.Contains(meshDataPlaneAuditLogs) {
				return networkmap.Snapshot{}, false, fmt.Errorf(
					"%w: audit credentials were sent without capability",
					ErrNetmapInvalid,
				)
			}
			audit, err := networkmap.NewAuditCredentials(
				response.Node.DataPlaneAuditLogID,
				response.DomainDataPlaneAuditLogID,
				converted.ID,
			)
			if err != nil {
				return networkmap.Snapshot{}, false, fmt.Errorf("%w: %w", ErrNetmapInvalid, err)
			}
			candidate.audit = audit
		}
	}
	if response.Node == nil && response.DomainDataPlaneAuditLogID != "" {
		return networkmap.Snapshot{}, false, fmt.Errorf(
			"%w: audit network token changed without self node",
			ErrNetmapInvalid,
		)
	}
	if response.Domain != "" {
		candidate.networkName = response.Domain
	}
	if response.ControlTime != nil {
		candidate.controlTime = response.ControlTime.UTC()
	}

	if response.Peers != nil {
		candidate.peers = make(map[tailcfg.NodeID]networkmap.Node, len(response.Peers))
		for _, peer := range response.Peers {
			converted, err := convertNode(peer)
			if err != nil {
				return networkmap.Snapshot{}, false, err
			}
			if _, exists := candidate.peers[peer.ID]; exists {
				return networkmap.Snapshot{}, false, fmt.Errorf(
					"%w: full response contains duplicate peer id",
					ErrNetmapInvalid,
				)
			}
			candidate.peers[peer.ID] = converted
		}
	} else {
		changedIDs := make(map[tailcfg.NodeID]struct{}, len(response.PeersChanged))
		for _, peer := range response.PeersChanged {
			converted, err := convertNode(peer)
			if err != nil {
				return networkmap.Snapshot{}, false, err
			}
			if _, exists := changedIDs[peer.ID]; exists {
				return networkmap.Snapshot{}, false, fmt.Errorf(
					"%w: delta contains duplicate changed peer id",
					ErrNetmapInvalid,
				)
			}
			changedIDs[peer.ID] = struct{}{}
			candidate.peers[peer.ID] = converted
		}
		for _, id := range response.PeersRemoved {
			delete(candidate.peers, id)
		}
	}
	for _, patch := range response.PeersChangedPatch {
		candidate.applyPeerPatch(patch)
	}
	for id, online := range response.OnlineChange {
		peer, exists := candidate.peers[id]
		if !exists {
			continue
		}
		peer.OnlineKnown = true
		peer.Online = online
		candidate.peers[id] = peer
	}
	if response.PacketFilter != nil {
		rules, err := convertFilterRules(response.PacketFilter)
		if err != nil {
			return networkmap.Snapshot{}, false, err
		}
		candidate.namedPolicies["base"] = rules
	}
	if response.PacketFilters != nil {
		if wildcard, exists := response.PacketFilters["*"]; exists {
			if wildcard != nil {
				return networkmap.Snapshot{}, false, fmt.Errorf(
					"%w: reserved policy wildcard has rules",
					ErrNetmapInvalid,
				)
			}
			candidate.namedPolicies = make(map[string][]networkmap.Rule)
		}
		for name, rawRules := range response.PacketFilters {
			if name == "*" {
				continue
			}
			if rawRules == nil {
				delete(candidate.namedPolicies, name)
				continue
			}
			rules, err := convertFilterRules(rawRules)
			if err != nil {
				return networkmap.Snapshot{}, false, err
			}
			candidate.namedPolicies[name] = rules
		}
	}
	// A legacy DERP map is ignored: relays come only from the signed relay
	// map in the node's Interchange grant.
	if response.DNSConfig != nil {
		dnsConfig, err := convertDNSConfig(response.DNSConfig)
		if err != nil {
			return networkmap.Snapshot{}, false, err
		}
		candidate.dns = dnsConfig
	}
	if a.initialized {
		for id, peer := range candidate.peers {
			if previous, exists := a.peers[id]; exists {
				if err := networkmap.ValidateAliasAdvance(previous.Alias, peer.Alias); err != nil {
					return networkmap.Snapshot{}, false, fmt.Errorf("%w: %w", ErrNetmapInvalid, err)
				}
			}
		}
	}
	if a.initialized && equalMapAccumulatorState(a, candidate) {
		if _, err := networkmap.ValidateAndClone(candidate.snapshot(), now); err != nil {
			return networkmap.Snapshot{}, false, fmt.Errorf("%w: %w", ErrNetmapInvalid, err)
		}

		return networkmap.Snapshot{}, false, nil
	}

	candidate.revision++
	candidate.initialized = true
	snapshot := candidate.snapshot()
	validated, err := networkmap.ValidateAndClone(snapshot, now)
	if err != nil {
		return networkmap.Snapshot{}, false, fmt.Errorf("%w: %w", ErrNetmapInvalid, err)
	}
	*a = *candidate

	return validated, true, nil
}

func (a *mapAccumulator) isAuthorityRevocation(response tailcfg.MapResponse) bool {
	return a.initialized && response.Node != nil &&
		response.Node.ID > 0 &&
		uint64(response.Node.ID) == a.self.ID &&
		response.Node.Key.String() == a.self.PublicKey &&
		response.Node.Expired && !response.Node.MachineAuthorized &&
		response.Peers != nil && len(response.Peers) == 0 &&
		response.PacketFilter != nil && len(response.PacketFilter) == 0
}

// isAuthorityPause matches a withdrawal that keeps the identity: the self node
// is unauthorized but not expired, with every peer and rule cleared.
func (a *mapAccumulator) isAuthorityPause(response tailcfg.MapResponse) bool {
	return a.initialized && response.Node != nil &&
		response.Node.ID > 0 &&
		uint64(response.Node.ID) == a.self.ID &&
		response.Node.Key.String() == a.self.PublicKey &&
		!response.Node.Expired && !response.Node.MachineAuthorized &&
		response.Peers != nil && len(response.Peers) == 0 &&
		response.PacketFilter != nil && len(response.PacketFilter) == 0
}

func (a *mapAccumulator) applyPeerPatch(patch *tailcfg.PeerChange) {
	if patch == nil {
		return
	}
	peer, exists := a.peers[patch.NodeID]
	if !exists {
		return
	}
	if patch.DERPRegion != 0 {
		peer.HomeRelay = patch.DERPRegion
	}
	if patch.Endpoints != nil {
		peer.Endpoints = append([]netip.AddrPort(nil), patch.Endpoints...)
	}
	if patch.Key != nil {
		peer.PublicKey = patch.Key.String()
	}
	if patch.DiscoKey != nil {
		peer.DiscoveryKey = patch.DiscoKey.String()
	}
	if patch.Online != nil {
		peer.OnlineKnown = true
		peer.Online = *patch.Online
	}
	if patch.KeyExpiry != nil {
		peer.KeyExpiry = patch.KeyExpiry.UTC()
	}
	a.peers[patch.NodeID] = peer
}

func (a *mapAccumulator) snapshot() networkmap.Snapshot {
	peerIDs := make([]tailcfg.NodeID, 0, len(a.peers))
	for id := range a.peers {
		peerIDs = append(peerIDs, id)
	}
	sort.Slice(peerIDs, func(left, right int) bool { return peerIDs[left] < peerIDs[right] })
	peers := make([]networkmap.Node, 0, len(peerIDs))
	for _, id := range peerIDs {
		peers = append(peers, a.peers[id])
	}

	policyNames := make([]string, 0, len(a.namedPolicies))
	for name := range a.namedPolicies {
		policyNames = append(policyNames, name)
	}
	sort.Strings(policyNames)
	var policy []networkmap.Rule
	for _, name := range policyNames {
		policy = append(policy, a.namedPolicies[name]...)
	}

	snapshot := networkmap.Snapshot{
		Revision:    a.revision,
		NetworkName: a.networkName,
		ControlTime: a.controlTime,
		Self:        a.self,
		Peers:       peers,
		Policy:      policy,
		Relays:      a.relays,
		DNS:         a.dns,
		Audit:       a.audit,
	}
	if a.interchange != nil {
		snapshot.Interchange, snapshot.Relays = a.interchange.snapshot()
	}
	return snapshot
}

func (a *mapAccumulator) clone() *mapAccumulator {
	cloned := &mapAccumulator{
		initialized:   a.initialized,
		revision:      a.revision,
		networkName:   a.networkName,
		controlTime:   a.controlTime,
		self:          cloneMapNode(a.self),
		peers:         make(map[tailcfg.NodeID]networkmap.Node, len(a.peers)),
		namedPolicies: make(map[string][]networkmap.Rule, len(a.namedPolicies)),
		relays:        make(map[int]networkmap.RelayRegion, len(a.relays)),
		dns:           cloneDNSConfig(a.dns),
		audit:         a.audit,
		interchange:   a.interchange,
	}
	for id, peer := range a.peers {
		cloned.peers[id] = cloneMapNode(peer)
	}
	for name, rules := range a.namedPolicies {
		cloned.namedPolicies[name] = cloneRules(rules)
	}
	for id, region := range a.relays {
		region.Nodes = append([]networkmap.RelayNode(nil), region.Nodes...)
		cloned.relays[id] = region
	}

	return cloned
}

func equalMapAccumulatorState(left, right *mapAccumulator) bool {
	if left == nil || right == nil {
		return left == right
	}

	return left.networkName == right.networkName &&
		left.controlTime.Equal(right.controlTime) &&
		equalMapNode(left.self, right.self) &&
		maps.EqualFunc(left.peers, right.peers, equalMapNode) &&
		maps.EqualFunc(left.namedPolicies, right.namedPolicies, equalRules) &&
		maps.EqualFunc(left.relays, right.relays, equalRelayRegion) &&
		equalDNSConfig(left.dns, right.dns) &&
		left.audit == right.audit &&
		left.interchange.equal(right.interchange)
}

func equalMapNode(left, right networkmap.Node) bool {
	return left.ID == right.ID && left.StableID == right.StableID &&
		left.Name == right.Name && left.PublicKey == right.PublicKey &&
		left.DiscoveryKey == right.DiscoveryKey &&
		slices.Equal(left.Addresses, right.Addresses) &&
		slices.Equal(left.AllowedIPs, right.AllowedIPs) &&
		slices.Equal(left.Endpoints, right.Endpoints) &&
		left.HomeRelay == right.HomeRelay &&
		left.OnlineKnown == right.OnlineKnown && left.Online == right.Online &&
		left.KeyExpiry.Equal(right.KeyExpiry) && left.Expired == right.Expired &&
		left.MachineAuthorized == right.MachineAuthorized &&
		networkmap.EqualAlias(left.Alias, right.Alias)
}

func equalRules(left, right []networkmap.Rule) bool {
	return slices.EqualFunc(left, right, func(leftRule, rightRule networkmap.Rule) bool {
		return slices.Equal(leftRule.Sources, rightRule.Sources) &&
			slices.Equal(leftRule.Destinations, rightRule.Destinations) &&
			slices.Equal(leftRule.Protocols, rightRule.Protocols)
	})
}

func equalRelayRegion(left, right networkmap.RelayRegion) bool {
	return left.ID == right.ID && left.Code == right.Code && left.Name == right.Name &&
		slices.Equal(left.Nodes, right.Nodes)
}

func equalDNSConfig(left, right *networkmap.DNSConfig) bool {
	if left == nil || right == nil {
		return left == right
	}
	if !slices.Equal(left.Resolvers, right.Resolvers) ||
		!slices.Equal(left.FallbackResolvers, right.FallbackResolvers) ||
		!slices.Equal(left.SearchDomains, right.SearchDomains) ||
		left.Proxied != right.Proxied || !slices.Equal(left.Records, right.Records) {
		return false
	}

	return slices.EqualFunc(left.Routes, right.Routes, func(
		leftRoute, rightRoute networkmap.DNSRoute,
	) bool {
		return leftRoute.Suffix == rightRoute.Suffix &&
			slices.Equal(leftRoute.Resolvers, rightRoute.Resolvers)
	})
}

//nolint:staticcheck // Capability 142 no longer sends Nameservers, but the adapter validates legacy input defensively.
func convertDNSConfig(raw *tailcfg.DNSConfig) (*networkmap.DNSConfig, error) {
	if raw == nil {
		return nil, nil
	}
	if raw.TempCorpIssue13969 != "" {
		return nil, fmt.Errorf("%w: dns contains an unsupported remote url", ErrNetmapInvalid)
	}
	if len(raw.CertDomains) > maxIgnoredCertDomains ||
		len(raw.ExitNodeFilteredSet) > maxIgnoredDNSSuffixes {
		return nil, fmt.Errorf("%w: ignored dns metadata exceeds its limit", ErrNetmapInvalid)
	}
	for _, domain := range raw.CertDomains {
		if _, err := canonicalDNSName(domain, false, false); err != nil {
			return nil, fmt.Errorf("%w: certificate domain is malformed", ErrNetmapInvalid)
		}
	}
	for _, suffix := range raw.ExitNodeFilteredSet {
		value := strings.TrimPrefix(suffix, ".")
		if value == "" || strings.ToLower(suffix) != suffix ||
			strings.HasSuffix(value, ".") || len(value) > 253 {
			return nil, fmt.Errorf("%w: exit-node dns suffix is malformed", ErrNetmapInvalid)
		}
		if _, err := canonicalDNSName(value, false, false); err != nil {
			return nil, fmt.Errorf("%w: exit-node dns suffix is malformed", ErrNetmapInvalid)
		}
	}

	resolvers, err := convertDNSResolvers(raw.Resolvers)
	if err != nil {
		return nil, err
	}
	if len(raw.Nameservers) != 0 {
		if len(raw.Resolvers) != 0 {
			return nil, fmt.Errorf("%w: dns mixes current and deprecated resolvers", ErrNetmapInvalid)
		}
		resolvers = make([]networkmap.DNSResolver, 0, len(raw.Nameservers))
		for _, address := range raw.Nameservers {
			resolvers = append(resolvers, networkmap.DNSResolver{
				Address: netip.AddrPortFrom(address.Unmap(), 53),
			})
		}
	}
	fallbackResolvers, err := convertDNSResolvers(raw.FallbackResolvers)
	if err != nil {
		return nil, err
	}

	routeNames := make([]string, 0, len(raw.Routes))
	for name := range raw.Routes {
		routeNames = append(routeNames, name)
	}
	sort.Strings(routeNames)
	routes := make([]networkmap.DNSRoute, 0, len(routeNames))
	for _, rawName := range routeNames {
		name, err := canonicalDNSName(rawName, true, true)
		if err != nil {
			return nil, fmt.Errorf("%w: dns route suffix is malformed", ErrNetmapInvalid)
		}
		routeResolvers, err := convertDNSResolvers(raw.Routes[rawName])
		if err != nil {
			return nil, err
		}
		routes = append(routes, networkmap.DNSRoute{
			Suffix:    name,
			Resolvers: routeResolvers,
		})
	}

	searchDomains := make([]string, 0, len(raw.Domains))
	for _, rawDomain := range raw.Domains {
		domain, err := canonicalDNSName(rawDomain, false, false)
		if err != nil {
			return nil, fmt.Errorf("%w: dns search domain is malformed", ErrNetmapInvalid)
		}
		searchDomains = append(searchDomains, domain)
	}

	records := make([]networkmap.DNSRecord, 0, len(raw.ExtraRecords))
	for _, rawRecord := range raw.ExtraRecords {
		name, err := canonicalDNSName(rawRecord.Name, true, false)
		if err != nil {
			return nil, fmt.Errorf("%w: dns record name is malformed", ErrNetmapInvalid)
		}
		address, err := netip.ParseAddr(rawRecord.Value)
		if err != nil {
			return nil, fmt.Errorf("%w: dns record address is malformed", ErrNetmapInvalid)
		}
		address = address.Unmap()
		recordType := networkmap.DNSRecordType(strings.ToUpper(rawRecord.Type))
		if recordType == "" {
			if address.Is4() {
				recordType = networkmap.DNSRecordA
			} else {
				recordType = networkmap.DNSRecordAAAA
			}
		}
		records = append(records, networkmap.DNSRecord{
			Name:    name,
			Type:    recordType,
			Address: address,
		})
	}

	return &networkmap.DNSConfig{
		Resolvers:         resolvers,
		FallbackResolvers: fallbackResolvers,
		Routes:            routes,
		SearchDomains:     searchDomains,
		Proxied:           raw.Proxied,
		Records:           records,
	}, nil
}

func convertDNSResolvers(raw []*dnstype.Resolver) ([]networkmap.DNSResolver, error) {
	converted := make([]networkmap.DNSResolver, 0, len(raw))
	for _, resolver := range raw {
		if resolver == nil || len(resolver.BootstrapResolution) != 0 || resolver.UseWithExitNode {
			return nil, fmt.Errorf("%w: dns resolver metadata is unsupported", ErrNetmapInvalid)
		}
		address, err := netip.ParseAddr(resolver.Addr)
		if err != nil {
			return nil, fmt.Errorf("%w: only classic ip dns resolvers are supported", ErrNetmapInvalid)
		}
		converted = append(converted, networkmap.DNSResolver{
			Address: netip.AddrPortFrom(address.Unmap(), 53),
		})
	}

	return converted, nil
}

func canonicalDNSName(raw string, allowTrailingDot, allowRoot bool) (string, error) {
	if allowRoot && raw == "." {
		return raw, nil
	}
	if raw == "" || strings.TrimSpace(raw) != raw || (!allowTrailingDot && strings.HasSuffix(raw, ".")) {
		return "", errors.New("dns name is empty or non-canonical")
	}
	trimmed := strings.TrimSuffix(raw, ".")
	if trimmed == "" || len(trimmed) > 253 || strings.HasSuffix(trimmed, ".") {
		return "", errors.New("dns name is empty or too long")
	}
	for label := range strings.SplitSeq(trimmed, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("dns label is malformed")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return "", errors.New("dns label contains an unsupported character")
			}
		}
	}

	return strings.ToLower(trimmed), nil
}

func cloneDNSConfig(config *networkmap.DNSConfig) *networkmap.DNSConfig {
	if config == nil {
		return nil
	}
	cloned := *config
	cloned.Resolvers = append([]networkmap.DNSResolver(nil), config.Resolvers...)
	cloned.FallbackResolvers = append([]networkmap.DNSResolver(nil), config.FallbackResolvers...)
	cloned.Routes = make([]networkmap.DNSRoute, len(config.Routes))
	for index, route := range config.Routes {
		cloned.Routes[index] = networkmap.DNSRoute{
			Suffix:    route.Suffix,
			Resolvers: append([]networkmap.DNSResolver(nil), route.Resolvers...),
		}
	}
	cloned.SearchDomains = append([]string(nil), config.SearchDomains...)
	cloned.Records = append([]networkmap.DNSRecord(nil), config.Records...)

	return &cloned
}

//nolint:staticcheck // This compatibility boundary intentionally accepts the legacy relay field.
func convertNode(node *tailcfg.Node) (networkmap.Node, error) {
	if node == nil {
		return networkmap.Node{}, fmt.Errorf("%w: node is nil", ErrNetmapInvalid)
	}
	if node.ID <= 0 {
		return networkmap.Node{}, fmt.Errorf("%w: node id is invalid", ErrNetmapInvalid)
	}
	allowedIPs := node.AllowedIPs
	if allowedIPs == nil {
		allowedIPs = node.Addresses
	}
	converted := networkmap.Node{
		ID:                uint64(node.ID),
		StableID:          string(node.StableID),
		Name:              node.Name,
		PublicKey:         node.Key.String(),
		Addresses:         append([]netip.Prefix(nil), node.Addresses...),
		AllowedIPs:        append([]netip.Prefix(nil), allowedIPs...),
		Endpoints:         append([]netip.AddrPort(nil), node.Endpoints...),
		HomeRelay:         node.HomeDERP,
		KeyExpiry:         node.KeyExpiry.UTC(),
		Expired:           node.Expired,
		MachineAuthorized: node.MachineAuthorized,
	}
	alias, err := convertAlias(node)
	if err != nil {
		return networkmap.Node{}, err
	}
	converted.Alias = alias
	if !node.DiscoKey.IsZero() {
		converted.DiscoveryKey = node.DiscoKey.String()
	}
	if node.Online != nil {
		converted.OnlineKnown = true
		converted.Online = *node.Online
	}
	if converted.HomeRelay == 0 && node.LegacyDERPString != "" {
		_, rawPort, err := net.SplitHostPort(node.LegacyDERPString)
		if err != nil {
			return networkmap.Node{}, fmt.Errorf("%w: legacy relay endpoint is malformed", ErrNetmapInvalid)
		}
		port, err := netip.ParseAddrPort(net.JoinHostPort("127.0.0.1", rawPort))
		if err != nil {
			return networkmap.Node{}, fmt.Errorf("%w: legacy relay id is malformed", ErrNetmapInvalid)
		}
		converted.HomeRelay = int(port.Port())
	}

	return converted, nil
}

func convertFilterRules(rawRules []tailcfg.FilterRule) ([]networkmap.Rule, error) {
	converted := make([]networkmap.Rule, 0, len(rawRules))
	for _, rawRule := range rawRules {
		if len(rawRule.CapGrant) > 0 && len(rawRule.DstPorts) > 0 {
			return nil, fmt.Errorf("%w: policy mixes network and capability grants", ErrNetmapInvalid)
		}
		if len(rawRule.DstPorts) == 0 {
			continue
		}
		rule := networkmap.Rule{}
		for index, rawSource := range rawRule.SrcIPs {
			var bits *int
			if index < len(rawRule.SrcBits) {
				bits = &rawRule.SrcBits[index]
			}
			selector, err := parseSelector(rawSource, bits, true)
			if err != nil {
				return nil, err
			}
			rule.Sources = append(rule.Sources, selector)
		}
		for _, rawDestination := range rawRule.DstPorts {
			selector, err := parseSelector(rawDestination.IP, rawDestination.Bits, false)
			if err != nil {
				return nil, err
			}
			rule.Destinations = append(rule.Destinations, networkmap.Destination{
				Selector: selector,
				PortFrom: rawDestination.Ports.First,
				PortTo:   rawDestination.Ports.Last,
			})
		}
		protocols, err := convertProtocols(rawRule.IPProto)
		if err != nil {
			return nil, err
		}
		rule.Protocols = protocols
		converted = append(converted, rule)
	}

	return converted, nil
}

func parseSelector(raw string, legacyBits *int, allowCapability bool) (networkmap.Selector, error) {
	if raw == "*" {
		return networkmap.Selector{Kind: networkmap.SelectorAny}, nil
	}
	if strings.TrimSpace(raw) != raw || raw == "" {
		return networkmap.Selector{}, fmt.Errorf("%w: address selector is malformed", ErrNetmapInvalid)
	}
	if strings.HasPrefix(raw, "cap:") {
		if !allowCapability || legacyBits != nil {
			return networkmap.Selector{}, fmt.Errorf("%w: capability selector is not allowed here", ErrNetmapInvalid)
		}

		return networkmap.Selector{
			Kind:       networkmap.SelectorCapability,
			Capability: strings.TrimPrefix(raw, "cap:"),
		}, nil
	}
	if start, end, found := strings.Cut(raw, "-"); found {
		if legacyBits != nil {
			return networkmap.Selector{}, fmt.Errorf("%w: address range has legacy bits", ErrNetmapInvalid)
		}
		startAddress, startErr := netip.ParseAddr(start)
		endAddress, endErr := netip.ParseAddr(end)
		if startErr != nil || endErr != nil {
			return networkmap.Selector{}, fmt.Errorf("%w: address range is malformed", ErrNetmapInvalid)
		}

		return networkmap.Selector{
			Kind:       networkmap.SelectorRange,
			RangeStart: startAddress.Unmap(),
			RangeEnd:   endAddress.Unmap(),
		}, nil
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		if legacyBits != nil {
			return networkmap.Selector{}, fmt.Errorf("%w: prefix has legacy bits", ErrNetmapInvalid)
		}

		return networkmap.Selector{Kind: networkmap.SelectorPrefix, Prefix: prefix.Masked()}, nil
	}
	address, err := netip.ParseAddr(raw)
	if err != nil {
		return networkmap.Selector{}, fmt.Errorf("%w: address selector is malformed", ErrNetmapInvalid)
	}
	address = address.Unmap()
	bits := address.BitLen()
	if legacyBits != nil {
		bits = *legacyBits
		if bits < 0 || bits > address.BitLen() {
			return networkmap.Selector{}, fmt.Errorf("%w: legacy prefix length is invalid", ErrNetmapInvalid)
		}
	}

	return networkmap.Selector{
		Kind:   networkmap.SelectorPrefix,
		Prefix: netip.PrefixFrom(address, bits).Masked(),
	}, nil
}

func convertProtocols(raw []int) ([]uint8, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	seen := make(map[uint8]struct{}, len(raw))
	converted := make([]uint8, 0, len(raw))
	for _, protocol := range raw {
		if protocol < 0 || protocol > 255 {
			return nil, fmt.Errorf("%w: ip protocol is outside uint8", ErrNetmapInvalid)
		}
		value := uint8(protocol)
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		converted = append(converted, value)
	}

	return converted, nil
}

func cloneMapNode(node networkmap.Node) networkmap.Node {
	if node.Alias != nil {
		alias := *node.Alias
		alias.Services = slices.Clone(alias.Services)
		node.Alias = &alias
	}
	node.Addresses = append([]netip.Prefix(nil), node.Addresses...)
	node.AllowedIPs = append([]netip.Prefix(nil), node.AllowedIPs...)
	node.Endpoints = append([]netip.AddrPort(nil), node.Endpoints...)

	return node
}

func cloneRules(rules []networkmap.Rule) []networkmap.Rule {
	cloned := make([]networkmap.Rule, len(rules))
	for index, rule := range rules {
		cloned[index] = networkmap.Rule{
			Sources:      append([]networkmap.Selector(nil), rule.Sources...),
			Destinations: append([]networkmap.Destination(nil), rule.Destinations...),
			Protocols:    append([]uint8(nil), rule.Protocols...),
		}
	}

	return cloned
}

// Unrequested alias authority is a permanent map error, before any consumer I/O.
func validateRequestedDeviceAliases(snapshot networkmap.Snapshot, enabled bool) error {
	if enabled {
		return nil
	}
	for _, peer := range snapshot.Peers {
		if peer.Alias != nil {
			return fmt.Errorf("%w: Device aliases were not enabled", ErrNetmapInvalid)
		}
	}
	return nil
}
