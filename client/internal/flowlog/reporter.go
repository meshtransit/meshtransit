package flowlog

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/packetmeta"
)

const (
	defaultEventQueue  = 4096
	defaultUploadQueue = 4
	defaultMaxFlows    = 4096
	maxUploadAttempts  = 3
)

// Config controls bounded flow aggregation and authenticated uploads.
type Config struct {
	BaseURL     string
	Interval    time.Duration
	Timeout     time.Duration
	EventQueue  int
	UploadQueue int
	MaxFlows    int
	HTTPClient  *http.Client
	Logger      *slog.Logger
	Clock       func() time.Time
}

// Reporter observes packet headers without retaining payload bytes.
type Reporter struct {
	endpoint *url.URL
	interval time.Duration
	timeout  time.Duration
	maxFlows int
	client   *http.Client
	logger   *slog.Logger
	clock    func() time.Time
	bootID   string
	sequence atomic.Uint64
	metadata atomic.Pointer[networkMetadata]
	events   chan packetEvent
	uploads  chan uploadBatch
	dropped  atomic.Uint64
}

type networkMetadata struct {
	credentials networkmap.AuditCredentials
	reporter    wireNode
	peers       []wireNode
	nodes       map[netip.Addr]wireNode
}

type wireNode struct {
	NodeID    string   `json:"node_id"`
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

type packetEvent struct {
	at       time.Time
	metadata *networkMetadata
	header   packetHeader
}

type flowKey struct {
	metadata *networkMetadata
	protocol uint8
	left     netip.AddrPort
	right    netip.AddrPort
}

type aggregate struct {
	first        time.Time
	last         time.Time
	leftPackets  uint64
	leftBytes    uint64
	rightPackets uint64
	rightBytes   uint64
	initiator    netip.AddrPort
	hasInitiator bool
	state        string
	sawHandshake bool
}

type uploadBatch struct {
	credentials networkmap.AuditCredentials
	body        nativeBatch
}

type nativeBatch struct {
	Version   int        `json:"version"`
	BatchID   string     `json:"batch_id"`
	Reporter  wireNode   `json:"reporter"`
	Peers     []wireNode `json:"peers"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   time.Time  `json:"ended_at"`
	Flows     []wireFlow `json:"flows"`
}

type wireFlow struct {
	Protocol                   uint8  `json:"protocol"`
	Source                     string `json:"source"`
	Destination                string `json:"destination"`
	Initiator                  string `json:"initiator"`
	State                      string `json:"state"`
	SourceToDestinationPackets uint64 `json:"source_to_destination_packets"`
	SourceToDestinationBytes   uint64 `json:"source_to_destination_bytes"`
	DestinationToSourcePackets uint64 `json:"destination_to_source_packets"`
	DestinationToSourceBytes   uint64 `json:"destination_to_source_bytes"`
}

// New constructs an opt-in reporter. The endpoint must be an HTTPS origin.
func New(cfg Config) (*Reporter, error) {
	endpoint, err := url.Parse(cfg.BaseURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		(endpoint.Path != "" && endpoint.Path != "/") {
		return nil, errors.New("flowlog: base URL must be an HTTPS origin")
	}
	if cfg.Interval < time.Second || cfg.Interval > 5*time.Minute {
		return nil, errors.New("flowlog: interval must be between 1s and 5m")
	}
	if cfg.Timeout <= 0 || cfg.Timeout > time.Minute {
		return nil, errors.New("flowlog: timeout must be between zero and 1m")
	}
	if cfg.EventQueue == 0 {
		cfg.EventQueue = defaultEventQueue
	}
	if cfg.UploadQueue == 0 {
		cfg.UploadQueue = defaultUploadQueue
	}
	if cfg.MaxFlows == 0 {
		cfg.MaxFlows = defaultMaxFlows
	}
	if cfg.EventQueue < 1 || cfg.EventQueue > 1<<20 || cfg.UploadQueue < 1 ||
		cfg.UploadQueue > 1024 || cfg.MaxFlows < 1 || cfg.MaxFlows > 1<<20 {
		return nil, errors.New("flowlog: queue or flow limit is invalid")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{}
	}
	httpClient := *cfg.HTTPClient
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	cfg.HTTPClient = &httpClient
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	var bootID [16]byte
	if _, err := io.ReadFull(cryptorand.Reader, bootID[:]); err != nil {
		return nil, fmt.Errorf("flowlog: create batch identity: %w", err)
	}
	endpoint.Path = "/v1/flows"

	return &Reporter{
		endpoint: endpoint,
		interval: cfg.Interval,
		timeout:  cfg.Timeout,
		maxFlows: cfg.MaxFlows,
		client:   cfg.HTTPClient,
		logger:   cfg.Logger,
		clock:    cfg.Clock,
		bootID:   hex.EncodeToString(bootID[:]),
		events:   make(chan packetEvent, cfg.EventQueue),
		uploads:  make(chan uploadBatch, cfg.UploadQueue),
	}, nil
}

// UpdateNetwork atomically publishes only the node metadata and opaque upload
// credentials required to interpret subsequent packet headers.
func (r *Reporter) UpdateNetwork(snapshot networkmap.Snapshot) {
	if r == nil || !snapshot.Audit.Enabled() || snapshot.Audit.NodeID() != snapshot.Self.ID {
		if r != nil {
			r.metadata.Store(nil)
		}

		return
	}
	metadata := &networkMetadata{
		credentials: snapshot.Audit,
		reporter:    toWireNode(snapshot.Self),
		peers:       make([]wireNode, 0, len(snapshot.Peers)),
		nodes:       make(map[netip.Addr]wireNode),
	}
	indexWireNode(metadata.nodes, metadata.reporter)
	for _, peer := range snapshot.Peers {
		wirePeer := toWireNode(peer)
		metadata.peers = append(metadata.peers, wirePeer)
		indexWireNode(metadata.nodes, wirePeer)
	}
	r.metadata.Store(metadata)
}

// ObservePacket extracts bounded L3/L4 metadata synchronously and queues only
// scalar header fields. Packet bytes and payload are never retained.
func (r *Reporter) ObservePacket(direction dataplane.PacketDirection, packet []byte) {
	if r == nil {
		return
	}
	header, err := parsePacketHeader(packet)
	if err != nil {
		return
	}
	r.observeHeader(direction, header)
}

// ObservePacketMetadata queues only accepted TCP/UDP headers in local TUN
// coordinates. Local translation aliases never become reporter identities.
func (r *Reporter) ObservePacketMetadata(direction dataplane.PacketDirection, header packetmeta.Header) {
	if r == nil || (header.Protocol != protocolTCP && header.Protocol != protocolUDP) ||
		!header.Source.IsValid() || !header.Destination.IsValid() ||
		header.SourcePort == 0 || header.DestinationPort == 0 || header.Length <= 0 {
		return
	}
	r.observeHeader(direction, packetHeader{
		protocol: header.Protocol,
		source:   netip.AddrPortFrom(header.Source, header.SourcePort),
		dest:     netip.AddrPortFrom(header.Destination, header.DestinationPort),
		bytes:    uint64(header.Length), tcpFlags: header.TCPFlags,
	})
}

func (r *Reporter) observeHeader(direction dataplane.PacketDirection, header packetHeader) {
	metadata := r.metadata.Load()
	if metadata == nil || (direction != dataplane.PacketOutbound && direction != dataplane.PacketInbound) {
		return
	}
	sourceNode, sourceKnown := metadata.nodes[header.source.Addr().Unmap()]
	destinationNode, destinationKnown := metadata.nodes[header.dest.Addr().Unmap()]
	if !sourceKnown || !destinationKnown || sourceNode.NodeID == destinationNode.NodeID {
		return
	}
	if direction == dataplane.PacketOutbound && sourceNode.NodeID != metadata.reporter.NodeID {
		return
	}
	if direction == dataplane.PacketInbound && destinationNode.NodeID != metadata.reporter.NodeID {
		return
	}
	event := packetEvent{
		at:       r.clock().UTC(),
		metadata: metadata,
		header:   header,
	}
	select {
	case r.events <- event:
	default:
		r.dropped.Add(1)
	}
}

// Run aggregates events and uploads batches until cancellation.
func (r *Reporter) Run(ctx context.Context) error {
	if r == nil {
		return errors.New("flowlog: reporter is nil")
	}
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		r.uploadLoop(ctx)
	}()
	r.aggregateLoop(ctx)
	close(r.uploads)
	wait.Wait()

	return ctx.Err()
}

func (r *Reporter) aggregateLoop(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	flows := make(map[flowKey]*aggregate)
	for {
		select {
		case <-ctx.Done():
			r.flush(flows)
			return
		case event := <-r.events:
			r.record(flows, event)
		case <-ticker.C:
			r.flush(flows)
			flows = make(map[flowKey]*aggregate)
		}
	}
}

func (r *Reporter) record(flows map[flowKey]*aggregate, event packetEvent) {
	left, right := event.header.source, event.header.dest
	leftToRight := true
	if left.Compare(right) > 0 {
		left, right = right, left
		leftToRight = false
	}
	key := flowKey{metadata: event.metadata, protocol: event.header.protocol, left: left, right: right}
	flow := flows[key]
	if flow == nil {
		if len(flows) >= r.maxFlows {
			r.dropped.Add(1)
			return
		}
		flow = &aggregate{first: event.at, state: "observed"}
		flows[key] = flow
	}
	flow.last = event.at
	if leftToRight {
		flow.leftPackets++
		flow.leftBytes += event.header.bytes
	} else {
		flow.rightPackets++
		flow.rightBytes += event.header.bytes
	}
	if event.header.protocol == protocolUDP {
		if !flow.hasInitiator {
			flow.initiator = event.header.source
			flow.hasInitiator = true
		}
		return
	}
	updateTCPState(flow, event.header)
}

func updateTCPState(flow *aggregate, header packetHeader) {
	const (
		tcpFIN = 0x01
		tcpSYN = 0x02
		tcpRST = 0x04
		tcpACK = 0x10
	)
	if flow.state == "reset" {
		return
	}
	if header.tcpFlags&tcpRST != 0 {
		flow.state = "reset"
		return
	}
	if flow.state == "closing" {
		return
	}
	if header.tcpFlags&tcpSYN != 0 {
		flow.sawHandshake = true
		if header.tcpFlags&tcpACK == 0 {
			flow.initiator = header.source
			flow.state = "syn"
		} else {
			flow.initiator = header.dest
			flow.state = "syn_ack"
		}
		flow.hasInitiator = true
	}
	if header.tcpFlags&tcpACK != 0 && header.tcpFlags&tcpSYN == 0 && flow.sawHandshake {
		flow.state = "established"
	}
	if header.tcpFlags&tcpFIN != 0 {
		flow.state = "closing"
	}
}

func (r *Reporter) flush(flows map[flowKey]*aggregate) {
	if len(flows) == 0 {
		return
	}
	grouped := make(map[*networkMetadata][]struct {
		key  flowKey
		flow *aggregate
	})
	for key, flow := range flows {
		grouped[key.metadata] = append(grouped[key.metadata], struct {
			key  flowKey
			flow *aggregate
		}{key: key, flow: flow})
	}
	for metadata, group := range grouped {
		body := nativeBatch{
			Version:   1,
			BatchID:   r.bootID + "-" + strconv.FormatUint(r.sequence.Add(1), 10),
			Reporter:  metadata.reporter,
			Peers:     append([]wireNode(nil), metadata.peers...),
			StartedAt: group[0].flow.first,
			EndedAt:   group[0].flow.last,
			Flows:     make([]wireFlow, 0, len(group)),
		}
		for _, item := range group {
			if item.flow.first.Before(body.StartedAt) {
				body.StartedAt = item.flow.first
			}
			if item.flow.last.After(body.EndedAt) {
				body.EndedAt = item.flow.last
			}
			body.Flows = append(body.Flows, makeWireFlow(metadata, item.key, item.flow))
		}
		select {
		case r.uploads <- uploadBatch{credentials: metadata.credentials, body: body}:
		default:
			r.dropped.Add(uint64(len(body.Flows)))
		}
	}
	dropped := r.dropped.Swap(0)
	if dropped != 0 {
		r.logger.Warn("flow telemetry dropped under bounded backpressure", "events_or_flows", dropped)
	}
}

func makeWireFlow(metadata *networkMetadata, key flowKey, flow *aggregate) wireFlow {
	source, destination := key.left, key.right
	sourcePackets, sourceBytes := flow.leftPackets, flow.leftBytes
	destinationPackets, destinationBytes := flow.rightPackets, flow.rightBytes
	initiator := "unknown"
	if flow.hasInitiator {
		if flow.initiator == key.right {
			source, destination = destination, source
			sourcePackets, destinationPackets = destinationPackets, sourcePackets
			sourceBytes, destinationBytes = destinationBytes, sourceBytes
		}
		if node, exists := metadata.nodes[source.Addr().Unmap()]; exists {
			if node.NodeID == metadata.reporter.NodeID {
				initiator = "reporter"
			} else {
				initiator = "peer"
			}
		}
	}

	return wireFlow{
		Protocol:                   key.protocol,
		Source:                     source.String(),
		Destination:                destination.String(),
		Initiator:                  initiator,
		State:                      flow.state,
		SourceToDestinationPackets: sourcePackets,
		SourceToDestinationBytes:   sourceBytes,
		DestinationToSourcePackets: destinationPackets,
		DestinationToSourceBytes:   destinationBytes,
	}
}

func (r *Reporter) uploadLoop(ctx context.Context) {
	for batch := range r.uploads {
		if err := r.upload(ctx, batch); err != nil && ctx.Err() == nil {
			r.logger.Warn("flow telemetry upload failed", "error", err)
		}
	}
}

func (r *Reporter) upload(ctx context.Context, batch uploadBatch) error {
	body, err := json.Marshal(batch.body)
	if err != nil {
		return errors.New("encode flow batch")
	}
	for attempt := 1; attempt <= maxUploadAttempts; attempt++ {
		requestCtx, cancel := context.WithTimeout(ctx, r.timeout)
		request, err := http.NewRequestWithContext(
			requestCtx,
			http.MethodPost,
			r.endpoint.String(),
			bytes.NewReader(body),
		)
		if err == nil {
			request.Header.Set("Authorization", "Bearer "+batch.credentials.NodeToken())
			request.Header.Set("X-MeshTransit-Network-Token", batch.credentials.NetworkToken())
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("User-Agent", "meshd-flowlog/1")
			response, requestErr := r.client.Do(request)
			if requestErr == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
				_ = response.Body.Close()
				if response.StatusCode >= 200 && response.StatusCode < 300 {
					cancel()
					return nil
				}
				err = fmt.Errorf("server returned http %d", response.StatusCode)
			} else {
				err = errors.New("HTTPS request failed")
			}
		}
		cancel()
		if attempt == maxUploadAttempts || ctx.Err() != nil {
			return err
		}
		timer := time.NewTimer(time.Duration(attempt) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}

	return errors.New("flow upload attempts exhausted")
}

func toWireNode(node networkmap.Node) wireNode {
	addresses := make([]string, 0, len(node.Addresses))
	for _, prefix := range node.Addresses {
		addresses = append(addresses, prefix.Addr().Unmap().String())
	}

	return wireNode{
		NodeID:    strconv.FormatUint(node.ID, 10),
		Name:      strings.TrimSuffix(node.Name, "."),
		Addresses: addresses,
	}
}

func indexWireNode(index map[netip.Addr]wireNode, node wireNode) {
	for _, value := range node.Addresses {
		if address, err := netip.ParseAddr(value); err == nil {
			index[address.Unmap()] = node
		}
	}
}
