package mtcp

import (
	"context"
	"log/slog"
	"sync"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/kubeprofile"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// CapabilityGatewayCeiling is gateway.ceiling1: a Kubernetes gateway reports
// what each group's own RBAC lets it do (mtcp-v1 §6.12).
const CapabilityGatewayCeiling = "gateway.ceiling1"

// GatewayCeilingWrite is what a ceiling's write did.
type GatewayCeilingWrite int

const (
	// GatewayCeilingWritten kept the ceiling.
	GatewayCeilingWritten GatewayCeilingWrite = iota + 1
	// GatewayCeilingKeptNewer found a newer ceiling kept already.
	GatewayCeilingKeptNewer
	// GatewayCeilingNoGateway found no gateway holding the session's keys.
	GatewayCeilingNoGateway
)

// GatewayCeilingRecorder keeps a gateway Device's latest ceiling (schema
// 265).
type GatewayCeilingRecorder interface {
	RecordGatewayCeiling(ctx context.Context, machine [32]byte, nodeKey []byte,
		ceiling kubecluster.EncodedCeiling) (GatewayCeilingWrite, error)
}

const (
	// gatewayCeilingEvery is the least time between the ceilings Core
	// writes for one gateway Device, whichever session sent them (§6.12,
	// review L9): one sent sooner waits, replacing one already waiting.
	gatewayCeilingEvery = time.Minute
	// gatewayCeilingMaximumAge drops a ceiling still unwritten after it.
	gatewayCeilingMaximumAge = 10 * time.Minute
	// gatewayCeilingBudget bounds the encoded bytes of ceilings waiting to
	// be written (review §33.9 M4, h4c M3); past it new ones are dropped.
	gatewayCeilingBudget = 32 << 20
	// maxGatewayCeilingDevices bounds the Devices Core remembers writing
	// for, to space their writes.
	maxGatewayCeilingDevices = 1 << 14
	// gatewayCeilingRecordTimeout bounds one write.
	gatewayCeilingRecordTimeout = 5 * time.Second
	// gatewayCeilingCheckedSkew and gatewayCeilingCheckedAge bound a shown
	// measurement time.
	gatewayCeilingCheckedSkew = 5 * time.Minute
	gatewayCeilingCheckedAge  = 30 * 24 * time.Hour
)

type gatewayCeilingPending struct {
	nodeKey  [32]byte
	ceiling  kubecluster.EncodedCeiling
	notAfter time.Time // written no sooner than this
}

func (pending gatewayCeilingPending) bytes() int { return len(pending.ceiling.Bytes()) }

// gatewayCeilingWriter writes ceilings off the session path: submit never
// blocks, a Device's newer ceiling replaces its waiting one, one goroutine
// writes, and a Device gets at most one write a minute.
type gatewayCeilingWriter struct {
	recorder GatewayCeilingRecorder
	metrics  *Metrics
	logger   *slog.Logger
	now      func() time.Time
	wake     chan struct{}

	ctx     context.Context
	cancel  context.CancelFunc
	start   sync.Once
	stopped chan struct{}

	mu      sync.Mutex
	halted  bool
	pending map[[32]byte]gatewayCeilingPending
	bytes   int
	written map[[32]byte]time.Time // last write a Device, for spacing
	warned  time.Time
}

func newGatewayCeilingWriter(recorder GatewayCeilingRecorder, metrics *Metrics, logger *slog.Logger,
	now func() time.Time,
) *gatewayCeilingWriter {
	if recorder == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &gatewayCeilingWriter{
		recorder: recorder, metrics: metrics, logger: logger, now: now,
		wake: make(chan struct{}, 1), ctx: ctx, cancel: cancel, stopped: make(chan struct{}),
		pending: make(map[[32]byte]gatewayCeilingPending), written: make(map[[32]byte]time.Time),
	}
}

// submit queues the ceiling of the gateway holding machine and nodeKey,
// replacing one still waiting; it waits for the Device's minute.
func (writer *gatewayCeilingWriter) submit(machine [32]byte, nodeKey node.Key, ceiling kubecluster.EncodedCeiling) {
	writer.mu.Lock()
	previous, waiting := writer.pending[machine]
	room := writer.bytes - previous.bytes() + len(ceiling.Bytes())
	if writer.halted || room > gatewayCeilingBudget || !waiting && len(writer.pending) >= maxGatewayCeilingDevices {
		writer.mu.Unlock()
		writer.metrics.limited(limitGatewayCeilingDropped)
		return
	}
	notAfter := ceiling.ReceivedAt()
	if last, wrote := writer.written[machine]; wrote && notAfter.Before(last.Add(gatewayCeilingEvery)) {
		notAfter = last.Add(gatewayCeilingEvery)
		writer.metrics.limited(limitGatewayCeilingSpaced)
	}
	writer.pending[machine] = gatewayCeilingPending{nodeKey: nodeKey.Bytes(), ceiling: ceiling, notAfter: notAfter}
	writer.bytes = room
	writer.mu.Unlock()
	writer.start.Do(func() { go writer.run() })
	select {
	case writer.wake <- struct{}{}:
	default:
	}
}

// run writes waiting ceilings until stop.
func (writer *gatewayCeilingWriter) run() {
	defer close(writer.stopped)
	due := time.NewTimer(gatewayCeilingEvery)
	defer due.Stop()
	for {
		for writer.writeOne() {
		}
		due.Reset(writer.nextDue())
		select {
		case <-writer.ctx.Done():
			return
		case <-writer.wake:
		case <-due.C:
		}
	}
}

// nextDue is how long until the earliest waiting ceiling is due, at most a
// minute.
func (writer *gatewayCeilingWriter) nextDue() time.Duration {
	now := writer.now()
	wait := gatewayCeilingEvery
	writer.mu.Lock()
	defer writer.mu.Unlock()
	for _, pending := range writer.pending {
		wait = min(wait, max(pending.notAfter.Sub(now), time.Millisecond))
	}
	return wait
}

// writeOne writes one ceiling due now; false when none is. A failed write
// is dropped: the gateway sends again on change and every 6 hours.
func (writer *gatewayCeilingWriter) writeOne() bool {
	now := writer.now()
	writer.mu.Lock()
	var machine [32]byte
	var next gatewayCeilingPending
	found := false
	for candidate, pending := range writer.pending {
		if now.Sub(pending.ceiling.ReceivedAt()) > gatewayCeilingMaximumAge {
			delete(writer.pending, candidate)
			writer.bytes -= pending.bytes()
			writer.metrics.limited(limitGatewayCeilingExpired)
			continue
		}
		if !found && !now.Before(pending.notAfter) {
			machine, next, found = candidate, pending, true
		}
	}
	if found {
		delete(writer.pending, machine)
		writer.bytes -= next.bytes()
		writer.remember(machine, now)
	}
	writer.mu.Unlock()
	if !found || writer.ctx.Err() != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(writer.ctx, gatewayCeilingRecordTimeout)
	written, err := writer.recorder.RecordGatewayCeiling(ctx, machine, next.nodeKey[:], next.ceiling)
	cancel()
	switch {
	case err != nil && writer.ctx.Err() != nil:
		// Cut off by the writer's stop: no failure to count.
	case err != nil:
		writer.metrics.limited(limitGatewayCeilingWriteFailed)
	case written == GatewayCeilingKeptNewer:
		writer.metrics.limited(limitGatewayCeilingOlder)
	case written == GatewayCeilingNoGateway:
		writer.metrics.limited(limitGatewayCeilingNoGateway)
	}
	if err != nil {
		writer.mu.Lock()
		warn := now.Sub(writer.warned) >= time.Minute
		if warn {
			writer.warned = now
		}
		writer.mu.Unlock()
		if warn && writer.ctx.Err() == nil {
			// The store's error carries its SQLSTATE, never the body.
			writer.logger.Warn("mtcp gateway ceiling not recorded", "error_code", "gateway_ceiling_failed",
				"error", err)
		}
	}
	return true
}

// remember notes a write for spacing; past the bound it forgets writes
// older than a minute, which space nothing. The caller holds mu.
func (writer *gatewayCeilingWriter) remember(machine [32]byte, now time.Time) {
	if len(writer.written) >= maxGatewayCeilingDevices {
		for candidate, at := range writer.written {
			if now.Sub(at) >= gatewayCeilingEvery {
				delete(writer.written, candidate)
			}
		}
	}
	if len(writer.written) < maxGatewayCeilingDevices {
		writer.written[machine] = now
	}
}

// stop ends the goroutine, cancelling the write in flight; waiting
// ceilings are dropped and later ones go nowhere.
func (writer *gatewayCeilingWriter) stop() {
	if writer == nil {
		return
	}
	writer.mu.Lock()
	writer.halted = true
	writer.mu.Unlock()
	writer.cancel()
	writer.start.Do(func() { close(writer.stopped) })
	<-writer.stopped
}

// receiveGroupCeiling takes a GatewayGroupCeiling (mtcp-v1 §6.12). It
// reports whether the session goes on.
func (session *Session) receiveGroupCeiling(now time.Time, message *mtcpv1.GatewayGroupCeiling) bool {
	writer := session.server.ceilings
	nodeKey, proven := session.gatewayGroupsKey()
	if writer == nil || !session.Supports(CapabilityGatewayCeiling) || !proven {
		session.SendError(mtcpv1.Error_UNSUPPORTED, "group ceilings need gateway.ceiling1 on a gateway session",
			false)
		return true
	}
	if sharedmtcp.ValidateGatewayGroupCeiling(message) != nil {
		session.SendError(mtcpv1.Error_INVALID, "invalid group ceiling", true)
		return false
	}
	var checkedAt time.Time
	if checked := time.UnixMilli(message.GetCheckedAtMs()); message.GetCheckedAtMs() > 0 &&
		checked.Before(now.Add(gatewayCeilingCheckedSkew)) && checked.After(now.Add(-gatewayCeilingCheckedAge)) {
		checkedAt = checked.UTC()
	}
	// Core encodes once, here, and checks the body again as it keeps it. A
	// ceiling the wire rules took but that check refuses is dropped and
	// counted, never fatal: gateways check only the wire rules, and a
	// difference must not make them all reconnect (review h4c M4).
	ceiling, err := ceilingBody(message).Encoded(checkedAt, now)
	if err != nil {
		session.server.options.Metrics.limited(limitGatewayCeilingRefused)
		return true
	}
	writer.submit(node.MachineKey(session.machine).Fingerprint(), nodeKey, ceiling)
	return true
}

// ceilingBody is a valid ceiling as Core keeps it: every list present.
func ceilingBody(message *mtcpv1.GatewayGroupCeiling) kubecluster.CeilingBody {
	body := kubecluster.CeilingBody{Truncated: message.GetTruncated(),
		Groups: make([]kubecluster.CeilingGroup, 0, len(message.GetGroups()))}
	for _, group := range message.GetGroups() {
		kept := kubecluster.CeilingGroup{
			Group: group.GetGroup(), ClusterRole: group.GetClusterRole(),
			Everywhere: ceilingScope(group.GetEverywhere()), NamespacesTruncated: group.GetNamespacesTruncated(),
			Namespaces: make([]kubecluster.CeilingScope, 0, len(group.GetNamespaces())),
		}
		for _, scope := range group.GetNamespaces() {
			kept.Namespaces = append(kept.Namespaces, ceilingScope(scope))
		}
		body.Groups = append(body.Groups, kept)
	}
	return body
}

func ceilingScope(scope *mtcpv1.GatewayCeilingScope) kubecluster.CeilingScope {
	kept := kubecluster.CeilingScope{
		Namespace: scope.GetNamespace(), Measured: scope.GetMeasured(), Incomplete: scope.GetIncomplete(),
		RulesDropped: int64(scope.GetRulesDropped()),
		Rules:        make([]kubeprofile.Rule, 0, len(scope.GetRules())),
	}
	for _, rule := range scope.GetRules() {
		kept.Rules = append(kept.Rules, kubeprofile.Rule{
			APIGroups: rule.GetApiGroups(), Resources: rule.GetResources(), Verbs: rule.GetVerbs(),
			ResourceNames: rule.GetResourceNames(), NonResourceURLs: rule.GetNonResourceUrls(),
		})
	}
	return kept
}
