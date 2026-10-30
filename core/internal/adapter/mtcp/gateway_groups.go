package mtcp

import (
	"context"
	"log/slog"
	"sync"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// CapabilityGatewayGroups is gateway.groups1: a Kubernetes gateway reports
// its groups' RBAC check (mtcp-v1 §6.11).
const CapabilityGatewayGroups = "gateway.groups1"

// GatewayGroupRecorder keeps a gateway Device's latest group report
// (schema 254). kept is false when the report met a lock and should be
// written again.
type GatewayGroupRecorder interface {
	RecordGatewayGroups(ctx context.Context, machine [32]byte, nodeKey []byte,
		report kubecluster.GatewayGroupReport) (kept bool, err error)
}

const (
	// gatewayGroupReportEvery is the least time between the reports Core
	// writes from one session; one sent sooner waits (§6.11).
	gatewayGroupReportEvery = 30 * time.Second
	// gatewayGroupRetry is how long a report that met a lock waits;
	// gatewayGroupMaximumAge drops one still unwritten after it, and a
	// report that failed otherwise is dropped at once (review d3 M2).
	gatewayGroupRetry      = 30 * time.Second
	gatewayGroupMaximumAge = 5 * time.Minute
	// gatewayGroupCheckedSkew and gatewayGroupCheckedAge bound the time of
	// a gateway's last check: further off it is not shown.
	gatewayGroupCheckedSkew = 5 * time.Minute
	gatewayGroupCheckedAge  = 30 * 24 * time.Hour
	// maxGatewayGroupPending bounds the Devices whose report waits.
	maxGatewayGroupPending = 1 << 12
	// gatewayGroupRecordTimeout bounds one report's transaction.
	gatewayGroupRecordTimeout = 5 * time.Second
)

type gatewayGroupPending struct {
	nodeKey  [32]byte
	report   kubecluster.GatewayGroupReport
	notAfter time.Time // written no sooner than this
}

// gatewayGroupWriter writes reports off the session path: report never
// blocks, a Device's newer report replaces its waiting one, and one
// goroutine writes. Its goroutine starts with the first report; stop ends
// it.
type gatewayGroupWriter struct {
	recorder GatewayGroupRecorder
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
	pending map[[32]byte]gatewayGroupPending
	warned  time.Time
}

func newGatewayGroupWriter(recorder GatewayGroupRecorder, metrics *Metrics, logger *slog.Logger,
	now func() time.Time) *gatewayGroupWriter {
	if recorder == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &gatewayGroupWriter{recorder: recorder, metrics: metrics, logger: logger, now: now,
		wake: make(chan struct{}, 1), ctx: ctx, cancel: cancel, stopped: make(chan struct{}),
		pending: make(map[[32]byte]gatewayGroupPending)}
}

// submit queues the report of the gateway holding machine and nodeKey, to
// be written no sooner than notBefore, replacing one still waiting.
func (writer *gatewayGroupWriter) submit(machine [32]byte, nodeKey node.Key,
	report kubecluster.GatewayGroupReport, notBefore time.Time) {
	writer.mu.Lock()
	if _, waiting := writer.pending[machine]; writer.halted || !waiting && len(writer.pending) >= maxGatewayGroupPending {
		writer.mu.Unlock()
		writer.metrics.limited(limitGatewayGroupDropped)
		return
	}
	writer.pending[machine] = gatewayGroupPending{nodeKey: nodeKey.Bytes(), report: report, notAfter: notBefore}
	writer.mu.Unlock()
	writer.start.Do(func() { go writer.run() })
	select {
	case writer.wake <- struct{}{}:
	default:
	}
}

// run writes waiting reports, one transaction each, until stop.
func (writer *gatewayGroupWriter) run() {
	defer close(writer.stopped)
	due := time.NewTimer(gatewayGroupRetry)
	defer due.Stop()
	for {
		for writer.writeOne() {
		}
		// Wake when the earliest waiting report is due (review d3 L2).
		due.Reset(writer.nextDue())
		select {
		case <-writer.ctx.Done():
			return
		case <-writer.wake:
		case <-due.C:
		}
	}
}

// nextDue is how long until the earliest waiting report is due, at most
// gatewayGroupRetry.
func (writer *gatewayGroupWriter) nextDue() time.Duration {
	now := writer.now()
	wait := gatewayGroupRetry
	writer.mu.Lock()
	defer writer.mu.Unlock()
	for _, pending := range writer.pending {
		wait = min(wait, max(pending.notAfter.Sub(now), time.Millisecond))
	}
	return wait
}

// writeOne writes one report due now; false when none is.
func (writer *gatewayGroupWriter) writeOne() bool {
	now := writer.now()
	writer.mu.Lock()
	var machine [32]byte
	var next gatewayGroupPending
	found := false
	for candidate, pending := range writer.pending {
		if now.Sub(pending.report.ReceivedAt) > gatewayGroupMaximumAge {
			delete(writer.pending, candidate)
			writer.metrics.limited(limitGatewayGroupDropped)
			continue
		}
		if !found && !now.Before(pending.notAfter) {
			machine, next, found = candidate, pending, true
		}
	}
	if found {
		delete(writer.pending, machine)
	}
	writer.mu.Unlock()
	if !found || writer.ctx.Err() != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(writer.ctx, gatewayGroupRecordTimeout)
	kept, err := writer.recorder.RecordGatewayGroups(ctx, machine, next.nodeKey[:], next.report)
	cancel()
	if err == nil && kept {
		return true
	}
	// A report that met a lock is written again later, unless a newer one
	// took its place; one that failed otherwise is dropped.
	writer.mu.Lock()
	if _, newer := writer.pending[machine]; err == nil && !newer && !writer.halted {
		next.notAfter = now.Add(gatewayGroupRetry)
		writer.pending[machine] = next
	}
	warn := err != nil && now.Sub(writer.warned) >= time.Minute
	if warn {
		writer.warned = now
	}
	writer.mu.Unlock()
	if warn && writer.ctx.Err() == nil {
		writer.logger.Warn("mtcp gateway group report not recorded", "error_code", "gateway_group_report_failed")
	}
	return true
}

// stop ends the goroutine, cancelling the report it is writing; waiting
// reports are dropped and later ones go nowhere.
func (writer *gatewayGroupWriter) stop() {
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

// receiveGroupReport takes a GatewayGroupReport (mtcp-v1 §6.11). It reports
// whether the session goes on.
func (session *Session) receiveGroupReport(now time.Time, message *mtcpv1.GatewayGroupReport) bool {
	writer := session.server.groupReports
	nodeKey, proven := session.gatewayGroupsKey()
	if writer == nil || !session.Supports(CapabilityGatewayGroups) || !proven {
		session.SendError(mtcpv1.Error_UNSUPPORTED, "group reports need gateway.groups1 on a gateway session",
			false)
		return true
	}
	if sharedmtcp.ValidateGatewayGroupReport(message) != nil {
		session.SendError(mtcpv1.Error_INVALID, "invalid group report", true)
		return false
	}
	// groupsAt is the slot of the session's last write: a report within 30 s
	// of it waits for the next slot, replacing one already waiting there
	// (review d3 L1, L2): one write a Device per 30 s.
	notBefore := now
	switch {
	case now.Before(session.groupsAt):
		notBefore = session.groupsAt
		session.server.options.Metrics.limited(limitGatewayGroupReport)
	case !session.groupsAt.IsZero() && now.Sub(session.groupsAt) < gatewayGroupReportEvery:
		notBefore = session.groupsAt.Add(gatewayGroupReportEvery)
		session.server.options.Metrics.limited(limitGatewayGroupReport)
	}
	session.groupsAt = notBefore
	report := kubecluster.GatewayGroupReport{Supported: true, Truncated: message.GetTruncated(),
		ReceivedAt: now, Groups: make([]kubecluster.GatewayGroupStatus, 0, len(message.GetGroups()))}
	if checked := time.UnixMilli(message.GetCheckedAtMs()); message.GetCheckedAtMs() > 0 &&
		checked.Before(now.Add(gatewayGroupCheckedSkew)) && checked.After(now.Add(-gatewayGroupCheckedAge)) {
		report.CheckedAt = checked.UTC()
	}
	for _, group := range message.GetGroups() {
		report.Groups = append(report.Groups, kubecluster.GatewayGroupStatus{Group: group.GetGroup(),
			Privileged: group.GetPrivileged(), State: groupStates[group.GetState()],
			Reason: groupReasons[group.GetReason()]})
	}
	writer.submit(node.MachineKey(session.machine).Fingerprint(), nodeKey, report, notBefore)
	return true
}

// markGroupsUnsupported records a gateway session that cannot report its
// groups while Core offers it, so people see its meshgw does not (Q172).
func (session *Session) markGroupsUnsupported() {
	writer := session.server.groupReports
	if writer == nil || session.Supports(CapabilityGatewayGroups) || !session.provenNodeKey.IsValid() {
		return
	}
	now := session.server.options.Now()
	writer.submit(node.MachineKey(session.machine).Fingerprint(), session.provenNodeKey,
		kubecluster.GatewayGroupReport{Supported: false, ReceivedAt: now}, now)
}

// gatewayGroupsKey is the node key a gateway session proved, or joined
// with; false for any other session.
func (session *Session) gatewayGroupsKey() (node.Key, bool) {
	if !session.servesGateway() {
		return node.Key{}, false
	}
	if session.provenNodeKey.IsValid() {
		return session.provenNodeKey, true
	}
	if joined := session.joinedNodeKey.Load(); joined != nil {
		return *joined, true
	}
	return node.Key{}, false
}

var groupStates = map[mtcpv1.GatewayGroupStatus_State]string{
	mtcpv1.GatewayGroupStatus_ENABLED:  kubecluster.GroupStateEnabled,
	mtcpv1.GatewayGroupStatus_DISABLED: kubecluster.GroupStateDisabled,
	mtcpv1.GatewayGroupStatus_PENDING:  kubecluster.GroupStatePending,
}

var groupReasons = map[mtcpv1.GatewayGroupStatus_Reason]string{
	mtcpv1.GatewayGroupStatus_NONE:              kubecluster.GroupReasonNone,
	mtcpv1.GatewayGroupStatus_NOT_CHECKED:       kubecluster.GroupReasonNotChecked,
	mtcpv1.GatewayGroupStatus_CHECK_STALE:       kubecluster.GroupReasonCheckStale,
	mtcpv1.GatewayGroupStatus_API_ERROR:         kubecluster.GroupReasonAPIError,
	mtcpv1.GatewayGroupStatus_RBAC_EXCEEDS:      kubecluster.GroupReasonRBACExceeds,
	mtcpv1.GatewayGroupStatus_IMPERSONATION_OFF: kubecluster.GroupReasonImpersonationOff,
}
