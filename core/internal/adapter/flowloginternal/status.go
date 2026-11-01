package flowloginternal

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net/http"
	"regexp"
	"slices"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// The receiver's report (connection logs design §16e, C67, C68): the only
// write of the internal API, with limits of its own so it never starves the
// reads.
const (
	statusPath = "/internal/v1/flowlog/status"
	// statusRate and statusBurst bound reports per replica: every receiver
	// instance reports about once a minute.
	statusRate  = 2
	statusBurst = 10
	// maxStatusBody bounds a report before it is decoded.
	maxStatusBody = 256 << 10
	// statusTimeout bounds one report's write; the store bounds the
	// statement to 2 seconds.
	statusTimeout = 3 * time.Second
)

// StatusWriter writes the receiver's reports.
type StatusWriter interface {
	ReportStatus(ctx context.Context, report connectionlog.ReceiverReport) (connectionlog.ReceiverReportResult, error)
}

var (
	// ErrReportStaleClock is what a StatusWriter answers for a report from a
	// clock ahead of the database's: the API answers 400.
	ErrReportStaleClock = errors.New("flowloginternal: report from the future")
	// ErrTooManyReceivers is what a StatusWriter answers for a new instance
	// past the deployment's bound: the API answers 429.
	ErrTooManyReceivers = errors.New("flowloginternal: too many receiver instances")
)

// statusLimits are the report's own limiter and its one write in flight.
type statusLimits struct {
	limiter *rate.Limiter
	slot    chan struct{}
}

func newStatusLimits() statusLimits {
	return statusLimits{limiter: rate.NewLimiter(statusRate, statusBurst), slot: make(chan struct{}, 1)}
}

func (handler *handler) serveStatus(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		handler.metrics.request("status", "method")
		response.Header().Set("Allow", http.MethodPost)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !handler.statusLimits.limiter.AllowN(handler.now(), 1) {
		handler.metrics.request("status", "throttled")
		response.Header().Set("Retry-After", "1")
		http.Error(response, "too many requests", http.StatusTooManyRequests)
		return
	}
	if encoding := request.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		handler.metrics.request("status", "invalid")
		http.Error(response, "unsupported content encoding", http.StatusUnsupportedMediaType)
		return
	}
	// The body first, then the write slot: a slow sender never holds it
	// (review s4c3 L7).
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maxStatusBody))
	if err != nil {
		handler.metrics.request("status", "invalid")
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(response, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(response, "bad request", http.StatusBadRequest)
		return
	}
	// Lenient: a newer receiver's fields are ignored and its enum values
	// read as unspecified, so a rolling upgrade never fails reports (review
	// s4c3 H1).
	message := &flowlogv1.FlowStatus{}
	if err := proto.Unmarshal(body, message); err != nil {
		handler.badRequest(response, "status")
		return
	}
	report, ok := receiverReport(message, handler.now())
	if !ok {
		handler.badRequest(response, "status")
		return
	}
	select {
	case handler.statusLimits.slot <- struct{}{}:
		defer func() { <-handler.statusLimits.slot }()
	default:
		handler.metrics.request("status", "busy")
		response.Header().Set("Retry-After", "1")
		http.Error(response, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	handler.writeStatus(response, request, report)
}

func (handler *handler) writeStatus(response http.ResponseWriter, request *http.Request,
	report connectionlog.ReceiverReport,
) {
	ctx, cancel := context.WithTimeout(request.Context(), statusTimeout)
	defer cancel()
	result, err := handler.status.ReportStatus(ctx, report)
	switch {
	case errors.Is(err, ErrReportStaleClock):
		handler.metrics.request("status", "stale_clock")
		http.Error(response, "report time ahead of Core's clock", http.StatusBadRequest)
		return
	case errors.Is(err, ErrTooManyReceivers):
		handler.metrics.request("status", "too_many_instances")
		response.Header().Set("Retry-After", "60")
		http.Error(response, "too many receiver instances", http.StatusTooManyRequests)
		return
	case err != nil:
		handler.unavailable(response, "status")
		return
	}
	handler.metrics.request("status", "accepted")
	handler.metrics.statusEntries(result)
	// The record of who reported what until 1b audits it (C68).
	handler.logger.InfoContext(ctx, "connection log receiver report",
		"instance", hex.EncodeToString(report.Instance[:]), "networks", len(report.Networks),
		"written", result.Written, "throttled", result.Throttled, "dropped", result.Dropped)
	response.WriteHeader(http.StatusNoContent)
}

var sealingKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

var (
	testResults = map[flowlogv1.FlowStatus_TestResult]string{
		flowlogv1.FlowStatus_TEST_OK:                    connectionlog.TestOK,
		flowlogv1.FlowStatus_TEST_ACCESS_DENIED:         connectionlog.TestAccessDenied,
		flowlogv1.FlowStatus_TEST_NO_SUCH_BUCKET:        connectionlog.TestNoSuchBucket,
		flowlogv1.FlowStatus_TEST_WRONG_OWNER:           connectionlog.TestWrongOwner,
		flowlogv1.FlowStatus_TEST_WRONG_REGION:          connectionlog.TestWrongRegion,
		flowlogv1.FlowStatus_TEST_UNREACHABLE:           connectionlog.TestUnreachable,
		flowlogv1.FlowStatus_TEST_CREDENTIAL_UNOPENABLE: connectionlog.TestCredentialUnopenable,
		flowlogv1.FlowStatus_TEST_OTHER:                 connectionlog.TestOther,
	}
	deliveryErrors = map[flowlogv1.FlowStatus_DeliveryError]string{
		flowlogv1.FlowStatus_DELIVERY_NONE:           connectionlog.DeliveryNone,
		flowlogv1.FlowStatus_DELIVERY_ACCESS_DENIED:  connectionlog.DeliveryAccessDenied,
		flowlogv1.FlowStatus_DELIVERY_NO_SUCH_BUCKET: connectionlog.DeliveryNoSuchBucket,
		flowlogv1.FlowStatus_DELIVERY_WRONG_OWNER:    connectionlog.DeliveryWrongOwner,
		flowlogv1.FlowStatus_DELIVERY_WRONG_REGION:   connectionlog.DeliveryWrongRegion,
		flowlogv1.FlowStatus_DELIVERY_UNREACHABLE:    connectionlog.DeliveryUnreachable,
		flowlogv1.FlowStatus_DELIVERY_THROTTLED:      connectionlog.DeliveryThrottled,
		flowlogv1.FlowStatus_DELIVERY_OTHER:          connectionlog.DeliveryOther,
	}
)

// receiverReport validates a report and sorts its Networks by ID; a Network
// listed twice, a report time outside the day before now and the allowed
// skew after it, or any bound passed, refuses the whole report. An entry
// time outside the day before the report is not believed: it reads as none
// (C69, review s4c3 M4).
func receiverReport(message *flowlogv1.FlowStatus, now time.Time) (connectionlog.ReceiverReport, bool) {
	instance := message.GetInstanceId()
	reportedAt := message.GetReportedAtMs()
	if len(instance) != 16 || bytes.Equal(instance, make([]byte, 16)) ||
		reportedAt < now.Add(-24*time.Hour).UnixMilli() ||
		reportedAt > now.Add(connectionlog.ReceiverReportFuture).UnixMilli() ||
		len(message.GetAcceptedVersions()) == 0 || len(message.GetAcceptedVersions()) > connectionlog.MaxReceiverVersions ||
		len(message.GetNoiseFingerprints()) == 0 ||
		len(message.GetNoiseFingerprints()) > connectionlog.MaxReceiverNoiseFingerprints ||
		len(message.GetSealingKeyIds()) > connectionlog.MaxReceiverSealingKeyIDs ||
		len(message.GetNetworks()) > connectionlog.MaxReceiverReportNetworks {
		return connectionlog.ReceiverReport{}, false
	}
	report := connectionlog.ReceiverReport{
		Instance: [16]byte(instance), ReportedAt: time.UnixMilli(message.GetReportedAtMs()).UTC(),
	}
	for _, version := range message.GetAcceptedVersions() {
		if version == 0 || version > math.MaxInt32 {
			return connectionlog.ReceiverReport{}, false
		}
		report.AcceptedVersions = append(report.AcceptedVersions, int(version))
	}
	for _, fingerprint := range message.GetNoiseFingerprints() {
		if len(fingerprint) != 32 {
			return connectionlog.ReceiverReport{}, false
		}
		report.NoiseFingerprints = append(report.NoiseFingerprints, [32]byte(fingerprint))
	}
	for _, id := range message.GetSealingKeyIds() {
		if !sealingKeyIDPattern.MatchString(id) {
			return connectionlog.ReceiverReport{}, false
		}
		report.SealingKeyIDs = append(report.SealingKeyIDs, id)
	}
	for _, entry := range message.GetNetworks() {
		status, ok := receiverNetworkStatus(entry, report.ReportedAt)
		if !ok {
			return connectionlog.ReceiverReport{}, false
		}
		report.Networks = append(report.Networks, status)
	}
	slices.SortFunc(report.Networks, func(left, right connectionlog.ReceiverNetworkStatus) int {
		leftID, rightID := left.Network.Bytes(), right.Network.Bytes()
		return bytes.Compare(leftID[:], rightID[:])
	})
	for index := 1; index < len(report.Networks); index++ {
		if report.Networks[index].Network == report.Networks[index-1].Network {
			return connectionlog.ReceiverReport{}, false
		}
	}
	return report, true
}

func receiverNetworkStatus(entry *flowlogv1.FlowStatus_Network, reportedAt time.Time,
) (connectionlog.ReceiverNetworkStatus, bool) {
	workspaceID, workspaceErr := publicid.FromBytes([16]byte(padded(entry.GetWorkspaceId())))
	networkID, networkErr := publicid.FromBytes([16]byte(padded(entry.GetNetworkId())))
	tag := entry.GetTestedEtag()
	if len(entry.GetWorkspaceId()) != 16 || len(entry.GetNetworkId()) != 16 || workspaceErr != nil ||
		networkErr != nil || (len(tag) != 0 && len(tag) != connectionlog.ReceiverStatusTestedETagBytes) ||
		entry.GetTestedAtMs() < 0 || entry.GetLastDeliveredAtMs() < 0 {
		return connectionlog.ReceiverNetworkStatus{}, false
	}
	status := connectionlog.ReceiverNetworkStatus{
		Workspace: workspace.ID(workspaceID), Network: network.ID(networkID),
		TestResult: connectionlog.ReceiverUnspecified, DeliveryError: connectionlog.ReceiverUnspecified,
		Lost: entry.GetLost_24H(), Overflow: entry.GetOverflow_24H(),
	}
	if len(tag) != 0 {
		status.TestedETag = append([]byte(nil), tag...)
	}
	if result, known := testResults[entry.GetTestResult()]; known {
		status.TestResult = result
	}
	if delivery, known := deliveryErrors[entry.GetDeliveryError()]; known {
		status.DeliveryError = delivery
	}
	status.TestedAt = believedTime(entry.GetTestedAtMs(), reportedAt)
	status.LastDeliveredAt = believedTime(entry.GetLastDeliveredAtMs(), reportedAt)
	return status, true
}

// believedTime is a reported time within the day before the report, or
// none.
func believedTime(milliseconds int64, reportedAt time.Time) time.Time {
	if milliseconds < reportedAt.Add(-24*time.Hour).UnixMilli() || milliseconds > reportedAt.UnixMilli() {
		return time.Time{}
	}
	return time.UnixMilli(milliseconds).UTC()
}

// padded returns value as 16 bytes for a length the caller checks.
func padded(value []byte) []byte {
	out := make([]byte, 16)
	copy(out, value)
	return out
}
