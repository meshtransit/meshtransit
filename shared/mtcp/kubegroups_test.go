package mtcp

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
)

func groupStatus(name string, privileged bool, state mtcpv1.GatewayGroupStatus_State,
	reason mtcpv1.GatewayGroupStatus_Reason) *mtcpv1.GatewayGroupStatus {
	return &mtcpv1.GatewayGroupStatus{Group: name, Privileged: privileged, State: state, Reason: reason}
}

func fullGroupReport() *mtcpv1.GatewayGroupReport {
	report := &mtcpv1.GatewayGroupReport{CheckedAtMs: 1_793_000_000_000}
	for index := range GatewayGroupReportMaximum {
		name := strings.Repeat("g", 60) + string(rune('a'+index/26)) + string(rune('a'+index%26))
		report.Groups = append(report.Groups, groupStatus(name, true, mtcpv1.GatewayGroupStatus_DISABLED,
			mtcpv1.GatewayGroupStatus_RBAC_EXCEEDS))
	}
	return report
}

func TestValidateGatewayGroupReport(t *testing.T) {
	t.Parallel()
	const (
		enabled  = mtcpv1.GatewayGroupStatus_ENABLED
		disabled = mtcpv1.GatewayGroupStatus_DISABLED
		pending  = mtcpv1.GatewayGroupStatus_PENDING
	)
	valid := &mtcpv1.GatewayGroupReport{Groups: []*mtcpv1.GatewayGroupStatus{
		groupStatus("view", false, enabled, mtcpv1.GatewayGroupStatus_NONE),
		groupStatus("sre", true, enabled, mtcpv1.GatewayGroupStatus_IMPERSONATION_OFF),
		groupStatus("edit", false, disabled, mtcpv1.GatewayGroupStatus_RBAC_EXCEEDS),
		groupStatus("ops", false, disabled, mtcpv1.GatewayGroupStatus_API_ERROR),
		groupStatus("dev", false, pending, mtcpv1.GatewayGroupStatus_NOT_CHECKED),
	}}
	if err := ValidateGatewayGroupReport(valid); err != nil {
		t.Fatalf("a valid report: %v", err)
	}
	if err := ValidateGatewayGroupReport(&mtcpv1.GatewayGroupReport{}); err != nil {
		t.Fatalf("an empty report: %v", err)
	}
	if err := ValidateGatewayGroupReport(fullGroupReport()); err != nil {
		t.Fatalf("64 groups: %v", err)
	}
	for name, report := range map[string]*mtcpv1.GatewayGroupReport{
		"65 groups": {Groups: append(fullGroupReport().GetGroups(),
			groupStatus("one-more", false, enabled, mtcpv1.GatewayGroupStatus_NONE))},
		"a group twice": {Groups: []*mtcpv1.GatewayGroupStatus{
			groupStatus("view", false, enabled, mtcpv1.GatewayGroupStatus_NONE),
			groupStatus("view", false, disabled, mtcpv1.GatewayGroupStatus_API_ERROR)}},
		"an upper case name": {Groups: []*mtcpv1.GatewayGroupStatus{
			groupStatus("View", false, enabled, mtcpv1.GatewayGroupStatus_NONE)}},
		"a name of 64 bytes": {Groups: []*mtcpv1.GatewayGroupStatus{
			groupStatus(strings.Repeat("a", 64), false, enabled, mtcpv1.GatewayGroupStatus_NONE)}},
		"a leading hyphen": {Groups: []*mtcpv1.GatewayGroupStatus{
			groupStatus("-view", false, enabled, mtcpv1.GatewayGroupStatus_NONE)}},
		"no state": {Groups: []*mtcpv1.GatewayGroupStatus{
			groupStatus("view", false, mtcpv1.GatewayGroupStatus_STATE_UNSPECIFIED, mtcpv1.GatewayGroupStatus_NONE)}},
		"enabled with a reason": {Groups: []*mtcpv1.GatewayGroupStatus{
			groupStatus("view", false, enabled, mtcpv1.GatewayGroupStatus_RBAC_EXCEEDS)}},
		"impersonation off, not privileged": {Groups: []*mtcpv1.GatewayGroupStatus{
			groupStatus("view", false, enabled, mtcpv1.GatewayGroupStatus_IMPERSONATION_OFF)}},
		"disabled without a reason": {Groups: []*mtcpv1.GatewayGroupStatus{
			groupStatus("view", false, disabled, mtcpv1.GatewayGroupStatus_NONE)}},
		"pending, checked": {Groups: []*mtcpv1.GatewayGroupStatus{
			groupStatus("view", false, pending, mtcpv1.GatewayGroupStatus_NONE)}},
		"an unknown reason": {Groups: []*mtcpv1.GatewayGroupStatus{
			groupStatus("view", false, disabled, mtcpv1.GatewayGroupStatus_Reason(99))}},
		"a negative time": {CheckedAtMs: -1},
	} {
		if err := ValidateGatewayGroupReport(report); !errors.Is(err, ErrGatewayGroupReport) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestGatewayGroupReportFitsItsLimit(t *testing.T) {
	t.Parallel()
	report := fullGroupReport()
	report.Truncated = true
	size := proto.Size(report)
	if size > MessageGatewayGroupReport.Limit() {
		t.Fatalf("the largest valid report takes %d bytes, over %d", size, MessageGatewayGroupReport.Limit())
	}
	if _, err := EncodeMessage(MessageGatewayGroupReport, report, CoreToNode, EncodeOptions{}); !errors.Is(err,
		ErrDirection) {
		t.Fatalf("Core sent a group report: %v", err)
	}
	fragments, err := EncodeMessage(MessageGatewayGroupReport, report, NodeToCore, EncodeOptions{})
	if err != nil || len(fragments) == 0 {
		t.Fatalf("encode: %d fragments, %v", len(fragments), err)
	}
}

// FuzzGatewayGroupReport feeds Core's decoder and validator arbitrary
// payloads: they refuse what breaks §6.11 without panicking.
func FuzzGatewayGroupReport(f *testing.F) {
	seed, _ := proto.Marshal(fullGroupReport())
	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x02, 0x0a, 0x00})
	f.Fuzz(func(t *testing.T, payload []byte) {
		message, err := DecodeMessage(MessageGatewayGroupReport, payload)
		if err != nil {
			return
		}
		report, ok := message.(*mtcpv1.GatewayGroupReport)
		if !ok {
			t.Fatalf("decoded %T", message)
		}
		if ValidateGatewayGroupReport(report) == nil && len(report.GetGroups()) > GatewayGroupReportMaximum {
			t.Fatal("accepted more than 64 groups")
		}
	})
}
