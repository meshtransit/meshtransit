package connectionlog

import (
	"encoding/hex"
	"testing"
	"time"
)

// What the Console shows of a Network's logging (design §16i C92).
func TestStatusView(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	credential := CredentialID(mustID(t, "01890f00-0000-7000-8000-000000000301"))
	settings := Settings{Enabled: true, Credential: &credential, Version: 4, ExpectedBucketOwner: "123456789012"}
	current := DestinationTag(4, credential, 2, "meshflow-1", "123456789012")
	at := func(ago time.Duration) *time.Time {
		moment := now.Add(-ago)
		return &moment
	}
	report := func(tag []byte, result, deliveryError string, received time.Duration) *ReportRow {
		return &ReportRow{
			TestedETag: tag, TestResult: result, TestedAt: at(received + time.Minute), DeliveredAt: at(received),
			DeliveryError: deliveryError, ReceivedAt: now.Add(-received),
		}
	}
	for name, test := range map[string]struct {
		rows StatusRows
		want StatusView
	}{
		"nothing reported": {
			rows: StatusRows{},
			want: StatusView{Report: ReportNone, Test: TestNone},
		},
		"a current report of the current settings": {
			rows: StatusRows{
				Report:     report(current, TestOK, DeliveryNone, time.Minute),
				ReceiverAt: at(30 * time.Second), SealedVersion: 2, SealingKeyID: "meshflow-1",
			},
			want: StatusView{
				ReceiverAvailable: true, Report: ReportCurrent, ReportedAt: at(time.Minute),
				Test: TestOK, TestedAt: at(2 * time.Minute), DeliveredAt: at(time.Minute),
			},
		},
		"a test of older settings": {
			rows: StatusRows{
				Report:     report(DestinationTag(3, credential, 2, "meshflow-1", "123456789012"), TestOK, "throttled", time.Minute),
				ReceiverAt: at(time.Minute), SealedVersion: 2, SealingKeyID: "meshflow-1",
			},
			want: StatusView{
				ReceiverAvailable: true, Report: ReportCurrent, ReportedAt: at(time.Minute), Test: TestPending,
				DeliveredAt: at(time.Minute), DeliveryError: "throttled",
			},
		},
		"a rotated key makes the test pending": {
			rows: StatusRows{
				Report:     report(current, TestOK, DeliveryNone, time.Minute),
				ReceiverAt: at(time.Minute), SealedVersion: 3, SealingKeyID: "meshflow-1",
			},
			want: StatusView{
				ReceiverAvailable: true, Report: ReportCurrent, ReportedAt: at(time.Minute), Test: TestPending,
				DeliveredAt: at(time.Minute),
			},
		},
		"a report too old to know": {
			rows: StatusRows{
				Report:     report(current, TestAccessDenied, ReceiverUnspecified, 11*time.Minute),
				ReceiverAt: at(11 * time.Minute), SealedVersion: 2, SealingKeyID: "meshflow-1",
			},
			want: StatusView{
				Report: ReportStale, ReportedAt: at(11 * time.Minute), Test: TestAccessDenied,
				TestedAt: at(12 * time.Minute), DeliveredAt: at(11 * time.Minute),
			},
		},
	} {
		got := test.rows.View(settings, now)
		if !sameView(got, test.want) {
			t.Errorf("%s: %+v, want %+v", name, got, test.want)
		}
	}
	// Settings without a credential have no test to compare.
	if view := (StatusRows{Report: report(current, TestOK, DeliveryNone, 0)}).View(Settings{}, now); view.Test != TestNone {
		t.Errorf("no credential: %+v", view)
	}
}

func sameView(a, b StatusView) bool {
	same := func(x, y *time.Time) bool { return (x == nil) == (y == nil) && (x == nil || x.Equal(*y)) }
	return a.ReceiverAvailable == b.ReceiverAvailable && a.Report == b.Report && a.Test == b.Test &&
		a.DeliveryError == b.DeliveryError && same(a.ReportedAt, b.ReportedAt) && same(a.TestedAt, b.TestedAt) &&
		same(a.DeliveredAt, b.DeliveredAt)
}

// The destination ETag is on the wire to receivers: its bytes never change
// by accident.
func TestDestinationTagVector(t *testing.T) {
	t.Parallel()
	credential := CredentialID(mustID(t, "01890f00-0000-7000-8000-000000000301"))
	got := hex.EncodeToString(DestinationTag(4, credential, 2, "meshflow-1", "123456789012"))
	if got != "88a6e7b595bd580079096265f3319bbe" {
		t.Fatalf("DestinationTag = %s", got)
	}
}
