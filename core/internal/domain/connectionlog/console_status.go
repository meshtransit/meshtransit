package connectionlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
)

// What a Network's reader sees of its logging (design §16i C91, C92): the
// rows Core holds, and the view the Console shows, derived here.

// ReportFreshFor is how long a receiver's report counts as current; past
// it the Console says the state is not known (C72).
const ReportFreshFor = 10 * time.Minute

// DestinationTag is the destination ETag a receiver writes under: it
// changes with the settings, the credential or its key, and the bucket
// owner. The internal API sends it; the Console compares a test with it.
func DestinationTag(settingsVersion int64, credential CredentialID, sealedVersion int64,
	sealingKeyID, bucketOwner string,
) []byte {
	material := make([]byte, 0, 64+len(sealingKeyID)+len(bucketOwner))
	material = binary.BigEndian.AppendUint64(material, uint64(settingsVersion)) //nolint:gosec // a version is positive
	id := publicid.ID(credential).Bytes()
	material = append(material, id[:]...)
	material = binary.BigEndian.AppendUint64(material, uint64(sealedVersion)) //nolint:gosec // a version is positive
	material = append(material, byte(len(sealingKeyID)))                      //nolint:gosec // at most 32 bytes, checked by the schema
	material = append(material, sealingKeyID...)
	material = append(material, bucketOwner...)
	digest := sha256.Sum256(material)
	return digest[:16]
}

// StatusRows are the rows behind a Network's status: what a receiver last
// reported, the newest receiver that takes the protocol, and the
// credential's key version the destination ETag names.
type StatusRows struct {
	// Report is nil until a receiver reported the Network.
	Report *ReportRow
	// ReceiverAt is when the newest receiver accepting
	// ReceiverProtocolVersion reported, or nil.
	ReceiverAt *time.Time
	// SealedVersion and SealingKeyID are the credential's, or zero when
	// the Network names none.
	SealedVersion int64
	SealingKeyID  string
	// Rejected24h is the records a push destination refused in the last
	// day, as last reported; WritesType whether every fresh receiver
	// writes to the credential's type, nil when not read (schema 273).
	Rejected24h int64
	WritesType  *bool
}

// ReportRow is a receiver's last report for one Network.
type ReportRow struct {
	TestedETag    []byte
	TestResult    string
	TestedAt      *time.Time
	DeliveredAt   *time.Time
	DeliveryError string
	ReceivedAt    time.Time
}

// What the Console says of a report and a test.
const (
	ReportNone    = "none"
	ReportCurrent = "current"
	ReportStale   = "stale"
	TestNone      = "none"
	TestPending   = "pending"
)

// StatusView is what the Console shows (C92): never a receiver instance,
// fingerprint or version.
type StatusView struct {
	ReceiverAvailable bool
	// Report is ReportNone, ReportCurrent or ReportStale.
	Report     string
	ReportedAt *time.Time
	// Test is TestNone, TestPending (the last test was of other
	// settings), or a test result.
	Test     string
	TestedAt *time.Time
	// DeliveredAt is the last object delivered; DeliveryError the kind of
	// the last failure, empty when none.
	DeliveredAt   *time.Time
	DeliveryError string
	// ReceiverWritesType is false while some receiver does not write to the
	// destination's type yet: Core then signs no ticket for it.
	ReceiverWritesType bool
	Rejected24h        int64
}

// View derives what the Console shows from rows read with settings.
func (rows StatusRows) View(settings Settings, now time.Time) StatusView {
	view := StatusView{
		ReceiverAvailable: rows.ReceiverAt != nil && now.Sub(*rows.ReceiverAt) <= ReportFreshFor,
		Report:            ReportNone, Test: TestNone,
		ReceiverWritesType: rows.WritesType == nil || *rows.WritesType, Rejected24h: max(rows.Rejected24h, 0),
	}
	report := rows.Report
	if report == nil {
		return view
	}
	received := report.ReceivedAt
	view.ReportedAt, view.Report = &received, ReportCurrent
	if now.Sub(received) > ReportFreshFor {
		view.Report = ReportStale
	}
	view.DeliveredAt = report.DeliveredAt
	if report.DeliveryError != DeliveryNone && report.DeliveryError != ReceiverUnspecified {
		view.DeliveryError = report.DeliveryError
	}
	if settings.Credential == nil || report.TestResult == ReceiverUnspecified || len(report.TestedETag) == 0 {
		return view
	}
	current := DestinationTag(settings.Version, *settings.Credential, rows.SealedVersion, rows.SealingKeyID,
		settings.ExpectedBucketOwner)
	if !bytes.Equal(report.TestedETag, current) {
		view.Test = TestPending
		return view
	}
	view.Test, view.TestedAt = report.TestResult, report.TestedAt
	return view
}
